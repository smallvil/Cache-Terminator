/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2009 Linpro AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * We maintain a number of worker thread pools, to spread lock contention.
 *
 * Pools can be added on the fly, as a means to mitigate lock contention,
 * but can only be removed again by a restart. (XXX: we could fix that)
 *
 * Two threads herd the pools, one eliminates idle threads and aggregates
 * statistics for all the pools, the other thread creates new threads
 * on demand, subject to various numerical constraints.
 *
 * The algorithm for when to create threads needs to be reactive enough
 * to handle startup spikes, but sufficiently attenuated to not cause
 * thread pileups.  This remains subject for improvement.
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_pool.c 103 2011-04-12 06:54:31Z jwg286 $")

#include <sys/types.h>
#if defined(HAVE_EPOLL_CTL)
#include <sys/epoll.h>
#endif
#if defined(HAVE_KQUEUE)
#include <sys/event.h>
#endif
#include <sys/times.h>

#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shmlog.h"
#include "vcl.h"
#include "cli_priv.h"
#include "cache.h"
#include "stevedore.h"
#include "hash_slinger.h"
#include "vsha256.h"

#define	EPOLLEVENT_MAX	(8 * 1024)
#define	KQEVENT_MAX	EPOLLEVENT_MAX

VTAILQ_HEAD(workerhead, worker);

/* Number of work requests queued in excess of worker threads available */

struct wq {
	unsigned		magic;
#define WQ_MAGIC		0x606658fa
	struct lock		mtx;
	struct workerhead	idle;
	VTAILQ_HEAD(, septum)	overflow;
	unsigned		nthr;
	unsigned		nqueue;
	unsigned		lqueue;
	uintmax_t		ndrop;
	uintmax_t		noverflow;
};

static struct wq		**wq;
static unsigned			nwq;
static unsigned			ovfl_max;
static unsigned			nthr_max;

static pthread_cond_t		herder_cond;
static struct lock		herder_mtx;
static struct lock		wstat_mtx;

/*--------------------------------------------------------------------*/

static void
wrk_sumstat(struct worker *w)
{

	Lck_AssertHeld(&wstat_mtx);
#define L0(n)
#define L1(n) (VSL_stats->n += w->stats.n)
#define MAC_STAT(n, t, l, f, d) L##l(n);
#include "stat_field.h"
#undef MAC_STAT
#undef L0
#undef L1
	memset(&w->stats, 0, sizeof w->stats);
}

void
WRK_SumStat(struct worker *w)
{

	Lck_Lock(&wstat_mtx);
	wrk_sumstat(w);
	Lck_Unlock(&wstat_mtx);
}

/*--------------------------------------------------------------------*/

static void
WRK_handlest(struct worker *w, struct septum *st)
{
	struct fetch *fp;
	struct pipe *dp;
	struct sess *sp;

	switch (st->type) {
	case SEPTUM_SESS:
		sp = st->arg;
		AN(sp);
		WRK_runsm_sess(w, sp);
		break;
	case SEPTUM_PIPE:
		dp = st->arg;
		AN(dp);
		WRK_runsm_pipe(w, dp);
		break;
	case SEPTUM_FETCH:
		fp = st->arg;
		AN(fp);
		WRK_runsm_fetch(w, fp);
		break;
	default:
		assert(0 == 1);
	}
}

/*--------------------------------------------------------------------*/

static void *
wrk_thread_real(struct wq *qp, unsigned shm_workspace)
{
#if defined(HAVE_EPOLL_CTL)
	struct epoll_event ev[EPOLLEVENT_MAX], *ep;
#endif
#if defined(HAVE_KQUEUE)
	struct kevent ev[KQEVENT_MAX], *ep;
	struct timespec tv;
#endif
	struct septum *st;
	struct worker *w, ww;
	unsigned char wlog[shm_workspace];
	int i, ms, n, stats_clean = 1;

	THR_SetName("cache-worker");
	w = &ww;
	memset(w, 0, sizeof *w);
	w->magic = WORKER_MAGIC;
	w->lastused = NAN;
	w->wlb = w->wlp = wlog;
	w->wle = wlog + sizeof wlog;
	AZ(pthread_cond_init(&w->cond, NULL));
	COT_init(w);

#if defined(HAVE_EPOLL_CTL)
	w->fd = epoll_create(1);
#endif
#if defined(HAVE_KQUEUE)
	w->fd = kqueue();
#endif
	assert(w->fd >= 0);

	Lck_New(&w->readylist_mtx);
	VTAILQ_INIT(&w->readylist);

	VSL(SLT_WorkThread, 0, "%p start", w);

	Lck_Lock(&qp->mtx);
	qp->nthr++;
	Lck_Unlock(&qp->mtx);

	while (1) {
		CHECK_OBJ_NOTNULL(w, WORKER_MAGIC);
		stats_clean = 0;

		/* XXX removes two times COT_ticks calls; here and below */
		COT_ticks(w);

		/*
		 * Process sockets waiting events.
		 */
		if (params->diag_bitmap & 0x00400000)
			VSL(SLT_WorkThread, 0, "%p %d %d %d",
			    (void *)pthread_self(), w->nsocket, w->nwaiting,
			    w->nreadylist);
		if (w->nsocket > 0) {
#if defined(HAVE_EPOLL_CTL)
			if (w->nwaiting == 0) {
				VSL_stats->timeout_1000ms++;
				ms = 1000;	/* ms */
			} else {
				VSL_stats->timeout_1ms++;
				ms = 1;
			}
			n = epoll_wait(w->fd, ev, EPOLLEVENT_MAX, ms);
#endif
#if defined(HAVE_KQUEUE)
			if (w->nwaiting == 0) {
				VSL_stats->timeout_1000ms++;
				tv.tv_sec = 1;
				tv.tv_nsec = 0;
			} else {
				VSL_stats->timeout_1ms++;
				tv.tv_sec = 0;
				tv.tv_nsec = 1000000;	/* waits 1 milisecond */
			}
			n = kevent(w->fd, NULL, 0, ev, KQEVENT_MAX, &tv);
#endif
			for (ep = ev, i = 0; i < n; i++, ep++, w->nsocket--) {
#if defined(HAVE_EPOLL_CTL)
				st = (struct septum *)ep->data.ptr;
#endif
#if defined(HAVE_KQUEUE)
				st = (struct septum *)ep->udata;
#endif
				/*
				 * stop callouts here because all sockets for
				 * clients are exited the state machine arming
				 * the callout.  It's a assumption and design.
				 */
				callout_stop(w, &st->co);
				SPT_EventDel(w->fd, st);
				WRK_handlest(w, st);
			}
		}
		/*
		 * Process readylist which includes SEPTUM pointers waken.
		 */
		Lck_Lock(&w->readylist_mtx);
		while (!VTAILQ_EMPTY(&w->readylist)) {
			st = VTAILQ_FIRST(&w->readylist);
			VTAILQ_REMOVE(&w->readylist, st, list);
			w->nreadylist--;
			assert(w->nreadylist >= 0);
			Lck_Unlock(&w->readylist_mtx);
			WRK_handlest(w, st);
			Lck_Lock(&w->readylist_mtx);
		}
		Lck_Unlock(&w->readylist_mtx);
		/*
		 * Process overflow requests, CNT_Session if any
		 */
		Lck_Lock(&qp->mtx);
		while (!VTAILQ_EMPTY(&qp->overflow)) {
			st = VTAILQ_FIRST(&qp->overflow);
			VTAILQ_REMOVE(&qp->overflow, st, list);
			qp->nqueue--;
			assert(qp->nqueue >= 0);
			Lck_Unlock(&qp->mtx);
			WRK_handlest(w, st);
			Lck_Lock(&qp->mtx);
		}
		Lck_Unlock(&qp->mtx);
		/*
		 * Process callouts.
		 * XXX really need to call COT_clock whenever a loop is turn?
		 */
		COT_clock(w);
		if (!Lck_Trylock(&wstat_mtx)) {
			wrk_sumstat(w);
			Lck_Unlock(&wstat_mtx);
			stats_clean = 1;
		}
		/* if worker thread has something to do we couldn't sleep */
		if (w->nsocket > 0 || w->nwaiting > 0 || w->nreadylist > 0)
			continue;
		/* Going sleeping from here. */
		if (isnan(w->lastused))
			w->lastused = TIM_real();
		if (!stats_clean)
			WRK_SumStat(w);
		w->septum = NULL;
		Lck_Lock(&qp->mtx);
		VTAILQ_INSERT_HEAD(&qp->idle, w, list);
		Lck_CondWait(&w->cond, &qp->mtx);
		Lck_Unlock(&qp->mtx);
		if (w->septum == NULL)
			break;
		/*
		 * needs to call COT_ticks because it just waken from sleep and
		 * don't know how long the worker thread slept so updates ticks
		 * for the session.
		 */
		COT_ticks(w);
		WRK_handlest(w, w->septum);
		w->septum = NULL;
	}
	Lck_Lock(&qp->mtx);
	qp->nthr--;
	Lck_Unlock(&qp->mtx);

	VSL(SLT_WorkThread, 0, "%p end", w);
	Lck_Delete(&w->readylist_mtx);
	AZ(close(w->fd));
	COT_fini(w);
	AZ(pthread_cond_destroy(&w->cond));
	HSH_Cleanup(w);
	WRK_SumStat(w);
	return (NULL);
}

#undef RUNSM

static void *
wrk_thread(void *priv)
{
	struct wq *qp;

	CAST_OBJ_NOTNULL(qp, priv, WQ_MAGIC);
	return (wrk_thread_real(qp, params->shm_workspace));
}

/*--------------------------------------------------------------------
 * Queue a workrequest if possible.
 *
 * Return zero if the request was queued, negative if it wasn't.
 */

int
WRK_Queue(struct septum *st)
{
	struct worker *w;
	struct wq *qp;
	static unsigned nq = 0;
	unsigned onq;

	/*
	 * Select which pool we issue to
	 * XXX: better alg ?
	 * XXX: per CPU ?
	 */
	onq = nq + 1;
	if (onq >= nwq)
		onq = 0;
	qp = wq[onq];
	nq = onq;

	Lck_Lock(&qp->mtx);

	/* If there are idle threads, we tickle the first one into action */
	w = VTAILQ_FIRST(&qp->idle);
	if (w != NULL) {
		VTAILQ_REMOVE(&qp->idle, w, list);
		Lck_Unlock(&qp->mtx);
		w->septum = st;
		AZ(pthread_cond_signal(&w->cond));
		return (0);
	}

	/* If we have too much in the overflow already, refuse. */
	if (qp->nqueue > ovfl_max) {
		qp->ndrop++;
		Lck_Unlock(&qp->mtx);
		return (-1);
	}

	VTAILQ_INSERT_TAIL(&qp->overflow, st, list);
	qp->noverflow++;
	qp->nqueue++;
	Lck_Unlock(&qp->mtx);
	AZ(pthread_cond_signal(&herder_cond));
	return (0);
}

/*--------------------------------------------------------------------
 * Run the State Machine.
 */

void
WRK_runsm_sess(struct worker *w, struct sess *sp)
{
	enum sess_status status;

	CHECK_OBJ_ORNULL(sp, SESS_MAGIC);

	w->lastused = NAN;
	THR_SetSession(sp);
	if (sp->wrk != NULL)
		assert(sp->wrk == w);
	sp->wrk = w;
	CHECK_OBJ_ORNULL(w->nobjhead, OBJHEAD_MAGIC);
	status = CNT_Session(sp);
	switch (status) {
	case SESS_WAIT:
		SES_EventAdd(sp);
		w->nsocket++;
		assert(w->nsocket < EPOLLEVENT_MAX);
		break;
	case SESS_DONE:
	case SESS_SLEEP:
		/* XXX do nothing? */
		break;
	default:
		assert(0 == 1);
		break;
	}
	CHECK_OBJ_ORNULL(w->nobjhead, OBJHEAD_MAGIC);
	THR_SetSession(NULL);
	assert((w)->wlp == (w)->wlb);
}

void
WRK_runsm_pipe(struct worker *w, struct pipe *dp)
{
	enum pipe_status status;

	CHECK_OBJ_ORNULL(dp, PIPE_MAGIC);

	w->lastused = NAN;
	status = PIE_Session(dp);
	switch (status) {
	case PIPE_WAIT:
		PIE_EventAdd(dp);
		w->nsocket++;
		assert(w->nsocket < EPOLLEVENT_MAX);
		break;
	case PIPE_DONE:
	case PIPE_SLEEP:
		/* XXX do nothing? */
		break;
	default:
		assert(0 == 1);
	}
}

void
WRK_runsm_fetch(struct worker *w, struct fetch *fp)
{
	enum fetch_status status;

	CHECK_OBJ_ORNULL(fp, FETCH_MAGIC);

	w->lastused = NAN;
	status = FET_Session(fp);
	switch (status) {
	case FETCH_WAIT:
		FET_EventAdd(fp);
		w->nsocket++;
		assert(w->nsocket < EPOLLEVENT_MAX);
		break;
	case FETCH_DONE:
		/* XXX do nothing? */
		break;
	default:
		assert(0 == 1);
	}
}

/*--------------------------------------------------------------------*/

int
WRK_QueueSession(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AZ(sp->wrk);
	sp->septum.type = SEPTUM_SESS;
	sp->septum.arg = sp;
	if (WRK_Queue(&sp->septum) == 0)
		return (0);

	/*
	 * Couldn't queue it -- kill it.
	 *
	 * XXX: a notice might be polite, but would potentially
	 * XXX: sleep whichever thread got us here
	 */
	sp->t_end = TIM_real();
	vca_close_session(sp, "dropped");
	if (sp->vcl != NULL) {
		/*
		 * A session parked on a busy object can come here
		 * after it wakes up.  Loose the VCL reference.
		 */
		VCL_Rel(&sp->vcl);
	}
	if (sp->geoip != NULL)
		GEO_Rel(&sp->geoip);
	SES_Delete(sp);
	return (1);
}

/*--------------------------------------------------------------------
 * Add (more) thread pools
 */

static void
wrk_addpools(const unsigned pools)
{
	struct wq **pwq, **owq;
	unsigned u;

	pwq = calloc(sizeof *pwq, pools);
	if (pwq == NULL)
		return;
	if (wq != NULL)
		memcpy(pwq, wq, sizeof *pwq * nwq);
	owq = wq;
	wq = pwq;
	for (u = nwq; u < pools; u++) {
		wq[u] = calloc(sizeof *wq[0], 1);
		XXXAN(wq[u]);
		wq[u]->magic = WQ_MAGIC;
		Lck_New(&wq[u]->mtx);
		VTAILQ_INIT(&wq[u]->overflow);
		VTAILQ_INIT(&wq[u]->idle);
	}
	(void)owq;	/* XXX: avoid race, leak it. */
	nwq = pools;
}

/*--------------------------------------------------------------------
 * If a thread is idle or excess, pick it out of the pool.
 */

static void
wrk_decimate_flock(struct wq *qp, double t_idle, struct varnish_stats *vs)
{
	struct worker *w = NULL;

	Lck_Lock(&qp->mtx);
	vs->n_wrk += qp->nthr;
	vs->n_wrk_queue += qp->nqueue;
	vs->n_wrk_drop += qp->ndrop;
	vs->n_wrk_overflow += qp->noverflow;

	if (qp->nthr > params->wthread_min) {
		w = VTAILQ_LAST(&qp->idle, workerhead);
		if (w != NULL && (w->lastused < t_idle || qp->nthr > nthr_max))
			VTAILQ_REMOVE(&qp->idle, w, list);
		else
			w = NULL;
	}
	Lck_Unlock(&qp->mtx);

	/* And give it a kiss on the cheek... */
	if (w != NULL) {
		AZ(w->septum);
		AZ(pthread_cond_signal(&w->cond));
		TIM_sleep(params->wthread_purge_delay * 1e-3);
	}
}

/*--------------------------------------------------------------------
 * Periodic pool herding thread
 *
 * Do things which we can do at our leisure:
 *  Add pools
 *  Scale constants
 *  Get rid of excess threads
 *  Aggregate stats across pools
 */

static void *
wrk_herdtimer_thread(void *priv)
{
	volatile unsigned u;
	double t_idle;
	struct varnish_stats vsm, *vs;
	int errno_is_multi_threaded;

	THR_SetName("wrk_herdtimer");

	/*
	 * This is one of the first threads created, test to see that
	 * errno is really per thread.  If this fails, your C-compiler
	 * needs some magic argument (-mt, -pthread, -pthreads etc etc).
	 */
	errno = 0;
	AN(unlink("/"));		/* This had better fail */
	errno_is_multi_threaded = errno;
	assert(errno_is_multi_threaded != 0);

	memset(&vsm, 0, sizeof vsm);
	vs = &vsm;

	(void)priv;
	while (1) {
		/* Add Pools */
		u = params->wthread_pools;
		if (u > nwq)
			wrk_addpools(u);

		/* Scale parameters */

		u = params->wthread_max / nwq;
		if (u < params->wthread_min)
			u = params->wthread_min;
		nthr_max = u;

		ovfl_max = (nthr_max * params->overflow_max) / 100;

		vs->n_wrk = 0;
		vs->n_wrk_queue = 0;
		vs->n_wrk_drop = 0;
		vs->n_wrk_overflow = 0;

		t_idle = TIM_real() - params->wthread_timeout;
		for (u = 0; u < nwq; u++)
			wrk_decimate_flock(wq[u], t_idle, vs);

		VSL_stats->n_wrk= vs->n_wrk;
		VSL_stats->n_wrk_queue = vs->n_wrk_queue;
		VSL_stats->n_wrk_drop = vs->n_wrk_drop;
		VSL_stats->n_wrk_overflow = vs->n_wrk_overflow;

		TIM_sleep(params->wthread_purge_delay * 1e-3);
	}
	NEEDLESS_RETURN(NULL);
}

/*--------------------------------------------------------------------
 * Create another thread, if necessary & possible
 */

static void
wrk_breed_flock(struct wq *qp)
{
	pthread_t tp;

	/*
	 * If we need more threads, and have space, create
	 * one more thread.
	 */
	if (qp->nthr < params->wthread_min ||	/* Not enough threads yet */
	    (qp->nqueue > params->wthread_add_threshold && /* more needed */
	    qp->nqueue > qp->lqueue)) {	/* not getting better since last */
		if (qp->nthr >= nthr_max) {
			VSL_stats->n_wrk_max++;
		} else if (pthread_create(&tp, NULL, wrk_thread, qp)) {
			VSL(SLT_Debug, 0, "Create worker thread failed %d %s",
			    errno, strerror(errno));
			VSL_stats->n_wrk_failed++;
			TIM_sleep(params->wthread_fail_delay * 1e-3);
		} else {
			AZ(pthread_detach(tp));
			VSL_stats->n_wrk_create++;
			TIM_sleep(params->wthread_add_delay * 1e-3);
		}
	}
	qp->lqueue = qp->nqueue;
}

/*--------------------------------------------------------------------
 * This thread wakes up whenever a pool overflows.
 *
 * The trick here is to not be too aggressive about creating threads.
 * We do this by only examining one pool at a time, and by sleeping
 * a short while whenever we create a thread and a little while longer
 * whenever we fail to, hopefully missing a lot of cond_signals in
 * the meantime.
 *
 * XXX: probably need a lot more work.
 *
 */

static void *
wrk_herder_thread(void *priv)
{
	unsigned u, w;

	THR_SetName("wrk_herder");
	(void)priv;
	while (1) {
		for (u = 0 ; u < nwq; u++) {
			wrk_breed_flock(wq[u]);

			/*
			 * Make sure all pools have their minimum complement
			 */
			for (w = 0 ; w < nwq; w++)
				while (wq[w]->nthr < params->wthread_min)
					wrk_breed_flock(wq[w]);
			/*
			 * We cannot avoid getting a mutex, so we have a
			 * bogo mutex just for POSIX_STUPIDITY
			 */
			Lck_Lock(&herder_mtx);
			Lck_CondWait(&herder_cond, &herder_mtx);
			Lck_Unlock(&herder_mtx);
		}
	}
	NEEDLESS_RETURN(NULL);
}

/*--------------------------------------------------------------------
 * Create and starte a back-ground thread which as its own worker and
 * session data structures;
 */

struct bgthread {
	unsigned	magic;
#define BGTHREAD_MAGIC	0x23b5152b
	const char	*name;
	bgthread_t	*func;
	void		*priv;
};

static void *
wrk_bgthread(void *arg)
{
	struct bgthread *bt;
	struct worker ww;
	struct sess *sp;
	unsigned char logbuf[1024];	/* XXX:  size ? */

	CAST_OBJ_NOTNULL(bt, arg, BGTHREAD_MAGIC);
	THR_SetName(bt->name);
	sp = SES_Alloc();
	XXXAN(sp);
	memset(&ww, 0, sizeof ww);
	sp->wrk = &ww;
	ww.magic = WORKER_MAGIC;
	ww.wlp = ww.wlb = logbuf;
	ww.wle = logbuf + sizeof logbuf;

	(void)bt->func(sp, bt->priv);

	WRONG("BgThread terminated");

	NEEDLESS_RETURN(NULL);
}

void
WRK_BgThread(pthread_t *thr, const char *name, bgthread_t *func, void *priv)
{
	struct bgthread *bt;

	ALLOC_OBJ(bt, BGTHREAD_MAGIC);
	AN(bt);

	bt->name = name;
	bt->func = func;
	bt->priv = priv;
	AZ(pthread_create(thr, NULL, wrk_bgthread, bt));
}

/*--------------------------------------------------------------------*/

void
WRK_Init(void)
{
	pthread_t tp;

	AZ(pthread_cond_init(&herder_cond, NULL));
	Lck_New(&herder_mtx);
	Lck_New(&wstat_mtx);

	wrk_addpools(params->wthread_pools);
	AZ(pthread_create(&tp, NULL, wrk_herdtimer_thread, NULL));
	AZ(pthread_detach(tp));
	AZ(pthread_create(&tp, NULL, wrk_herder_thread, NULL));
	AZ(pthread_detach(tp));
}

/*--------------------------------------------------------------------*/
