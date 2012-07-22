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
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_fetch.c 144 2011-04-15 18:48:04Z jwg286 $")

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include "shmlog.h"
#include "cache.h"
#include "stevedore.h"
#include "cli_priv.h"
#include "hash_slinger.h"

static const char *fet_statusstr[] = {
	"CONTINUE",
	"DONE",
	"SLEEP",
	"WAIT"
};
const char *fet_stepstr[] = {
#define FETCHSTEP(l,u)	"FET_" #u,
#include "fetchsteps.h"
#undef FETCHSTEP
};

/*--------------------------------------------------------------------*/

/* this function would be called in COT_clock() */
static void
FET_SessionTimeout(void *arg)
{
	struct fetch *fp = arg;
	struct septum *st = &fp->septum;

	fp->step = FET_TIMEOUT;
	callout_stop(fp->wrk, &st->co);
	FET_EventDel(fp);
	FET_Wakeup(fp);
}

static enum fetch_status
fet_timeout(struct fetch *fp)
{

	fp->step = FET_ERROR;
	return (FETCH_CONTINUE);
}

static enum fetch_status
fet_first(struct fetch *fp)
{
	struct sess *sp;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);

	switch (sp->wrkvar.body_status) {
	case BS_LENGTH:
		assert(SEPTUM_GCL(&fp->septum) > 0);
		break;
	case BS_EOF:
		/* do nothing */
		break;
	case BS_CHUNKED:
		SEPTUM_SST(&fp->septum, NULL);
		SEPTUM_SOFFSET(&fp->septum, 0);
		SEPTUM_SNUMBUFLEN(&fp->septum, 20);
		SEPTUM_SNUMBUF(&fp->septum, WS_Alloc(sp->ws,
		    SEPTUM_GNUMBUFLEN(&fp->septum)));
		AN(SEPTUM_GNUMBUF(&fp->septum));

		fp->step = FET_CHUNKED_CL;
		return (FETCH_CONTINUE);
	default:
		WRONG("Unknown body status for first step");
	}

	fp->step = FET_STRAIGHT_OR_EOF;
	return (FETCH_CONTINUE);
}

static enum fetch_status
fet_chunked_cl(struct fetch *fp)
{
	struct http_conn *htc;
	struct sess *sp;
	struct storage *st;
	struct vbe_conn *vc;
	ssize_t tlen, u, v;
	unsigned w;
	int i, islastchunk = 0;
	char *q;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(htc, sp->wrkvar.htc, HTTP_CONN_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	i = HTC_Read(htc, SEPTUM_GNUMBUF(&fp->septum) +
	    SEPTUM_GOFFSET(&fp->septum), 1);
	if (i == -2) {
		SEPTUM_FETCHEVENT(fp, htc->htc_fd, htc->htc_want,
		    CALLOUT_SECTOTICKS(vc->between_bytes_timeout));
		return (FETCH_WAIT);
	}
	if (i <= 0) {
		WSP(sp, SLT_FetchError, "chunked read_error: %d", errno);
		fp->step = FET_ERROR;
		return (FETCH_CONTINUE);
	}
	SEPTUM_SOFFSET(&fp->septum, SEPTUM_GOFFSET(&fp->septum) + i);

	/* marks the end of string with `\0' */
	q = SEPTUM_GNUMBUF(&fp->septum);
	q[SEPTUM_GOFFSET(&fp->septum)] = '\0';

	/*
	 * Checks whether it has a completed form for content length.
	 */

	u = strtoul(SEPTUM_GNUMBUF(&fp->septum), &q, 16);

	/* Skip trailing whitespace */
	if (q != NULL && q > SEPTUM_GNUMBUF(&fp->septum)) {
       		while (*q == '\t' || *q == ' ')
			q++;
		if (*q == '\r')
			q++;
	}
	if (q == NULL || q == SEPTUM_GNUMBUF(&fp->septum) || *q != '\n') {
		if (SEPTUM_GOFFSET(&fp->septum) >=
		    SEPTUM_GNUMBUFLEN(&fp->septum)) {
			WSP(sp, SLT_FetchError, "chunked hex-line too long");
			fp->step = FET_ERROR;
			return (FETCH_CONTINUE);
		}
		fp->step = FET_CHUNKED_CL;
		return (FETCH_CONTINUE);
	}

	/* Skip NL */
	q++;

	if (u == 0)
		islastchunk = 1;

	/*
	 * NOTE: during processing the last chunk STV_alloc could be called
	 * multiple times but no harms because it calls STV_free or STV_trim
	 * if no datas.
	 */

	assert(SEPTUM_GSL(&fp->septum) >= 0);
	u += 2;	/* chunk length + CRLF */
	tlen = SEPTUM_GOFFSET(&fp->septum) + u;
	if ((st = SEPTUM_GST(&fp->septum)) == NULL ||
	    st->len + tlen > st->space ||
	    st->len == st->space) {
		if (st != NULL && st->len == 0) {
			VTAILQ_REMOVE(&sp->obj->store, st, list);
			STV_free(st);
		} else if (st != NULL && st->len < st->space) {
			/* Trims the previous storage */
			STV_trim(st, st->len);
		}
		v = tlen;
		if (tlen < params->fetch_chunksize * 1024)
			v = params->fetch_chunksize * 1024;
		st = STV_alloc(sp, v, NULL);
		VTAILQ_INSERT_TAIL(&sp->obj->store, st, list);
		SEPTUM_SST(&fp->septum, st);
	}

	if (islastchunk == 1)
		goto last_chunk;

	SEPTUM_SCL(&fp->septum, u);
	SEPTUM_SSL(&fp->septum, st->space - st->len);
	if (SEPTUM_GSL(&fp->septum) > SEPTUM_GCL(&fp->septum))
		SEPTUM_SSL(&fp->septum, SEPTUM_GCL(&fp->septum));
	assert(SEPTUM_GCL(&fp->septum) >= 0);
	assert(SEPTUM_GSL(&fp->septum) >= 0);

	/* Handle anything left in our buffer first */
	w = pdiff(q, SEPTUM_GNUMBUF(&fp->septum) + SEPTUM_GOFFSET(&fp->septum));
	/* XXX if my approach is right this assertion is always true */
	assert(w == 0);
	memcpy(st->ptr + st->len, SEPTUM_GNUMBUF(&fp->septum),
	    SEPTUM_GOFFSET(&fp->septum));
	st->len += SEPTUM_GOFFSET(&fp->septum);
	assert(st->len <= st->space);
	sp->obj->len += SEPTUM_GOFFSET(&fp->septum);
	SEPTUM_SPTR(&fp->septum, st->ptr + st->len);
	if (SEPTUM_GCL(&fp->septum) == 0)
		goto last_chunk;
	assert(SEPTUM_GSL(&fp->septum) > 0);

	fp->step = FET_RECV;
	return (FETCH_CONTINUE);

last_chunk:
	/* Checks CRLF to trail the chunks */
	w = pdiff(q, SEPTUM_GNUMBUF(&fp->septum) +
	    SEPTUM_GOFFSET(&fp->septum));
	if (w == 0) {
		/* looks the last chunk isn't delivered yet so get more */
		fp->step = FET_CHUNKED_CL;
		return (FETCH_CONTINUE);
	}
	if (w == 1) {
		if (q[0] == '\r') {
			fp->step = FET_CHUNKED_CL;
			return (FETCH_CONTINUE);
		}
		WSP(sp, SLT_FetchError, "chunked missing trailing crlf");
		fp->step = FET_ERROR;
		return (FETCH_CONTINUE);
	}
	assert(w == 2);
	if (q[0] != '\r' || q[1] != '\n') {
		WSP(sp, SLT_FetchError, "chunked missing trailing crlf");
		fp->step = FET_ERROR;
		return (FETCH_CONTINUE);
	}

	CAST_OBJ_NOTNULL(st, SEPTUM_GST(&fp->septum), STORAGE_MAGIC);

	memcpy(st->ptr + st->len, SEPTUM_GNUMBUF(&fp->septum),
	    SEPTUM_GOFFSET(&fp->septum));
	st->len += SEPTUM_GOFFSET(&fp->septum);
	assert(st->len <= st->space);
	sp->obj->len += SEPTUM_GOFFSET(&fp->septum);
	SEPTUM_SPTR(&fp->septum, st->ptr + st->len);

	if (st != NULL && st->len == 0) {
		VTAILQ_REMOVE(&sp->obj->store, st, list);
		STV_free(st);
	} else if (st != NULL && st->len < st->space)
		STV_trim(st, st->len);

	HSH_Rush(sp);

	fp->step = FET_DONE;
	return (FETCH_CONTINUE);
}

static enum fetch_status
fet_straight_or_eof(struct fetch *fp)
{
	struct sess *sp;
	struct storage *st = NULL;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);

	switch (sp->wrkvar.body_status) {
	case BS_LENGTH:
		st = STV_alloc(sp, SEPTUM_GCL(&fp->septum), NULL);
		SEPTUM_SSL(&fp->septum, st->space);
		if (SEPTUM_GSL(&fp->septum) > SEPTUM_GCL(&fp->septum))
			SEPTUM_SSL(&fp->septum, SEPTUM_GCL(&fp->septum));
		SEPTUM_SPTR(&fp->septum, st->ptr);
		break;
	case BS_EOF:
		st = STV_alloc(sp, params->fetch_chunksize * 1024LL, NULL);
		SEPTUM_SSL(&fp->septum, st->space - st->len);
		SEPTUM_SPTR(&fp->septum, st->ptr + st->len);
		break;
	default:
		WRONG("Unknown body status");
	}
	AN(st);
	SEPTUM_SST(&fp->septum, st);
	VTAILQ_INSERT_TAIL(&sp->obj->store, st, list);

	fp->step = FET_RECV;
	return (FETCH_CONTINUE);
}

static enum fetch_status
fet_recv(struct fetch *fp)
{
	struct http_conn *htc;
	struct sess *sp;
	struct storage *st;
	struct vbe_conn *vc;
	ssize_t i;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(htc, sp->wrkvar.htc, HTTP_CONN_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	i = HTC_Read(htc, SEPTUM_GPTR(&fp->septum), SEPTUM_GSL(&fp->septum));
	if (i == -2) {
		SEPTUM_FETCHEVENT(fp, htc->htc_fd, htc->htc_want,
		    CALLOUT_SECTOTICKS(vc->between_bytes_timeout));
		return (FETCH_WAIT);
	}
	CAST_OBJ_NOTNULL(st, SEPTUM_GST(&fp->septum), STORAGE_MAGIC);
	if (i <= 0) {
		switch (sp->wrkvar.body_status) {
		case BS_LENGTH:
			WSP(sp, SLT_FetchError,
			    "straight read_error: %d %d", i, errno);
			fp->step = FET_ERROR;
			return (FETCH_CONTINUE);
		case BS_EOF:
			if (i < 0) {
				WSP(sp, SLT_FetchError,
				    "eof read_error: %d %d", i, errno);
				fp->step = FET_ERROR;
				return (FETCH_CONTINUE);
			}
			assert(i == 0);
			if (st->len == 0) {
				VTAILQ_REMOVE(&sp->obj->store, st, list);
				STV_free(st);
			} else
				STV_trim(st, st->len);
			/* EOF couldn't recycle the connection again */
			sp->flags |= SESS_F_CLOSE;
			fp->step = FET_DONE;
			return (FETCH_CONTINUE);
		case BS_CHUNKED:
			WSP(sp, SLT_FetchError,
			    "chunked read_error: %d %d", i, errno);
			fp->step = FET_ERROR;
			return (FETCH_CONTINUE);
		default:
			WRONG("Unknown body status for error handling");
		}
	}
	/*
	 * Aborts the fetcher if the client is disconnected.
	 *
	 * XXX at here we can add some options such as keeping the fetcher to
	 * download the content if the download rate is over some threshold.
	 */
	if (params->quickabort == 1 &&
	    (sp->flags & SESS_F_QUICKABORT) != 0) {
		WSP(sp, SLT_FetchError, "client aborted its connection.");
		fp->step = FET_ERROR;
		return (FETCH_CONTINUE);
	}
	SEPTUM_SPTR(&fp->septum, SEPTUM_GPTR(&fp->septum) + i);
	SEPTUM_SSL(&fp->septum, SEPTUM_GSL(&fp->septum) - i);
	if (sp->wrkvar.body_status == BS_LENGTH ||
	    sp->wrkvar.body_status == BS_CHUNKED)
		SEPTUM_SCL(&fp->septum, SEPTUM_GCL(&fp->septum) - i);
	st->len += i;
	assert(st->len <= st->space);
	sp->obj->len += i;

	/* the data is ready at this moment so rush the waiting sessions.  */
	HSH_Rush(sp);

	switch (sp->wrkvar.body_status) {
	case BS_LENGTH:
		assert(SEPTUM_GCL(&fp->septum) >= 0);
		if (SEPTUM_GCL(&fp->septum) == 0) {
			fp->step = FET_DONE;
			return (FETCH_CONTINUE);
		}
		/* FALLTHROUGH */
	case BS_EOF:
		assert(SEPTUM_GSL(&fp->septum) >= 0);
		if (SEPTUM_GSL(&fp->septum) == 0) {
			fp->step = FET_STRAIGHT_OR_EOF;
			return (FETCH_CONTINUE);
		}
		fp->step = FET_RECV;
		return (FETCH_CONTINUE);
	case BS_CHUNKED:
		if (SEPTUM_GCL(&fp->septum) <= 0) {
			SEPTUM_SOFFSET(&fp->septum, 0);
			fp->step = FET_CHUNKED_CL;
			return (FETCH_CONTINUE);
		}
		assert(SEPTUM_GSL(&fp->septum) > 0);
		fp->step = FET_RECV;
		return (FETCH_CONTINUE);
	default:
		WRONG("Wrong body status");
	}
}

static enum fetch_status
fet_error(struct fetch *fp)
{
	struct sess *sp;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);

	sp->wrk->stats.fetch_failed++;
	sp->obj->flags |= OBJECT_F_ERROR;
	/* Marks whether the backend connection should be closed or not */
	sp->flags |= SESS_F_CLOSE;

	fp->step = FET_DONE;
	return (FETCH_CONTINUE);
}

static enum fetch_status
fet_done(struct fetch *fp)
{
	struct sess *sp;
	struct storage *st;
	ssize_t uu = 0;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);

	if ((sp->obj->flags & OBJECT_F_ERROR) == 0) {
		/* Sanity check fetch methods accounting */
		VTAILQ_FOREACH(st, &sp->obj->store, list)
			uu += st->len;
		assert(uu == sp->obj->len);
	}
	if (sp->obj->len == 0)
		sp->obj->flags |= OBJECT_F_ZEROLEN;
	sp->obj->flags |= OBJECT_F_DONE;

	/* all fetch is done so wakes up all */
	HSH_Rush(sp);
	return (FETCH_DONE);
}

enum fetch_status
FET_Session(struct fetch *fp)
{
	struct sess *sp;
	struct worker *w;
	enum fetch_status status = FETCH_CONTINUE;

	CHECK_OBJ_NOTNULL(fp, FETCH_MAGIC);
	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(w, fp->wrk, WORKER_MAGIC);

	for (;status == FETCH_CONTINUE;) {
		assert(fp->wrk == w);

#ifdef VARNISH_DEBUG
		fp->stephist[fp->stephist_cur++] = fp->step;
		if (fp->stephist_cur >= STEPHIST_MAX)
			fp->stephist_cur = 0;
#endif

		if (params->diag_bitmap & 0x00080000)
			WSL(fp->wrk, SLT_FetchSM, fp->vc.vc_fd, "%s",
			    fet_stepstr[fp->step]);

		switch (fp->step) {
#define FETCHSTEP(l,u)				\
		case FET_##u:			\
			status = fet_##l(fp);	\
			break;
#include "fetchsteps.h"
#undef FETCHSTEP
		default:
			WRONG("fetch state engine misfire");
		}
		assert(fp->wrk == w);

		if (params->diag_bitmap & 0x00080000)
			WSL(fp->wrk, SLT_FetchSM, fp->vc.vc_fd, "%s",
			    fet_statusstr[status]);
	}
	WSL_Flush(w, 0);
	return (status);
}

void
FET_Wakeup(struct fetch *fp)
{
	struct septum *st = &fp->septum;
	struct sess *sp;

	CAST_OBJ_NOTNULL(sp, fp->sess, SESS_MAGIC);

	SPT_Wakeup(sp->wrk, st);
}

void
FET_EventAdd(struct fetch *fp)
{
	struct worker *w = fp->wrk;

	SPT_EventAdd(w->fd, &fp->septum);
}

void
FET_EventDel(struct fetch *fp)
{
	struct worker *w = fp->wrk;

	SPT_EventDel(w->fd, &fp->septum);
}

void
FET_Init(struct sess *sp)
{
	struct fetch *fp = (struct fetch *)sp->vc;
	struct vbe_conn *vc;

	CAST_OBJ_NOTNULL(vc, &(fp)->vc, VBE_CONN_MAGIC);
	CHECK_OBJ_NOTNULL(&((vc)->common), VBE_COMMON_MAGIC);
	assert((vc)->common.type == VBE_TYPE_FETCH);

	fp->magic = FETCH_MAGIC;
	fp->flags = 0;
	fp->sess = sp;
	fp->wrk = sp->wrk;
	fp->step = FET_FIRST;
	/* XXX really need? */
	bzero(&fp->septum, sizeof(struct septum));
	fp->septum.type = SEPTUM_FETCH;
	fp->septum.arg = fp;
}
