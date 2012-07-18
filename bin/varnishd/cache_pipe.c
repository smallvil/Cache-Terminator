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
 * XXX: charge bytes to srcaddr
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_pipe.c 103 2011-04-12 06:54:31Z jwg286 $")

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "shmlog.h"
#include "cache.h"
#include "cache_backend.h"

static const char *pie_statusstr[] = {
	"CONTINUE",
	"DONE",
	"SLEEP",
	"WAIT"
};
const char *pie_stepstr[] = {
#define PIPESTEP(l,u)	"PIE_" #u,
#include "pipesteps.h"
#undef PIPESTEP
};

static void
pie_EventTimeout(void *arg)
{
	struct pipe *dp = arg;
	struct septum *st = &dp->septum;

	callout_stop(dp->wrk, &st->co);
	PIE_Wakeup(dp);
}

/* this function would be called in COT_clock() */
static void
PIE_SessionTimeout(void *arg)
{
	struct pipe *dp = arg;

	dp->step = PIE_TIMEOUT;
	pie_EventTimeout(dp);
	PIE_EventDel(dp);
}

static enum pipe_status
pie_timeout(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	dp->flags |= PIPE_F_PIPEDONE;
	if ((dp->flags & PIPE_F_SESSDONE) != 0) {
		dp->step = PIE_END;
		return (PIPE_CONTINUE);
	}
	(void)shutdown(vc->vc_fd, SHUT_RD);	/* XXX */
	(void)shutdown(sp->sp_fd, SHUT_WR);	/* XXX */
	dp->step = PIE_END;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_first(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;

	CHECK_OBJ_NOTNULL(dp, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	dp->t_last = TIM_real();
	TCP_hisname(vc->vc_fd, dp->addr, sizeof(dp->addr), dp->port,
	    sizeof(dp->port));

	dp->step = PIE_RECV;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_recv(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;

	CHECK_OBJ_NOTNULL(dp, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	if (params->tcp_info_interval > 0)
		CNT_EmitTCPInfo(sp, vc->vc_fd, &dp->t_last, "b", dp->addr,
		    dp->port, 0);

	dp->buflen[1] = 0;
	dp->step = PIE_RECV_FROMBACKEND;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_recv_frombackend(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;
	int i;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	i = CFD_read(&vc->fds, dp->buf[1], dp->bufsize);
	if (i == -2) {
		SEPTUM_PIPEEVENT(dp, vc->vc_fd, vc->vc_want,
		    (vc->vc_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (PIPE_WAIT);
	}
	if (i <= 0) {
		if (i == -1)
			WSP(sp, SLT_Error, "%s: read(2) %d %s", __func__, errno,
			    strerror(errno));
		else
			WSP(sp, SLT_Error, "%s: read(2) eof", __func__);
		dp->flags |= PIPE_F_PIPEDONE;
		if ((dp->flags & PIPE_F_SESSDONE) != 0) {
			dp->step = PIE_END;
			return (PIPE_CONTINUE);
		}
		(void)shutdown(vc->vc_fd, SHUT_RD);	/* XXX */
		(void)shutdown(sp->sp_fd, SHUT_WR);	/* XXX */
		dp->step = PIE_END;
		return (PIPE_CONTINUE);
	}
	assert(i > 0);
	dp->buflen[1] = i;
	dp->step = PIE_SEND;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_send(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	assert(dp->buflen[1] > 0);
	dp->bufoffset[1] = 0;
	dp->step = PIE_SEND_TOCLIENT;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_send_toclient(struct pipe *dp)
{
	struct septum *st = &dp->septum;
	struct sess *sp;
	struct vbe_conn *vc;
	int i, len;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	len = dp->buflen[1] - dp->bufoffset[1];
	assert(len != 0);

	i = CFD_write(&sp->fds, dp->buf[1] + dp->bufoffset[1], len);
	if (i == -2) {
		/* XXX a hack; see a comment on TUNNEL_PIPE_SEND_TOBACKEND */
		VSL_stats->pipe_callout_client++;
		callout_reset(dp->wrk, &st->co, 0, pie_EventTimeout, dp);
		PIE_Sleep(dp);
		return (PIPE_SLEEP);
	}
	if (i <= 0) {
		dp->flags |= PIPE_F_PIPEDONE;
		if ((dp->flags & PIPE_F_SESSDONE) != 0) {
			dp->step = PIE_END;
			return (PIPE_CONTINUE);
		}
		(void)shutdown(vc->vc_fd, SHUT_RD);	/* XXX */
		(void)shutdown(sp->sp_fd, SHUT_WR);	/* XXX */
		dp->step = PIE_END;
		return (PIPE_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		dp->bufoffset[1] += i;
		return (PIPE_CONTINUE);
	}
	dp->step = PIE_RECV;
	return (PIPE_CONTINUE);
}

static enum pipe_status
pie_end(struct pipe *dp)
{
	struct sess *sp;
	struct vbe_conn *vc;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	if (params->tcp_info_interval > 0)
		CNT_EmitTCPInfo(sp, vc->vc_fd, &dp->t_last, "b", dp->addr,
		    dp->port, 1);

	/*
	 * Only wake up SP if it's waiting our response.  At here we don't
	 * need to take care locks because there's a assumption that it's
	 * happening on the same thread between SP and DP.
	 */
	if ((dp->flags & PIPE_F_SESSDONE) != 0)
		SES_Wakeup(sp);
	return (PIPE_DONE);
}

enum pipe_status
PIE_Session(struct pipe *dp)
{
	enum pipe_status status = PIPE_CONTINUE;
	struct worker *w;

	CHECK_OBJ_NOTNULL(dp, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(w, dp->wrk, WORKER_MAGIC);

	for (;status == PIPE_CONTINUE;) {
		assert(dp->wrk == w);

		if (params->diag_bitmap & 0x00080000)
			WSL(dp->wrk, SLT_PipeSM, dp->vc.vc_fd, "%s",
			    pie_stepstr[dp->step]);

#ifdef VARNISH_DEBUG
		dp->stephist[dp->stephist_cur++] = dp->step;
		if (dp->stephist_cur >= STEPHIST_MAX)
			dp->stephist_cur = 0;
#endif
		switch (dp->step) {
#define PIPESTEP(l,u)				\
		case PIE_##u:			\
			status = pie_##l(dp);	\
			break;
#include "pipesteps.h"
#undef PIPESTEP
		default:
			WRONG("Drainpipe state engine misfire");
		}
		assert(dp->wrk == w);

		if (params->diag_bitmap & 0x00080000)
			WSL(dp->wrk, SLT_PipeSM, dp->vc.vc_fd, "%s",
			    pie_statusstr[status]);
	}
	WSL_Flush(w, 0);
	return (status);
}

void
PIE_Wakeup(struct pipe *dp)
{
	struct septum *st = &dp->septum;
	struct sess *sp;
	struct worker *w;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(w, sp->wrk, WORKER_MAGIC);

	SPT_Wakeup(w, st);
	w->nwaiting--;
	assert(w->nwaiting >= 0);

	if (params->diag_bitmap & 0x00100000)
		WSL(w, SLT_Debug, sp->sp_fd, "PIPE wakeup <w %p sp %p>",
		    w, sp);
}

void
PIE_Sleep(struct pipe *dp)
{
	struct sess *sp;
	struct worker *w;

	CAST_OBJ_NOTNULL(sp, dp->sess, SESS_MAGIC);
	CAST_OBJ_NOTNULL(w, sp->wrk, WORKER_MAGIC);

	assert(w->nwaiting >= 0);
	w->nwaiting++;

	if (params->diag_bitmap & 0x00100000)
		WSL(w, SLT_Debug, sp->sp_fd,
		    "PIPE sleep <w %p sp %p>", w, sp);
}

void
PIE_EventAdd(struct pipe *dp)
{
	struct worker *w = dp->wrk;

	SPT_EventAdd(w->fd, &dp->septum);
}

void
PIE_EventDel(struct pipe *dp)
{
	struct worker *w = dp->wrk;

	SPT_EventDel(w->fd, &dp->septum);
}

void
PIE_Init(struct sess *sp)
{
	struct pipe *dp = (struct pipe *)sp->vc;
	struct vbe_conn *vc;

	CAST_OBJ_NOTNULL(vc, &(dp)->vc, VBE_CONN_MAGIC);
	CHECK_OBJ_NOTNULL(&((vc)->common), VBE_COMMON_MAGIC);
	assert((vc)->common.type == VBE_TYPE_PIPE);

	dp->magic = PIPE_MAGIC;
	dp->flags |= PIPE_F_STARTED;
	dp->sess = sp;
	dp->wrk = sp->wrk;
	dp->buf[0] = WS_Alloc(sp->ws, BUFSIZ);
	AN(dp->buf[0]);
	dp->buf[1] = WS_Alloc(sp->ws, BUFSIZ);
	AN(dp->buf[1]);
	dp->buflen[0] = 0;
	dp->buflen[1] = 0;
	dp->bufsize = BUFSIZ;
	dp->septum.type = SEPTUM_PIPE;
	dp->septum.arg = dp;
}
