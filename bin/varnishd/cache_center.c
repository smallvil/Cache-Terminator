/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2010 Redpill Linpro AS
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
 * This file contains the central state machine for pushing requests.
 *
 * We cannot just use direct calls because it is possible to kick a
 * request back to the lookup stage (usually after a rewrite).  The
 * state engine also allows us to break the processing up into some
 * logical chunks which improves readability a little bit.
 *
 * Since the states are rather nasty in detail, I have decided to embedd
 * a dot(1) graph in the source code comments.  So to see the big picture,
 * extract the DOT lines and run though dot(1), for instance with the
 * command:
 *	sed -n '/^DOT/s///p' cache_center.c | dot -Tps > /tmp/_.ps
 */

/*
DOT digraph vcl_center {
xDOT	page="8.2,11.5"
DOT	size="7.2,10.5"
DOT	margin="0.5"
DOT	center="1"
DOT acceptor [
DOT	shape=hexagon
DOT	label="Request received"
DOT ]
DOT ERROR [shape=plaintext]
DOT RESTART [shape=plaintext]
DOT acceptor -> start [style=bold,color=green,weight=4]
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_center.c 147 2011-04-15 20:46:28Z jwg286 $")

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef HAVE_SRANDOMDEV
#include "compat/srandomdev.h"
#endif

#include "shmlog.h"
#include "vcl.h"
#include "cli_priv.h"
#include "cache.h"
#include "cache_backend.h"
#include "hash_slinger.h"
#include "stevedore.h"

static unsigned xids;
static const char *cnt_statusstr[] = {
	"CONTINUE",
	"DONE",
	"SLEEP",
	"WAIT"
};
const char *cnt_stepstr[] = {
#define STEP(l,u)	"STP_" #u,
#include "steps.h"
#undef STEP
};

void
CNT_EmitTCPInfo(struct sess *sp, int fd, double *last, const char *prefix,
    const char *addr, const char *port, int force)
{
	struct tcp_info tcpi;
	double now = TIM_real();
	socklen_t size;

	if (force == 0 && (now - *last) < params->tcp_info_interval)
		return;

	size = sizeof(struct tcp_info);
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, (void *)&tcpi, &size))
		return;

#ifdef __FreeBSD__
	WSP(sp, SLT_TCPInfo, "%p %s %s %s %d %u %u %u %u %u %u"
	    " %u %u %u %u %u"
	    " %u %u %u %u %u %u %u %u", sp, prefix, addr, port, force,
	    0, 0,
	    tcpi.tcpi_rto, 0,
	    tcpi.tcpi_snd_mss, tcpi.tcpi_rcv_mss,
	    0, 0,
	    0, 0,
	    0,
	    0, 0,
	    tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
	    tcpi.tcpi_snd_ssthresh, tcpi.tcpi_snd_cwnd,
	    0, 0);
#else
	WSP(sp, SLT_TCPInfo, "%p %s %s %s %d %u %u %u %u %u %u"
	    " %u %u %u %u %u"
	    " %u %u %u %u %u %u %u %u", sp, prefix, addr, port, force,
	    tcpi.tcpi_retransmits, tcpi.tcpi_probes,
	    tcpi.tcpi_rto, tcpi.tcpi_ato,
	    tcpi.tcpi_snd_mss, tcpi.tcpi_rcv_mss,
	    tcpi.tcpi_unacked, tcpi.tcpi_sacked,
	    tcpi.tcpi_lost, tcpi.tcpi_retrans,
	    tcpi.tcpi_fackets,
	    tcpi.tcpi_pmtu, tcpi.tcpi_rcv_ssthresh,
	    tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
	    tcpi.tcpi_snd_ssthresh, tcpi.tcpi_snd_cwnd,
	    tcpi.tcpi_advmss, tcpi.tcpi_reordering);
#endif
	*last = now;
}

/*--------------------------------------------------------------------
 * TIMEOUT
 * Timeout events are passed
 */
static enum sess_status
cnt_timeout(struct sess *sp)
{
	enum step prevstep = (enum step)TRUST_ME(sp->cur_method);
	struct http_conn *htc;
	struct pipe *dp;
	struct vbe_conn *vc;

	switch (prevstep) {
	case STP_HTTP_PIPE_CONNECT:
		/*
		 * in here the reason why it moved to STP_HTTP_PIPE_CLOSEWAIT is
		 * we have a assumption that it goes to DONE step.
		 */
		SESS_ERROR(sp, 503, "pipe connect timeout");
		sp->step = STP_HTTP_PIPE_END;
		return (SESS_CONTINUE);
	case STP_HTTP_WAIT_RECV:
		vca_close_session(sp, "error");
		sp->step = STP_DONE;
		break;
	case STP_HTTP_FETCH_CONNECT:
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "fetch connect timeout");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	case STP_HTTP_FETCH_RESP_RECV_FIRSTBYTE:
		CAST_OBJ_NOTNULL(htc, sp->wrkvar.htc, HTTP_CONN_MAGIC);
		WS_ReleaseP(htc->ws, htc->rxbuf.b);
		VBE_CloseFd(sp, &sp->vc, 0);

		SESS_ERROR(sp, 503, "fetch firstbyte timeout");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	case STP_SOCKS_RECV:
		vca_close_session(sp, "SOCKS read timeout");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case STP_SOCKSv4_CONNECT_DO:
		SESS_ERROR(sp, SOCKSv4_S_REJECTED,
		    "SOCKSv4 connect timeout");
		sp->step = STP_SOCKSv4_ERROR;
		return (SESS_CONTINUE);
	case STP_SOCKSv5_RECV:
		vca_close_session(sp, "SOCKSv5 read timeout");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case STP_SOCKSv5_CONNECT_DO:
		SESS_ERROR(sp, SOCKSv5_S_SOCKS_FAIL,
		    "SOCKSv5 connect timeout");
		sp->step = STP_SOCKSv5_ERROR;
		return (SESS_CONTINUE);
	case STP_SOCKS_PIPE_RECV_FROMCLIENT:
		CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
		CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_SOCKS_PIPE_END;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_SOCKS_PIPE_END;
		return (SESS_CONTINUE);
	case STP_TUNNEL_CONNECT:
		SESS_ERROR(sp, TUNNEL_ERROR_CONNECT, "tunnel connect timeout");
		sp->step = STP_TUNNEL_PIPE_END;
		return (SESS_CONTINUE);
	default:
		WRONG("Uncovered timeout step");
	}
	return (SESS_CONTINUE);
}

static void
cnt_WakeupCallout(void *arg)
{
	struct sess *sp = arg;

	SES_Wakeup(sp);
}

/* this function would be called in COT_clock() */
static void
CNT_SessionTimeout(void *arg)
{
	struct sess *sp = arg;
	struct septum *st = &sp->septum;

	sp->cur_method = sp->step; /* XXX hack for a temp variable */
	sp->step = STP_TIMEOUT;
	callout_stop(sp->wrk, &st->co);
	SES_EventDel(sp);
	SES_Wakeup(sp);
}

/*--------------------------------------------------------------------
 * The very first request
 */
static enum sess_status
cnt_first(struct sess *sp)
{
	struct listen_sock *ls;
	int ret;

	/*
	 * XXX: If we don't have acceptfilters we are somewhat subject
	 * XXX: to DoS'ing here.  One remedy would be to set a shorter
	 * XXX: SO_RCVTIMEO and once we have received something here
	 * XXX: increase it to the normal value.
	 */

	assert(sp->xid == 0);
	assert(sp->restarts == 0);
	VCA_Prep(sp);

	/* Record the session watermark */
	sp->ws_ses = WS_Snapshot(sp->ws);

	sp->wrk->lastused = sp->t_open;
	sp->acct_tmp.sess++;

	/*
	 * Get VCL reference.  Note that there are two points to get VCL
	 * reference at state machine.  First is here and second is at
	 * STP_HTTP_START.  Normally holding VCL reference would happen once
	 * for most connection but if the persistent connection (aka keep-alive
	 * connection) is involved it could be held multiple times.
	 */
	AZ(sp->vcl);
	VCL_Refresh(&sp->vcl);
	AZ(sp->geoip);
	GEO_Refresh(&sp->geoip);

	VCL_accept_method(sp);
	switch (sp->handling) {
	case VCL_RET_HTTP:
		ls = sp->mylsock;
		/* if ls->ssl_ctx isn't NULL it means it's for SSL listen */
		if (ls->ssl_ctx != NULL) {
			sp->sp_ssl = SSL_new(sp->mylsock->ssl_ctx);
			AN(sp->sp_ssl);
			SSL_set_accept_state(sp->sp_ssl);
			ret = SSL_set_fd(sp->sp_ssl, sp->sp_fd);
			assert(ret == 1);
		}

		/* Receive a HTTP protocol request */
		HTC_Init(sp->htc, sp->ws, sp->sp_fd, sp->sp_ssl);
		sp->step = STP_HTTP_WAIT_BEGIN;
		break;
	case VCL_RET_PIPE:
		sp->step = STP_TUNNEL_START;
		break;
	case VCL_RET_SOCKS:
		sp->step = STP_SOCKS_START;
		break;
	default:
		WRONG("Wrong handling value for accept method");
	}

	return (SESS_CONTINUE);
}

/* Note that it's named as TUNNEL but it's almost same with pipe operation. */
static enum sess_status
cnt_tunnel_start(struct sess *sp)
{
	struct vbe_conn *vc;

	sp->wrk->stats.tunnel_req++;

	/* If no director is set at `VCL_acecept_method' then use the first */
	if (sp->director == NULL)
		sp->director = sp->vcl->director[0];

	AZ(sp->vc);
	vc = sp->vc = VBE_GetConn(NULL, sp, VBE_TYPE_PIPE);
	if (vc == NULL) {
		assert(0 == 1);
		return (SESS_SLEEP);
	}
	vc->vc_fd = VBE_GetSocket(sp, vc);
	if (vc->vc_fd == -1)
		assert(0 == 1);

	sp->step = STP_TUNNEL_CONNECT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_connect(struct sess *sp)
{
	struct vbe_conn *vc;
	double timeout;
	int i;
	char abuf1[TCP_ADDRBUFSIZE], abuf2[TCP_ADDRBUFSIZE];
	char pbuf1[TCP_PORTBUFSIZE], pbuf2[TCP_PORTBUFSIZE];

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	i = connect(vc->vc_fd, (struct sockaddr *)&vc->sa, vc->salen);
	if (i == -1 && errno == EINPROGRESS) {
		FIND_TMO(connect_timeout, timeout, sp, vc->backend);
		SEPTUM_SESSEVENT(sp, vc->vc_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(timeout));
		return (SESS_WAIT);
	}
	if (i == -1 && errno != EISCONN) {
		VBE_CloseFd(sp, &sp->vc, 0);
		sp->step = STP_TUNNEL_END;
		return (SESS_CONTINUE);
	}
	TCP_myname(vc->vc_fd, abuf1, sizeof(abuf1), pbuf1, sizeof(pbuf1));
	TCP_name((struct sockaddr *)&vc->sa, vc->salen, abuf2, sizeof(abuf2),
	    pbuf2, sizeof(pbuf2));
	WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd, "%s %s %s -> %s %s",
	    vc->backend->vcl_name, abuf1, pbuf1, abuf2, pbuf2);

	sp->step = STP_TUNNEL_PIPE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe(struct sess *sp)
{
	struct pipe *dp;

	PIE_Init(sp);
	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	PIE_Wakeup(dp);

	sp->step = STP_TUNNEL_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe_recv(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	dp->buflen[0] = 0;
	sp->step = STP_TUNNEL_PIPE_RECV_FROMCLIENT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe_recv_fromclient(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;
	int i;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	i = read(sp->sp_fd, dp->buf[0], dp->bufsize);
	if (i == -1 && errno == EAGAIN) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd,
		    SEPTUM_WANT_READ,
		    CALLOUT_SECTOTICKS(params->recv_timeout));
		return (SESS_WAIT);
	}
	if (i == -1 || i == 0) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_TUNNEL_PIPE_END;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_TUNNEL_PIPE_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	dp->buflen[0] = i;
	sp->step = STP_TUNNEL_PIPE_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe_send(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	assert(dp->buflen[0] > 0);
	dp->bufoffset[0] = 0;
	sp->step = STP_TUNNEL_PIPE_SEND_TOBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe_send_tobackend(struct sess *sp)
{
	struct pipe *dp;
	struct septum *st = &sp->septum;
	struct vbe_conn *vc;
	int i, len;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	len = dp->buflen[0] - dp->bufoffset[0];
	assert(len != 0);
	i = write(vc->vc_fd, dp->buf[0] + dp->bufoffset[0], len);
	if (i == -1 && errno == EAGAIN) {
		/*
		 * XXX a hack; exists due to lack of my brain knowledge that
		 * in the previous implementation it used two epoll descriptors
		 * to implement a pipe but I hoped it's reduced into one so
		 * the resule is here but the problem is that epoll doesn't
		 * allow registering a fd twice so the state machine should
		 * see two events (for IN and OUT) simultaneously.  It means
		 * when vc->vc_fd is registered for WRITABLE and at same time
		 * vc->vc_fd is registered for READABLE it'd be crashed because
		 * of a assert.
		 */
		VSL_stats->pipe_callout_backend++;
		callout_reset(sp->wrk, &st->co, 0, cnt_WakeupCallout, sp);
		SES_Sleep(sp);
		return (SESS_SLEEP);
	}
	if (i == -1) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_TUNNEL_PIPE_END;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_TUNNEL_PIPE_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		dp->bufoffset[0] += i;
		return (SESS_CONTINUE);
	}
	sp->step = STP_TUNNEL_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_pipe_end(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	if ((dp->flags & PIPE_F_STARTED) != 0) {
		if ((dp->flags & PIPE_F_PIPEDONE) == 0) {
			SES_Sleep(sp);
			return (SESS_SLEEP);
		}
		assert((dp->flags & PIPE_F_SESSDONE) != 0 &&
		    (dp->flags & PIPE_F_PIPEDONE) != 0);
	}

	sp->step = STP_TUNNEL_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_tunnel_end(struct sess *sp)
{

	vca_close_session(sp, "tunnel");
	VBE_CloseFd(sp, &sp->vc, 0);
	sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_start(struct sess *sp)
{

	/* By default we use the first backend */
	AZ(sp->director);
	sp->director = sp->vcl->director[0];
	AN(sp->director);
	sp->t_last = TIM_real();

	sp->wrk->stats.socks_req++;
	SCK_Init(sp->socks.stc, sp->ws, sp->sp_fd);
	sp->step = STP_SOCKS_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_recv(struct sess *sp)
{
	struct socks_conn *stc = sp->socks.stc;
	int i;
	const char *p;

	i = SCK_Rx(stc, SOCKS_T_V4REQ_OR_V5AUTH);
	switch (i) {
	case -4:
		vca_close_session(sp, "corrupted format");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case -3:
	case 0:
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_READ,
		    CALLOUT_SECTOTICKS(params->recv_timeout));
		return (SESS_WAIT);
	case -2:
		vca_close_session(sp, "out of buffer");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case -1:
		vca_close_session(sp, "read(2) error");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	default:
		assert(i == 1);
		break;
	}

	Tcheck(stc->rxbuf);
	p = stc->rxbuf.b;
	if (p[0] == SOCKS_VER4) {
		sp->wrk->stats.socks_v4_req++;
		sp->step = STP_SOCKSv4_REQ;
		return (SESS_CONTINUE);
	}
	if (p[0] == SOCKS_VER5) {
		sp->wrk->stats.socks_v5_auth++;
		sp->step = STP_SOCKSv5_AUTH;
		return (SESS_CONTINUE);
	}
	vca_close_session(sp, "invalid socks version");
	sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_req(struct sess *sp)
{
	struct socks_conn *stc = sp->socks.stc;
	const char *p;

	Tcheck(stc->rxbuf);
	assert(stc->pipeline.b == NULL);
	p = stc->rxbuf.b;

	assert(p[0] == SOCKS_VER4);
	assert(p[1] == SOCKSv4_C_CONNECT || p[1] == SOCKSv4_C_BIND);

	switch (p[1]) {
	case SOCKSv4_C_CONNECT:
		sp->step = STP_SOCKSv4_CONNECT;
		break;
	case SOCKSv4_C_BIND:
		/* XXX FALLTHROUGH */
	default:
		assert(0 == 1);
	}
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_connect(struct sess *sp)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)&sp->socks.sockaddr;
	struct socks_conn *stc = sp->socks.stc;
	struct vbe_conn *vc;
	const unsigned short *q;
	const char *p;

	Tcheck(stc->rxbuf);
	p = stc->rxbuf.b;
	q = (const unsigned short *)p;

	assert(p[0] == SOCKS_VER4);
	assert(p[1] == SOCKSv4_C_CONNECT);

	if (p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] != 0)
		assert(0 == 1);		/* FQDN */

	sp->socks.sockaddrlen = sizeof(struct sockaddr_in);
	bzero(in4, sp->socks.sockaddrlen);
	in4->sin_family = AF_INET;
	assert(sizeof(struct in_addr) == 4);
	bcopy(p + 4, &in4->sin_addr, sizeof(struct in_addr));
	in4->sin_port = q[1];

	if (params->diag_bitmap & 0x00080000) {
		char buf[BUFSIZ];

		/*
		 * Emits the debugging entry before the connection timeout
		 * is happened.
		 */
		p = inet_ntop(AF_INET, (const void *)&in4->sin_addr, buf,
		    BUFSIZ);
		WSL(sp->wrk, SLT_Debug, sp->sp_fd,
		    "SOCKSv4 Connect %s %d", p, ntohs(in4->sin_port));
	}

	/*
	 * XXX there are two points to call `vcl_socks_req' method.  Should
	 * be merged.
	 */
	VCL_socks_req_method(sp);
	switch (sp->handling) {
	case VCL_RET_DROP:
		assert(0 == 1);
	case VCL_RET_PIPE:
		break;
	default:
		WRONG("Unexpected return handling");
	}

	AZ(sp->vc);
	vc = sp->vc = VBE_GetConn(NULL, sp, VBE_TYPE_PIPE);
	if (vc == NULL) {
		assert(0 == 1);
		return (SESS_SLEEP);
	}
	vc->vc_fd = VBE_GetSocket(sp, vc);
	if (vc->vc_fd == -1)
		assert(0 == 1);

	sp->step = STP_SOCKSv4_CONNECT_DO;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_connect_do(struct sess *sp)
{
	struct vbe_conn *vc = sp->vc;
	double timeout;
	int i;
	char abuf1[TCP_ADDRBUFSIZE], abuf2[TCP_ADDRBUFSIZE];
	char pbuf1[TCP_PORTBUFSIZE], pbuf2[TCP_PORTBUFSIZE];

	i = connect(vc->vc_fd, &sp->socks.sockaddr, sp->socks.sockaddrlen);
	if (i == -1 && errno == EINPROGRESS) {
		FIND_TMO(connect_timeout, timeout, sp, vc->backend);
		SEPTUM_SESSEVENT(sp, vc->vc_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(timeout));
		return (SESS_WAIT);
	}
	if (i == -1 && errno != EISCONN) {
		SESS_ERROR(sp, SOCKSv4_S_REJECTED, "SOCKSv4 connect error");
		sp->step = STP_SOCKSv4_ERROR;
		return (SESS_CONTINUE);
	}
	TCP_myname(vc->vc_fd, abuf1, sizeof(abuf1), pbuf1, sizeof(pbuf1));
	TCP_name(&sp->socks.sockaddr, sp->socks.sockaddrlen,
	    abuf2, sizeof(abuf2), pbuf2, sizeof(pbuf2));
	WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd, "%s %s %s -> %s %s",
	    vc->backend->vcl_name, abuf1, pbuf1, abuf2, pbuf2);

	sp->step = STP_SOCKSv4_RESP;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_resp(struct sess *sp)
{
	struct socksv4_resp *resp = &sp->socks.resp;

	assert(sizeof(struct socksv4_resp) == 8);
	resp->nullbyte = 0;
	resp->status = SOCKSv4_S_GRANTED;
	SEPTUM_SOFFSET(&sp->septum, 0);

	sp->step = STP_SOCKSv4_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_error(struct sess *sp)
{
	struct socksv4_resp *resp = &sp->socks.resp;

	sp->wrk->stats.socks_v4_error++;

	assert(sizeof(struct socksv4_resp) == 8);
	resp->nullbyte = 0;
	resp->status = sp->err_code;
	SEPTUM_SOFFSET(&sp->septum, 0);

	sp->step = STP_SOCKSv4_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv4_send(struct sess *sp)
{
	int i, len;
	char *p;

	p = (char *)&sp->socks.resp;
	len = sizeof(struct socksv4_resp) - SEPTUM_GOFFSET(&sp->septum);
	i = write(sp->sp_fd, p + SEPTUM_GOFFSET(&sp->septum), len);
	if (i == -1 && errno == EAGAIN) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		sp->step = STP_SOCKS_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		SEPTUM_SOFFSET(&sp->septum, SEPTUM_GOFFSET(&sp->septum) + i);
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	/* SESS_F_ERROR could be set if a timeout is happened.  */
	if ((sp->flags & SESS_F_ERROR) != 0) {
		sp->step = STP_SOCKS_END;
		return (SESS_CONTINUE);
	}
	sp->step = STP_SOCKS_PIPE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_auth(struct sess *sp)
{
	struct socks_conn *stc = sp->socks.stc;
	unsigned int i, found = 0, nmethods;
	const char *p;

	Tcheck(stc->rxbuf);
	assert(stc->pipeline.b == NULL);
	p = stc->rxbuf.b;

	assert(p[0] == SOCKS_VER5);
	nmethods = (unsigned int)p[1];
	assert(Tlen(stc->rxbuf) == 1 /* VER */ + 1 /* NMETHOD */ + nmethods);
	for (i = 0; i < nmethods; i++) {
		if (p[2 + i] == SOCKSv5_A_NOAUTH) {
			found = 1;
			break;
		}
	}
	if (found == 0) {
		/* SESS_ERROR marks a SESS_F_ERROR flag */
		SESS_ERROR(sp, SOCKSv5_A_NOACCEPTABLE,
		    "SOCKSv5 no acceptable methods");
	}

	sp->step = STP_SOCKSv5_SENDAUTH;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_sendauth(struct sess *sp)
{
	struct socksv5_authresp ar;
	ssize_t r;

	/* XXX no authentication is implemented at this moment */
	assert(sizeof(struct socksv5_authresp) == 2);
	ar.ver = SOCKS_VER5;
	if ((sp->flags & SESS_F_ERROR) == 0)
		ar.method = SOCKSv5_A_NOAUTH;
	else
		ar.method = SOCKSv5_A_NOACCEPTABLE;

	/* XXX AFAIK the below operation must be atomic because it's size . */
	r = write(sp->sp_fd, (const void *)&ar,
	    sizeof(struct socksv5_authresp));
	if (r == -1 && errno == EAGAIN) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (r == -1)
		assert(0 == 1);
	assert(r > 0);
	assert(r == 2);

	if ((sp->flags & SESS_F_ERROR) != 0) {
		vca_close_session(sp, "no acceptable methods");
		VBE_CloseFd(sp, &sp->vc, 0);
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	}
	sp->step = STP_SOCKSv5_RECV_PREPARE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_recv_prepare(struct sess *sp)
{

	/* XXX why need to reinit this whole structure? */
	SCK_Init(sp->socks.stc, sp->ws, sp->sp_fd);
	sp->step = STP_SOCKSv5_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_recv(struct sess *sp)
{
	struct socks_conn *stc = sp->socks.stc;
	int i;

	i = SCK_Rx(stc, SOCKS_T_V5REQ);
	switch (i) {
	case -4:
		vca_close_session(sp, "corrupted format");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case -3:
	case 0:
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_READ,
		    CALLOUT_SECTOTICKS(params->recv_timeout));
		return (SESS_WAIT);
	case -2:
		vca_close_session(sp, "out of buffer");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	case -1:
		vca_close_session(sp, "read(2) error");
		sp->step = STP_DONE;
		return (SESS_CONTINUE);
	default:
		assert(i == 1);
		break;
	}

	sp->step = STP_SOCKSv5_REQ;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_req(struct sess *sp)
{
	struct socks_conn *stc = sp->socks.stc;
	const char *p;

	Tcheck(stc->rxbuf);
	assert(stc->pipeline.b == NULL);
	p = stc->rxbuf.b;

	assert(p[0] == SOCKS_VER5);
	assert(p[1] == SOCKSv5_C_CONNECT || p[1] == SOCKSv5_C_BIND ||
	    p[1] == SOCKSv5_C_UDP_ASSOCIATE);

	switch (p[1]) {
	case SOCKSv5_C_CONNECT:
		sp->step = STP_SOCKSv5_CONNECT;
		break;
	case SOCKSv5_C_BIND:
	case SOCKSv5_C_UDP_ASSOCIATE:
		/* FALLTHROUGH */
	default:
		assert(0 == 1);
	}
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_connect(struct sess *sp)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)&sp->socks.sockaddr;
	struct socks_conn *stc = sp->socks.stc;
	struct vbe_conn *vc;
	const unsigned short *q;
	const char *p;

	Tcheck(stc->rxbuf);
	p = stc->rxbuf.b;
	q = (const unsigned short *)p;

	assert(p[0] == SOCKS_VER5);
	assert(p[1] == SOCKSv5_C_CONNECT);
	assert(p[3] == SOCKSv5_I_IPV4);	/* only IPv4 supported */

	sp->socks.sockaddrlen = sizeof(struct sockaddr_in);
	bzero(in4, sp->socks.sockaddrlen);
	in4->sin_family = AF_INET;
	assert(sizeof(struct in_addr) == 4);
	bcopy(p + 4, &in4->sin_addr, sizeof(struct in_addr));
	in4->sin_port = q[4];

	/*
	 * XXX there are two points to call `vcl_socks_req' method.  Should
	 * be merged.
	 */
	VCL_socks_req_method(sp);
	switch (sp->handling) {
	case VCL_RET_DROP:
		assert(0 == 1);
		break;
	case VCL_RET_PIPE:
		break;
	default:
		WRONG("Unexpected return handling");
	}

	AZ(sp->vc);
	vc = sp->vc = VBE_GetConn(NULL, sp, VBE_TYPE_PIPE);
	if (vc == NULL) {
		assert(0 == 1);
		return (SESS_SLEEP);
	}
	vc->vc_fd = VBE_GetSocket(sp, vc);
	if (vc->vc_fd == -1)
		assert(0 == 1);

	sp->step = STP_SOCKSv5_CONNECT_DO;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_connect_do(struct sess *sp)
{
	struct vbe_conn *vc = sp->vc;
	double timeout;
	int error, i;
	char abuf1[TCP_ADDRBUFSIZE], abuf2[TCP_ADDRBUFSIZE];
	char pbuf1[TCP_PORTBUFSIZE], pbuf2[TCP_PORTBUFSIZE];

	i = connect(vc->vc_fd, &sp->socks.sockaddr, sp->socks.sockaddrlen);
	if (i == -1 && errno == EINPROGRESS) {
		FIND_TMO(connect_timeout, timeout, sp, vc->backend);
		SEPTUM_SESSEVENT(sp, vc->vc_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(timeout));
		return (SESS_WAIT);
	}
	if (i == -1 && errno != EISCONN) {
		error = SOCKSv5_S_SOCKS_FAIL;
		if (errno == ECONNREFUSED)
			error = SOCKSv5_S_CONNREFUSED;
		if (errno == ENETUNREACH)
			error = SOCKSv5_S_NUNREACHABLE;
		SESS_ERROR(sp, error, "SOCKSv5 connect error");
		sp->step = STP_SOCKSv5_ERROR;
		return (SESS_CONTINUE);
	}
	TCP_myname(vc->vc_fd, abuf1, sizeof(abuf1), pbuf1, sizeof(pbuf1));
	TCP_name(&sp->socks.sockaddr, sp->socks.sockaddrlen,
	    abuf2, sizeof(abuf2), pbuf2, sizeof(pbuf2));
	WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd, "%s %s %s -> %s %s",
	    vc->backend->vcl_name, abuf1, pbuf1, abuf2, pbuf2);

	sp->step = STP_SOCKSv5_RESP;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_resp(struct sess *sp)
{

	SEPTUM_SOFFSET(&sp->septum, 0);

	sp->step = STP_SOCKSv5_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_send(struct sess *sp)
{
	struct sockaddr sa;
	struct sockaddr_in *sap;
	struct vbe_conn *vc = sp->vc;
	socklen_t slen, tlen;
	int i, len;
	char buf[BUFSIZ], *p;

	/*
	 * build a response
	 */
	buf[0] = SOCKS_VER5;
	if ((sp->flags & SESS_F_ERROR) == 0)
		buf[1] = SOCKSv5_S_SUCCESS;
	else
		buf[1] = sp->err_code;
	buf[2] = 0x0;
	if ((sp->flags & SESS_F_ERROR) == 0) {
		/*
		 * XXX a system call!.  Called multiple times due to
		 * non-blocking!
		 */
		AZ(getsockname(vc->vc_fd, &sa, &slen));
		sap = (struct sockaddr_in *)&sa;
		buf[3] = SOCKSv5_I_IPV4;
		assert(sizeof(struct in_addr) == 4);
		memcpy(&buf[4], &sap->sin_addr, sizeof(struct in_addr));
		memcpy(&buf[8], &sap->sin_port, sizeof(unsigned short));
	} else
		bzero(&buf[4], sizeof(struct in_addr) + sizeof(unsigned short));
	tlen = 4 + 4 + 2;	/* XXX magic?? */

	/*
	 * Send it.
	 */
	p = (char *)buf;
	len = tlen - SEPTUM_GOFFSET(&sp->septum);
	i = write(sp->sp_fd, p + SEPTUM_GOFFSET(&sp->septum), len);
	if (i == -1 && errno == EAGAIN) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		sp->step = STP_SOCKS_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		SEPTUM_SOFFSET(&sp->septum, SEPTUM_GOFFSET(&sp->septum) + i);
		SEPTUM_SESSEVENT(sp, sp->sp_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	/* SESS_F_ERROR could be set if a timeout is happened.  */
	if ((sp->flags & SESS_F_ERROR) != 0) {
		sp->step = STP_SOCKS_END;
		return (SESS_CONTINUE);
	}
	sp->step = STP_SOCKS_PIPE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socksv5_error(struct sess *sp)
{

	sp->wrk->stats.socks_v5_error++;
	SEPTUM_SOFFSET(&sp->septum, 0);
	sp->step = STP_SOCKSv5_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe(struct sess *sp)
{
	struct pipe *dp;

	PIE_Init(sp);
	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	PIE_Wakeup(dp);

	sp->step = STP_SOCKS_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe_recv(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	/* Outputs TCP_INFO shmlog entry. */
	if (params->tcp_info_interval > 0)
		CNT_EmitTCPInfo(sp, sp->sp_fd, &sp->t_last, "c", sp->addr,
		    sp->port, 0);

	dp->buflen[0] = 0;
	sp->step = STP_SOCKS_PIPE_RECV_FROMCLIENT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe_recv_fromclient(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;
	int i;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	i = read(sp->sp_fd, dp->buf[0], dp->bufsize);
	if (i == -1 && errno == EAGAIN) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd,
		    SEPTUM_WANT_READ,
		    CALLOUT_SECTOTICKS(params->recv_timeout));
		return (SESS_WAIT);
	}
	if (i == -1 || i == 0) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_SOCKS_PIPE_END;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_SOCKS_PIPE_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	dp->buflen[0] = i;
	sp->step = STP_SOCKS_PIPE_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe_send(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	assert(dp->buflen[0] > 0);
	dp->bufoffset[0] = 0;
	sp->step = STP_SOCKS_PIPE_SEND_TOBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe_send_tobackend(struct sess *sp)
{
	struct pipe *dp;
	struct septum *st = &sp->septum;
	struct vbe_conn *vc;
	int i, len;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	len = dp->buflen[0] - dp->bufoffset[0];
	assert(len != 0);
	i = write(vc->vc_fd, dp->buf[0] + dp->bufoffset[0], len);
	if (i == -1 && errno == EAGAIN) {
		/* XXX a hack; see a comment on TUNNEL_PIPE_SEND_TOBACKEND */
		VSL_stats->pipe_callout_backend++;
		callout_reset(sp->wrk, &st->co, 0, cnt_WakeupCallout, sp);
		SES_Sleep(sp);
		return (SESS_SLEEP);
	}
	if (i == -1) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_SOCKS_PIPE_END;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_SOCKS_PIPE_END;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		dp->bufoffset[0] += i;
		return (SESS_CONTINUE);
	}
	sp->step = STP_SOCKS_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_pipe_end(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	if ((dp->flags & PIPE_F_STARTED) != 0) {
		if ((dp->flags & PIPE_F_PIPEDONE) == 0) {
			SES_Sleep(sp);
			return (SESS_SLEEP);
		}
		assert((dp->flags & PIPE_F_SESSDONE) != 0 &&
		    (dp->flags & PIPE_F_PIPEDONE) != 0);
	}

	sp->step = STP_SOCKS_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_socks_end(struct sess *sp)
{

	/* Outputs TCP_INFO shmlog entry. */
	if (params->tcp_info_interval > 0)
		CNT_EmitTCPInfo(sp, sp->sp_fd, &sp->t_last, "c", sp->addr,
		    sp->port, 1);

	vca_close_session(sp, "pipe");
	VBE_CloseFd(sp, &sp->vc, 0);
	sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * WAIT_BEGIN
 * WAIT_RECV
 * WAIT_END
 * Wait (briefly) until we have a full request in our htc.
 */

static enum sess_status
cnt_http_wait_begin(struct sess *sp)
{
	int i;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AZ(sp->obj);
	assert(sp->xid == 0);

	i = HTC_Complete(sp->htc);
	if (i == 0 && params->session_linger > 0) {
		sp->step = STP_HTTP_WAIT_RECV;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_WAIT_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_wait_recv(struct sess *sp)
{
	struct http_conn *htc = sp->htc;
	int i;

	i = HTC_RxNoCompleteCheck(htc);
	if (i == 0) {
		sp->step = STP_HTTP_WAIT_END;
		return (SESS_CONTINUE);
	}
	if (i == 1) {
		SEPTUM_SESSEVENT(sp, htc->htc_fd, htc->htc_want,
		    (htc->htc_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -2) {
		sp->step = STP_HTTP_WAIT_END;
		vca_close_session(sp, "overflow");
		return (SESS_CONTINUE);
	}
	vca_close_session(sp, "error");
	sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_wait_end(struct sess *sp)
{
	int i;

	i = HTC_Complete(sp->htc);
	if (i == 0) {
		WSL(sp->wrk, SLT_Debug, sp->sp_fd, "herding");
		sp->wrk->stats.sess_herd++;
		SES_Charge(sp);
		sp->wrk = NULL;
		/* sp->vcl isn't NULL if it grabbed at STP_FIRST */
		if (sp->vcl != NULL)
			VCL_Rel(&sp->vcl);
		if (sp->geoip != NULL)
			GEO_Rel(&sp->geoip);
		vca_return_session(sp);
		return (SESS_DONE);
	}
	assert(i == 1);
	sp->step = STP_HTTP_START;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * START
 * Handle a request, wherever it came from recv/restart.
 *
DOT start [shape=box,label="Dissect request"]
DOT start -> recv [style=bold,color=green,weight=4]
 */

static enum sess_status
cnt_http_start(struct sess *sp)
{
	int done;
	char *p;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AZ(sp->restarts);
	AZ(sp->obj);

	/* Update stats of various sorts */
	sp->wrk->stats.client_req++;
	sp->t_req = TIM_real();
	sp->wrk->lastused = sp->t_req;
	sp->acct_tmp.req++;

	/* Assign XID and log */
	sp->xid = ++xids;				/* XXX not locked */
	WSP(sp, SLT_ReqStart, "%s %s %u", sp->addr, sp->port,  sp->xid);

	/*
	 * Get VCL reference if it comes from STP_DONE.  Normally it grabs
	 * it at STP_FIRST.
	 */
	if (sp->vcl == NULL)
		VCL_Refresh(&sp->vcl);
	if (sp->geoip == NULL)
		GEO_Refresh(&sp->geoip);

	http_Setup(sp->http, sp->ws);
	done = http_DissectRequest(sp);

	/* If we could not even parse the request, just close */
	if (done < 0) {
		sp->step = STP_DONE;
		vca_close_session(sp, "junk");
		return (SESS_CONTINUE);
	}

	/* Catch request snapshot */
	sp->ws_req = WS_Snapshot(sp->ws);

	/* Catch original request, before modification */
	HTTP_Copy(sp->http0, sp->http);

	if (done != 0) {
		SESS_ERROR(sp, done, NULL);
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	}

	sp->doclose = http_DoConnection(sp->http);

	/* XXX: Handle TRACE & OPTIONS of Max-Forwards = 0 */

	/*
	 * Handle Expect headers
	 */
	if (http_GetHdr(sp->http, H_Expect, &p)) {
		if (strcasecmp(p, "100-continue")) {
			SESS_ERROR(sp, 417, NULL);
			sp->step = STP_HTTP_ERROR;
			return (SESS_CONTINUE);
		}
		SEPTUM_SOFFSET(&sp->septum, 0);
		sp->step = STP_HTTP_START_CONTINUE;
		return (SESS_CONTINUE);
	}

	sp->step = STP_HTTP_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_start_continue(struct sess *sp)
{
	ssize_t len, slen;
	int i;
	const char *msg = "HTTP/1.1 100 Continue\r\n\r\n";

	slen = strlen(msg);
	len = slen - SEPTUM_GOFFSET(&sp->septum);
	assert(len != 0);

	i = CFD_write(&sp->fds, msg + SEPTUM_GOFFSET(&sp->septum), len);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd, sp->sp_want,
		    (sp->sp_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i <= 0)
		goto skip;
	if (i != len) {
		SEPTUM_SOFFSET(&sp->septum,
		    SEPTUM_GOFFSET(&sp->septum) + i);
		return (SESS_CONTINUE);
	}
skip:
	/* XXX: When we do ESI includes, this is not removed
	 * XXX: because we use http0 as our basis.  Believed
	 * XXX: safe, but potentially confusing.
	 */
	http_Unset(sp->http, H_Expect);
	sp->step = STP_HTTP_RECV;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * RECV
 * We have a complete request, set everything up and start it.
 *
DOT subgraph xcluster_recv {
DOT	recv [
DOT		shape=record
DOT		label="vcl_recv()|req."
DOT	]
DOT }
DOT RESTART -> recv
DOT recv -> pipe [label="pipe",style=bold,color=orange]
DOT recv -> pass2 [label="pass",style=bold,color=red]
DOT recv -> err_recv [label="error"]
DOT err_recv [label="ERROR",shape=plaintext]
DOT recv -> hash [label="lookup",style=bold,color=green,weight=4]
 */

static enum sess_status
cnt_http_recv(struct sess *sp)
{
	unsigned recv_handling;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);
	AZ(sp->obj);
	assert((sp->flags & SESS_F_NEEDOBJREL) == 0);

	/* By default we use the first backend */
	AZ(sp->director);
	sp->director = sp->vcl->director[0];
	AN(sp->director);

	sp->flags &= ~SESS_F_PASS;
	sp->client_identity = NULL;

	http_CollectHdr(sp->http, H_Cache_Control);

	VCL_http_recv_method(sp);
	recv_handling = sp->handling;

	if (sp->restarts >= params->max_restarts) {
		if (sp->err_code == 0)
			sp->err_code = 503;
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	}

	SHA256_Init(&sp->wrkvar.sha256ctx);
	VCL_http_hash_method(sp);
	assert(sp->handling == VCL_RET_HASH);
	SHA256_Final(sp->digest, &sp->wrkvar.sha256ctx);

	if (!strcmp(sp->http->hd[HTTP_HDR_REQ].b, "HEAD"))
		sp->flags &= ~SESS_F_WANTBODY;
	else
		sp->flags |= SESS_F_WANTBODY;
	sp->flags &= ~SESS_F_SENDBODY;

	switch (recv_handling) {
	case VCL_RET_LOOKUP:
		/* XXX: discard req body, if any */
		sp->step = STP_HTTP_LOOKUP;
		return (SESS_CONTINUE);
	case VCL_RET_PIPE:
		sp->step = STP_HTTP_PIPE_BEGIN;
		return (SESS_CONTINUE);
	case VCL_RET_PASS:
		sp->step = STP_HTTP_PASS;
		return (SESS_CONTINUE);
	case VCL_RET_ERROR:
		/* XXX: discard req body, if any */
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	default:
		WRONG("Illegal action in vcl_recv{}");
	}
}

/*--------------------------------------------------------------------
 * LOOKUP
 * Hash things together and look object up in hash-table.
 *
 * LOOKUP consists of two substates so that we can reenter if we
 * encounter a busy object.
 *
DOT subgraph xcluster_lookup {
DOT	hash [
DOT		shape=record
DOT		label="vcl_hash()|req."
DOT	]
DOT	lookup [
DOT		shape=diamond
DOT		label="obj in cache ?\ncreate if not"
DOT	]
DOT	lookup2 [
DOT		shape=diamond
DOT		label="obj.pass ?"
DOT	]
DOT	hash -> lookup [label="hash",style=bold,color=green,weight=4]
DOT	lookup -> lookup2 [label="yes",style=bold,color=green,weight=4]
DOT }
DOT lookup2 -> hit [label="no", style=bold,color=green,weight=4]
DOT lookup2 -> pass [label="yes",style=bold,color=red]
DOT lookup -> miss [label="no",style=bold,color=blue,weight=2]
 */

static enum sess_status
cnt_http_lookup(struct sess *sp)
{
	struct objcore *oc;
	struct object *o;
	struct objhead *oh;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	oc = HSH_Lookup(sp, &oh);
	if (oc == NULL) {
		SES_Sleep(sp);
		return (SESS_SLEEP);
	}

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oh, OBJHEAD_MAGIC);

	/* If we inserted a new object it's a miss */
	if (oc->flags & OC_F_BUSY) {
		sp->wrk->stats.cache_miss++;

		AZ(oc->obj);
		sp->objhead = oh;
		sp->objcore = oc;
		sp->step = STP_HTTP_MISS;
		return (SESS_CONTINUE);
	}

	o = oc->obj;
	CHECK_OBJ_NOTNULL(o, OBJECT_MAGIC);
	sp->obj = o;

	if (oc->flags & OC_F_PASS) {
		sp->wrk->stats.cache_hitpass++;
		WSP(sp, SLT_HitPass, "%u", sp->obj->xid);
		HSH_Deref(sp->wrk, &sp->obj);
		sp->objcore = NULL;
		sp->objhead = NULL;
		sp->step = STP_HTTP_PASS;
		return (SESS_CONTINUE);
	}

	sp->wrk->stats.cache_hit++;
	WSP(sp, SLT_Hit, "%u", sp->obj->xid);
	sp->step = STP_HTTP_HIT;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * We have fetched the headers from the backend, ask the VCL code what
 * to do next, then head off in that direction.
 *
DOT subgraph xcluster_fetch {
DOT	fetch [
DOT		shape=ellipse
DOT		label="fetch from backend\n(find obj.ttl)"
DOT	]
DOT	vcl_fetch [
DOT		shape=record
DOT		label="vcl_fetch()|req.\nbereq.\nberesp."
DOT	]
DOT	fetch -> vcl_fetch [style=bold,color=blue,weight=2]
DOT	fetch_pass [
DOT		shape=ellipse
DOT		label="obj.pass=true"
DOT	]
DOT	vcl_fetch -> fetch_pass [label="pass",style=bold,color=red]
DOT }
DOT fetch_pass -> deliver [style=bold,color=red]
DOT vcl_fetch -> deliver [label="deliver",style=bold,color=blue,weight=2]
DOT vcl_fetch -> recv [label="restart"]
DOT vcl_fetch -> rstfetch [label="restart",color=purple]
DOT rstfetch [label="RESTART",shape=plaintext]
DOT fetch -> errfetch
DOT vcl_fetch -> errfetch [label="error"]
DOT errfetch [label="ERROR",shape=plaintext]
 */

static enum sess_status
cnt_http_fetch_begin(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	AN(sp->director);
	AZ(sp->vc);
	AZ(sp->obj);

	/* sp->wrkvar.http[0] is (still) bereq */
	sp->wrkvar.beresp = sp->wrkvar.http[1];
	http_Setup(sp->wrkvar.beresp, sp->ws);

	if (sp->objcore != NULL) {		/* pass has no objcore */
		CHECK_OBJ_NOTNULL(sp->objcore, OBJCORE_MAGIC);
		AN(sp->objhead);		/* details in hash_slinger.h */
		AN(sp->objcore->flags & OC_F_BUSY);
	}

	sp->step = STP_HTTP_FETCH_GETBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_getbackend(struct sess *sp)
{
	struct vbe_conn *vc;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->wrk, WORKER_MAGIC);

	AZ(sp->vc);
	vc = sp->vc = VBE_GetConn(NULL, sp, VBE_TYPE_FETCH);
	if (vc == NULL) {
		SESS_ERROR(sp, 503, "no backend connection");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}

	FET_Init(sp);

	if (vc->recycled) {
		sp->step = STP_HTTP_FETCH_PREPARE;
		return (SESS_CONTINUE);
	}

	vc->vc_fd = VBE_GetSocket(sp, vc);
	if (vc->vc_fd == -1) {
		if (vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "socket table overflow");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_FETCH_CONNECT;
	return (SESS_CONTINUE);
}

/* XXX almost dup with STP_HTTP_PIPE_CONNECT */
static enum sess_status
cnt_http_fetch_connect(struct sess *sp)
{
	struct vbe_conn *vc;
	double timeout;
	int i;
	char abuf1[TCP_ADDRBUFSIZE], abuf2[TCP_ADDRBUFSIZE];
	char pbuf1[TCP_PORTBUFSIZE], pbuf2[TCP_PORTBUFSIZE];

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	if (params->diag_bitmap & 0x00200000) {
		struct sockaddr *sa = (struct sockaddr *)&vc->sa;

		if (sa->sa_family == AF_INET) {
			struct sockaddr_in *sain = (struct sockaddr_in *)sa;
			char buf[BUFSIZ];

			WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd,
			    "Trying to %s:%d",
			    inet_ntop(sa->sa_family, &sain->sin_addr, buf,
				sizeof(buf)), ntohs(sain->sin_port));
		}
	}

	i = connect(vc->vc_fd, (struct sockaddr *)&vc->sa, vc->salen);
	if (i == -1 && errno == EINPROGRESS) {
		FIND_TMO(connect_timeout, timeout, sp, vc->backend);
		SEPTUM_SESSEVENT(sp, vc->vc_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(timeout));
		return (SESS_WAIT);
	}
	if (i == -1 && errno != EISCONN) {
		if (vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "connect error for FETCH");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	TCP_myname(vc->vc_fd, abuf1, sizeof(abuf1), pbuf1, sizeof(pbuf1));
	TCP_name((struct sockaddr *)&vc->sa, vc->salen, abuf2, sizeof(abuf2),
	    pbuf2, sizeof(pbuf2));
	WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd, "%s %s %s -> %s %s",
	    vc->backend->vcl_name, abuf1, pbuf1, abuf2, pbuf2);

	sp->step = STP_HTTP_FETCH_PREPARE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_retry(struct sess *sp)
{

	AN(sp->vc);
	VBE_CloseFd(sp, &sp->vc, 0);

	/* For special backend 0.0.0.0 that it needs to be reset again. */
	sp->flags &= ~SESS_F_INADDR_ANY;
	sp->flags &= ~SESS_F_BACKEND_HINT;

	/* XXX currently there's no limitations for retrying. */
	VSL_stats->backend_retry++;
	sp->step = STP_HTTP_FETCH_GETBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_prepare(struct sess *sp)
{
	struct http *hp = sp->wrkvar.bereq;
	struct vbe_conn *vc;
	char *b;

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	/*
	 * Now that we know our backend, we can set a default Host:
	 * header if one is necessary.  This cannot be done in the VCL
	 * because the backend may be chosen by a director.
	 */
	if (!http_GetHdr(hp, H_Host, &b))
		VBE_AddHostHeader(sp);
	WRW_Reserve(sp, &vc->vc_fd, &vc->vc_ssl);
	(void)http_Write(sp, hp, 0);	/* XXX: stats ? */

	/* Now deal with any message-body the request might have */
	sp->step = STP_HTTP_FETCH_REQ;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_req(struct sess *sp)
{
	unsigned long clen;
	char *ptr, *endp;

	if (http_GetHdr(sp->http, H_Transfer_Encoding, NULL)) {
		/* XXX: Handle chunked encoding. */
		WSL(sp->wrk, SLT_Debug, sp->sp_fd,
		    "Transfer-Encoding in request");
		WRW_Release(sp);
		VBE_CloseFd(sp, &sp->vc, 0);
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	if (http_GetHdr(sp->http, H_Content_Length, &ptr)) {
		/*
		 * Checks the content length of the request so if error or
		 * length 0 cases wouldn't be skipped.
		 */
		errno = 0;
		clen = strtoul(ptr, &endp, 10);
		if (clen == ULONG_MAX && errno == ERANGE)
			goto nobody;
		if (clen == 0)
			goto nobody;
		SEPTUM_SCL(&sp->septum, clen);
		sp->step = STP_HTTP_FETCH_REQ_BODY_BEGIN;
		return (SESS_CONTINUE);
	}
nobody:
	sp->step = STP_HTTP_FETCH_REQ_HDR_FLUSH;
	return (SESS_CONTINUE);
}

/* XXX dup with STP_HTTP_DELIVER_SEND */
static enum sess_status
cnt_http_fetch_req_hdr_flush(struct sess *sp)
{
	struct vbe_conn *vc;
	int i, want;

	i = WRW_Flush(sp, &want);
	if (i == -3)
		return (SESS_CONTINUE);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, *sp->wrkvar.wfd, want,
		    (want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
		WRW_Release(sp);
		if (vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "hdr write error");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_FETCH_RESP;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_req_body_begin(struct sess *sp)
{
#define	XXX_BUFLEN	8192

	/* Sets a revert point. */
	AZ(sp->ws_fet);
	sp->ws_fet = WS_Snapshot(sp->ws);
	SEPTUM_SBUF(&sp->septum, WS_Alloc(sp->ws, XXX_BUFLEN));
	SEPTUM_SBUFLEN(&sp->septum, XXX_BUFLEN);

	sp->step = STP_HTTP_FETCH_REQ_BODY_RECV;
	return (SESS_CONTINUE);
#undef	XXX_BUFLEN
}

static enum sess_status
cnt_http_fetch_req_body_recv(struct sess *sp)
{
	struct http_conn *htc = sp->htc;
	struct vbe_conn *vc;
	int rdcnt;

	assert(SEPTUM_GCL(&sp->septum) > 0);

	if (SEPTUM_GCL(&sp->septum) > SEPTUM_GBUFLEN(&sp->septum))
		rdcnt = SEPTUM_GBUFLEN(&sp->septum);
	else
		rdcnt = SEPTUM_GCL(&sp->septum);

	rdcnt = HTC_Read(htc, SEPTUM_GBUF(&sp->septum), rdcnt);
	if (rdcnt == -2) {
		SEPTUM_SESSEVENT(sp, htc->htc_fd, htc->htc_want,
		    (htc->htc_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (rdcnt == -1 || rdcnt == 0) {
		CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
		WRW_Release(sp);
		if (vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "read error");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	SEPTUM_SCL(&sp->septum, SEPTUM_GCL(&sp->septum) - rdcnt);
	if ((sp->flags & SESS_F_SENDBODY) == 0) {
		if (SEPTUM_GCL(&sp->septum) == 0) {
			sp->step = STP_HTTP_FETCH_REQ_BODY_SEND;
			return (SESS_CONTINUE);
		}
		/* NB: don't need to set it but for readability */
		sp->step = STP_HTTP_FETCH_REQ_BODY_RECV;
		return (SESS_CONTINUE);
	}
	WRW_Write(sp, SEPTUM_GBUF(&sp->septum), rdcnt);
	sp->step = STP_HTTP_FETCH_REQ_BODY_SEND;
	return (SESS_CONTINUE);
}

/* XXX dup with STP_HTTP_DELIVER_SEND */
static enum sess_status
cnt_http_fetch_req_body_send(struct sess *sp)
{
	struct vbe_conn *vc;
	int i, want;

	i = WRW_Flush(sp, &want);
	if (i == -3)
		return (SESS_CONTINUE);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, *sp->wrkvar.wfd, want,
		    (want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
		WRW_Release(sp);
		if (vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		VBE_CloseFd(sp, &sp->vc, 0);
		SESS_ERROR(sp, 503, "write error");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	if (SEPTUM_GCL(&sp->septum) > 0) {
		sp->step = STP_HTTP_FETCH_REQ_BODY_RECV;
		return (SESS_CONTINUE);
	}
	assert(SEPTUM_GCL(&sp->septum) == 0);
	sp->step = STP_HTTP_FETCH_REQ_BODY_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_req_body_end(struct sess *sp)
{

	WS_Reset(sp->ws, sp->ws_fet);
	sp->ws_fet = NULL;
	SEPTUM_SBUF(&sp->septum, NULL);
	SEPTUM_SBUFLEN(&sp->septum, 0);

	sp->step = STP_HTTP_FETCH_RESP;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_resp(struct sess *sp)
{
	struct vbe_conn *vc = sp->vc;
	struct worker *w = sp->wrk;

	WRW_Release(sp);
	/* Checkpoint the shmlog here */
	WSL_Flush(w, 0);
	/* XXX is this the right place? */
	VSL_stats->backend_req++;

	/* Receive response */
	HTC_Init(sp->wrkvar.htc, sp->ws, vc->vc_fd, vc->vc_ssl);
	sp->step = STP_HTTP_FETCH_RESP_RECV_FIRSTBYTE;
	return (SESS_CONTINUE);
}

/*
 * The diff between STP_HTTP_FETCH_RESP_RECV_FIRSTBYTE and
 * STP_HTTP_FETCH_RESP_RECV_NEXTBYTES is a timeout value.
 * All other parts would be same.
 */
static enum sess_status
cnt_http_fetch_resp_recv_firstbyte(struct sess *sp)
{
	struct http_conn *htc;
	struct vbe_conn *vc;
	int i;

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
	CAST_OBJ_NOTNULL(htc, sp->wrkvar.htc, HTTP_CONN_MAGIC);

	i = HTC_RxNoCompleteCheck(htc);
	if (i == 1) {
		SEPTUM_SESSEVENT(sp, htc->htc_fd, htc->htc_want,
		    CALLOUT_SECTOTICKS(vc->first_byte_timeout));
		return (SESS_WAIT);
	}
	if (i < 0) {
		WSP(sp, SLT_FetchError, "http first read error: %d %d (%s)",
		    i, errno, strerror(errno));
		if (i == -1 && vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		SESS_ERROR(sp, 503, "fetch firstbyte error");
		VBE_CloseFd(sp, &sp->vc, 0);
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	i = HTC_Complete(htc);
	if (i == 0) {
		sp->step = STP_HTTP_FETCH_RESP_RECV_NEXTBYTES;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_FETCH_RESP_HDRDISSECT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_resp_recv_nextbytes(struct sess *sp)
{
	struct http_conn *htc;
	struct vbe_conn *vc;
	int i;

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
	CAST_OBJ_NOTNULL(htc, sp->wrkvar.htc, HTTP_CONN_MAGIC);

	i = HTC_RxNoCompleteCheck(htc);
	if (i == 1) {
		SEPTUM_SESSEVENT(sp, htc->htc_fd, htc->htc_want,
		    CALLOUT_SECTOTICKS(vc->between_bytes_timeout));
		return (SESS_WAIT);
	}
	if (i < 0) {
		WSP(sp, SLT_FetchError, "http read error: %d %d (%s)",
		    i, errno, strerror(errno));
		if (i == -1 && vc->recycled) {
			sp->step = STP_HTTP_FETCH_RETRY;
			return (SESS_CONTINUE);
		}
		SESS_ERROR(sp, 503, "fetch nextbyte error");
		VBE_CloseFd(sp, &sp->vc, 0);
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}
	i = HTC_Complete(htc);
	if (i == 0) {
		/* NB: don't need to set but for readability */
		sp->step = STP_HTTP_FETCH_RESP_RECV_NEXTBYTES;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_FETCH_RESP_HDRDISSECT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_resp_hdrdissect(struct sess *sp)
{
	struct fetch *fp;
	struct http *hp, *hp2;
	struct vsb *vary = NULL;
	unsigned l, nhttp;
	int nort = 0, varyl = 0;
	char *b;

	hp = sp->wrkvar.beresp;
	if (http_DissectResponse(sp->wrk, sp->wrkvar.htc, hp)) {
		WSP(sp, SLT_FetchError, "http format error");
		VBE_CloseFd(sp, &sp->vc, 0);
		/* XXX: other cleanup ? */
		SESS_ERROR(sp, 503, "http format error");
		sp->step = STP_HTTP_FETCH_ERROR;
		return (SESS_CONTINUE);
	}

	/*
	 * These two headers can be spread over multiple actual headers
	 * and we rely on their content outside of VCL, so collect them
	 * into one line here.
	 */
	http_CollectHdr(sp->wrkvar.beresp, H_Cache_Control);
	http_CollectHdr(sp->wrkvar.beresp, H_Vary);

	/*
	 * Save a copy before it might get mangled in VCL.  When it comes to
	 * dealing with the body, we want to see the unadultered headers.
	 */
	sp->wrkvar.beresp1 = sp->wrkvar.http[2];
	*sp->wrkvar.beresp1 = *sp->wrkvar.beresp;

	sp->err_code = http_GetStatus(sp->wrkvar.beresp);

	/*
	 * Initial cacheability determination per [RFC2616, 13.4]
	 * We do not support ranges yet, so 206 is out.
	 */
	switch (sp->err_code) {
	case 200: /* OK */
	case 203: /* Non-Authoritative Information */
	case 300: /* Multiple Choices */
	case 301: /* Moved Permanently */
	case 302: /* Moved Temporarily */
	case 410: /* Gone */
	case 404: /* Not Found */
		sp->flags |= SESS_F_CACHEABLE;
		break;
	default:
		sp->flags &= ~SESS_F_CACHEABLE;
		break;
	}

	sp->wrkvar.entered = TIM_real();
	sp->wrkvar.age = 0;
	sp->wrkvar.ttl = RFC2616_Ttl(sp);
	sp->wrkvar.grace = NAN;
	sp->wrkvar.body_status = RFC2616_Body(sp);

	VCL_http_fetch_method(sp);

	if (sp->objcore == NULL) {
		/* This is a pass from vcl_recv */
		AZ(sp->objhead);
		sp->flags &= ~SESS_F_CACHEABLE;
	} else if ((sp->flags & SESS_F_CACHEABLE) == 0) {
		if (sp->objhead != NULL)
			HSH_DerefObjCore(sp);
	}

	/*
	 * At this point we are either committed to flesh out the busy
	 * object we have in the hash or we have let go of it, if we ever
	 * had one.
	 */

	if ((sp->flags & SESS_F_CACHEABLE) != 0) {
		CHECK_OBJ_NOTNULL(sp->objhead, OBJHEAD_MAGIC);
		CHECK_OBJ_NOTNULL(sp->objcore, OBJCORE_MAGIC);
		vary = VRY_Create(sp, sp->wrkvar.beresp);
		if (vary != NULL) {
			varyl = vsb_len(vary);
			assert(varyl > 0);
		}
	} else {
		AZ(sp->objhead);
		AZ(sp->objcore);
	}

	l = http_EstimateWS(sp->wrkvar.beresp,
	    (sp->flags & SESS_F_PASS) ? HTTPH_A_PASS : HTTPH_A_INS, &nhttp);

	if (vary != NULL)
		l += varyl;

	/* Space for producing a Content-Length: header */
	l += 30;

	/*
	 * AFTER THIS MOMENT we couldn't jump to STP_HTTP_FETCH_ERROR step
	 * because we'd allocate sp->obj at the below and it'd use HSH_Drop if
	 * the backend was failed.
	 */
	sp->flags |= SESS_F_NEEDOBJREL;

	/*
	 * XXX: If we have a Length: header, we should allocate the body
	 * XXX: also.
	 */

	sp->obj = STV_NewObject(sp, l, sp->wrkvar.ttl, nhttp);
	assert(sp->obj->flags == 0);

	if (sp->objhead != NULL) {
		CHECK_OBJ_NOTNULL(sp->objhead, OBJHEAD_MAGIC);
		CHECK_OBJ_NOTNULL(sp->objcore, OBJCORE_MAGIC);
		sp->objcore->obj = sp->obj;
		sp->obj->objcore = sp->objcore;
		sp->objcore->objhead = sp->objhead;
		sp->objhead = NULL;	/* refcnt follows pointer. */
		sp->objcore = NULL;	/* refcnt follows pointer. */
		BAN_NewObj(sp->obj);
	}

	if (vary != NULL) {
		sp->obj->vary =
		    (void *)WS_Alloc(sp->obj->http->ws, varyl);
		AN(sp->obj->vary);
		memcpy(sp->obj->vary, vsb_data(vary), varyl);
		vsb_delete(vary);
		vary = NULL;
	}

	sp->obj->xid = sp->xid;
	sp->obj->response = sp->err_code;
	if (sp->flags & SESS_F_CACHEABLE)
		sp->obj->flags |= OBJECT_F_CACHEABLE;
	else
		sp->obj->flags &= ~OBJECT_F_CACHEABLE;
	sp->obj->ttl = sp->wrkvar.ttl;
	sp->obj->grace = sp->wrkvar.grace;
	if (sp->obj->ttl == 0. && sp->obj->grace == 0.)
		sp->obj->flags &= ~OBJECT_F_CACHEABLE;
	sp->obj->age = sp->wrkvar.age;
	sp->obj->entered = sp->wrkvar.entered;
	WS_Assert(sp->obj->ws_o);

	/* Filter into object */
	hp2 = sp->obj->http;

	hp2->logtag = HTTP_Obj;
	http_CopyResp(hp2, hp);
	http_FilterFields(sp->wrk, sp->sp_fd, hp2, hp,
	    (sp->flags & SESS_F_PASS) ? HTTPH_A_PASS : HTTPH_A_INS);
	http_CopyHome(sp->wrk, sp->sp_fd, hp2);

	if (http_GetHdr(hp, H_Last_Modified, &b))
		sp->obj->last_modified = TIM_parse(b);
	else
		sp->obj->last_modified = sp->wrkvar.entered;

	/* We use the unmodified headers */
	AN(sp->director);
	if (sp->obj->objcore != NULL)	   /* pass has no objcore */
		AN(ObjIsBusy(sp->obj));

	/*
	 * Determine if we have a body or not
	 * XXX: Missing:  RFC2616 sec. 4.4 in re 1xx, 204 & 304 responses
	 */

	switch (sp->wrkvar.body_status) {
	case BS_NONE:
		sp->flags &= ~(SESS_F_CLOSE | SESS_F_MKLEN);
		break;
	case BS_ZERO:
		sp->flags &= ~SESS_F_CLOSE;
		sp->flags |= SESS_F_MKLEN;
		break;
	case BS_ERROR:
		sp->flags |= SESS_F_CLOSE;
		sp->flags &= ~SESS_F_MKLEN;
		sp->flags &= ~SESS_F_NEEDOBJREL;
		VBE_CloseFd(sp, &sp->vc, 0);
		HSH_Drop(sp);
		AZ(sp->obj);
		sp->wrkvar.bereq = NULL;
		sp->wrkvar.beresp = NULL;
		sp->wrkvar.beresp1 = NULL;
		SESS_ERROR(sp, 503, NULL);
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	case BS_LENGTH:
		CAST_FETCH_NOTNULL(fp, sp->vc, FETCH_MAGIC);
		AN(http_GetHdr(hp, H_Content_Length, &b));
		SEPTUM_SCL(&fp->septum, strtoumax(b, NULL, 0));
		if (SEPTUM_GCL(&fp->septum) == 0)
			nort = 1; /* No realtime transfer if length == 0 */
		/* FALLTHROUGH */
	case BS_CHUNKED:
	case BS_EOF:
		/* it'd be handled later for realtime transfer.  */

		if (sp->wrkvar.body_status == BS_EOF)
			sp->obj->flags |= OBJECT_F_EOF;
		break;
	default:
		sp->flags &= ~(SESS_F_CLOSE | SESS_F_MKLEN);
		INCOMPL();
	}

	WSL(sp->wrk, SLT_Fetch_Body, sp->vc->vc_fd, "%u %u %u",
	    sp->wrkvar.body_status,
	    (sp->flags & SESS_F_CLOSE) != 0,
	    (sp->flags & SESS_F_MKLEN) != 0);

	if (http_HdrIs(hp, H_Connection, "close"))
		sp->flags |= SESS_F_CLOSE;
	if ((sp->flags & SESS_F_CLOSE) == 0 && hp->protover < 1.1 &&
	    !http_HdrIs(hp, H_Connection, "keep-alive"))
		sp->flags |= SESS_F_CLOSE;

	if ((sp->flags & SESS_F_MKLEN) != 0) {
		http_Unset(sp->obj->http, H_Content_Length);
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->obj->http,
		    "Content-Length: %zd", sp->obj->len);
	}

	if ((sp->flags & SESS_F_CACHEABLE) != 0)
		HSH_Object(sp);

	AZ(sp->wrkvar.wfd);
	AN(sp->director);

	switch (sp->handling) {
	case VCL_RET_RESTART:
		/* if the backend is recyclable then do it */
		VBE_CloseFd(sp, &sp->vc,
		    (nort == 1 && (sp->flags & SESS_F_CLOSE) == 0) ? 1 : 0);
		HSH_Drop(sp);
		sp->flags &= ~SESS_F_NEEDOBJREL;
		sp->director = NULL;
		sp->restarts++;
		sp->wrkvar.bereq = NULL;
		sp->wrkvar.beresp = NULL;
		sp->wrkvar.beresp1 = NULL;
		sp->step = STP_HTTP_RECV;
		return (SESS_CONTINUE);
	case VCL_RET_PASS:
		if (sp->obj->objcore != NULL)
			sp->obj->objcore->flags |= OC_F_PASS;
		if (sp->obj->ttl - sp->t_req < params->default_ttl)
			sp->obj->ttl = sp->t_req + params->default_ttl;
		break;
	case VCL_RET_DELIVER:
		break;
	case VCL_RET_ERROR:
		VBE_CloseFd(sp, &sp->vc, 0);
		HSH_Drop(sp);
		sp->flags &= ~SESS_F_NEEDOBJREL;
		sp->wrkvar.bereq = NULL;
		sp->wrkvar.beresp = NULL;
		sp->wrkvar.beresp1 = NULL;
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	default:
		WRONG("Illegal action in vcl_fetch{}");
	}

	if ((sp->flags & SESS_F_CACHEABLE) != 0) {
		EXP_Insert(sp->obj);
		AN(sp->obj->ban);
		HSH_Unbusy(sp);
	}

	/*
	 * If the body status is one of BS_LENGTH, BS_CHUNKED or BS_EOF, the
	 * object status isn't determined so the FETCH state machine definitely
	 * set it whether it's available for caching or not.
	 *
	 * Currentl handling the family of BS_LENGTH, BS_CHUNKED and BS_EOF is
	 * totally independant with handling BS_NONE, BS_ZERO and etc so it's
	 * needed to be careful.  (e.g. closing the backend connection or
	 * dropping or inserting the object.)
	 */
	switch (sp->wrkvar.body_status) {
	case BS_LENGTH:
		if (nort == 1)
			break;
		/* FALLTHROUGH */
	case BS_CHUNKED:
	case BS_EOF:
		sp->step = STP_HTTP_FETCH_RESP_BODY;
		return (SESS_CONTINUE);
	default:
		break;
	}

	VBE_CloseFd(sp, &sp->vc, (sp->flags & SESS_F_CLOSE) == 0);

	/* Sets the object if the object don't have any body. */

	sp->obj->flags |= OBJECT_F_DONE;
	sp->obj->flags |= OBJECT_F_CACHEABLE;
	sp->obj->flags |= OBJECT_F_ZEROLEN;

	sp->step = STP_HTTP_DELIVER_BEGIN;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_resp_body(struct sess *sp)
{
	struct fetch *fp;

	CAST_FETCH_NOTNULL(fp, sp->vc, FETCH_MAGIC);

	/* As first time, wake up the fetch state machine.  */
	FET_Wakeup(fp);

	sp->step = STP_HTTP_DELIVER_BEGIN;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_fetch_error(struct sess *sp)
{

	AZ(sp->vc);
	assert(sp->err_code >= 100 && sp->err_code <= 999);

	VSL_stats->backend_fail++;
	WSP(sp, SLT_FetchError, "backend write error: %d (%s): %s",
	    errno, strerror(errno), sp->err_reason);

	sp->flags |= SESS_F_CLOSE;	/* Closes the backend conn */
	sp->flags |= SESS_F_ERROR;

	if (sp->objcore != NULL) {
		CHECK_OBJ_NOTNULL(sp->objhead, OBJHEAD_MAGIC);
		CHECK_OBJ_NOTNULL(sp->objcore, OBJCORE_MAGIC);
		HSH_DerefObjCore(sp);
		AZ(sp->objhead);
		AZ(sp->objcore);
	}
	AZ(sp->obj);
	sp->wrkvar.bereq = NULL;
	sp->wrkvar.beresp = NULL;
	sp->wrkvar.beresp1 = NULL;
	sp->step = STP_HTTP_ERROR;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * HIT
 * We had a cache hit.  Ask VCL, then march off as instructed.
 *
DOT subgraph xcluster_hit {
DOT	hit [
DOT		shape=record
DOT		label="vcl_hit()|req.\nobj."
DOT	]
DOT }
DOT hit -> err_hit [label="error"]
DOT err_hit [label="ERROR",shape=plaintext]
DOT hit -> rst_hit [label="restart",color=purple]
DOT rst_hit [label="RESTART",shape=plaintext]
DOT hit -> pass [label=pass,style=bold,color=red]
DOT hit -> deliver [label="deliver",style=bold,color=green,weight=4]
 */

static enum sess_status
cnt_http_hit(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->obj, OBJECT_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	assert(!(sp->obj->objcore->flags & OC_F_PASS));

	VCL_http_hit_method(sp);

	if (sp->handling == VCL_RET_DELIVER) {
		/*
		 * Dispose of any body part of the request then deliver the
		 * content.
		 */
		sp->step = STP_HTTP_HIT_REQ_BEGIN;
		return (SESS_CONTINUE);
	}

	/* Drop our object, we won't need it */
	HSH_Deref(sp->wrk, &sp->obj);
	sp->objcore = NULL;
	AZ(sp->objhead);

	switch(sp->handling) {
	case VCL_RET_PASS:
		sp->step = STP_HTTP_PASS;
		return (SESS_CONTINUE);
	case VCL_RET_ERROR:
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	case VCL_RET_RESTART:
		sp->director = NULL;
		sp->restarts++;
		sp->step = STP_HTTP_RECV;
		return (SESS_CONTINUE);
	default:
		WRONG("Illegal action in vcl_hit{}");
	}
}

static enum sess_status
cnt_http_hit_req_begin(struct sess *sp)
{
	char *ptr, *endp;

	if (http_GetHdr(sp->http, H_Transfer_Encoding, NULL)) {
		/* XXX: Handle chunked encoding. */
		WSL(sp->wrk, SLT_Debug, sp->sp_fd,
		    "Transfer-Encoding in request");
		sp->step = STP_HTTP_HIT_REQ_END;
		return (SESS_CONTINUE);
	}
	if (http_GetHdr(sp->http, H_Content_Length, &ptr)) {
		SEPTUM_SCL(&sp->septum, strtoul(ptr, &endp, 10));
		sp->step = STP_HTTP_HIT_REQ_RECV;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_HIT_REQ_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_hit_req_recv(struct sess *sp)
{
	struct http_conn *htc = sp->htc;
	struct vbe_conn *vc;
	int rdcnt;
	char buf[BUFSIZ];

	assert(SEPTUM_GCL(&sp->septum) > 0);
	if (SEPTUM_GCL(&sp->septum) > BUFSIZ)
		rdcnt = BUFSIZ;
	else
		rdcnt = SEPTUM_GCL(&sp->septum);
	rdcnt = HTC_Read(htc, buf, rdcnt);
	if (rdcnt == -2) {
		SEPTUM_SESSEVENT(sp, htc->htc_fd, htc->htc_want,
		    (htc->htc_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (rdcnt == -1 || rdcnt == 0) {
		CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);
		sp->step = STP_HTTP_HIT_REQ_END;
		return (SESS_CONTINUE);
	}
	SEPTUM_SCL(&sp->septum, SEPTUM_GCL(&sp->septum) - rdcnt);
	assert(SEPTUM_GCL(&sp->septum) >= 0);
	if (SEPTUM_GCL(&sp->septum) > 0) {
		/* NB: don't need to set it but for readability */
		sp->step = STP_HTTP_HIT_REQ_RECV;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_HIT_REQ_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_hit_req_end(struct sess *sp)
{

	sp->wrkvar.bereq = NULL;
	sp->step = STP_HTTP_DELIVER_BEGIN;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * We had a miss, ask VCL, proceed as instructed
 *
DOT subgraph xcluster_miss {
DOT	miss [
DOT		shape=ellipse
DOT		label="filter req.->bereq."
DOT	]
DOT	vcl_miss [
DOT		shape=record
DOT		label="vcl_miss()|req.\nbereq."
DOT	]
DOT	miss -> vcl_miss [style=bold,color=blue,weight=2]
DOT }
DOT vcl_miss -> rst_miss [label="restart",color=purple]
DOT rst_miss [label="RESTART",shape=plaintext]
DOT vcl_miss -> err_miss [label="error"]
DOT err_miss [label="ERROR",shape=plaintext]
DOT vcl_miss -> fetch [label="fetch",style=bold,color=blue,weight=2]
DOT vcl_miss -> pass [label="pass",style=bold,color=red]
DOT
 */

static enum sess_status
cnt_http_miss(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	AZ(sp->obj);
	AN(sp->objcore);
	AN(sp->objhead);
	sp->wrkvar.bereq = sp->wrkvar.http[0];
	http_Setup(sp->wrkvar.bereq, sp->ws);
	http_FilterHeader(sp, HTTPH_R_FETCH);
	http_ForceGet(sp->wrkvar.bereq);
	sp->wrk->connect_timeout = 0;
	sp->wrk->first_byte_timeout = 0;
	sp->wrk->between_bytes_timeout = 0;
	VCL_http_miss_method(sp);
	switch(sp->handling) {
	case VCL_RET_ERROR:
		HSH_DerefObjCore(sp);
		sp->wrkvar.bereq = NULL;
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	case VCL_RET_PASS:
		HSH_DerefObjCore(sp);
		sp->step = STP_HTTP_PASS;
		return (SESS_CONTINUE);
	case VCL_RET_FETCH:
		sp->step = STP_HTTP_FETCH_BEGIN;
		return (SESS_CONTINUE);
	case VCL_RET_RESTART:
		HSH_DerefObjCore(sp);
		INCOMPL();
	default:
		WRONG("Illegal action in vcl_miss{}");
	}
}

/*--------------------------------------------------------------------
 * Start pass processing by getting headers from backend, then
 * continue in passbody.
 *
DOT subgraph xcluster_pass {
DOT	pass [
DOT		shape=ellipse
DOT		label="deref obj."
DOT	]
DOT	pass2 [
DOT		shape=ellipse
DOT		label="filter req.->bereq."
DOT	]
DOT	vcl_pass [
DOT		shape=record
DOT		label="vcl_pass()|req.\nbereq."
DOT	]
DOT	pass_do [
DOT		shape=ellipse
DOT		label="create anon object\n"
DOT	]
DOT	pass -> pass2 [style=bold, color=red]
DOT	pass2 -> vcl_pass [style=bold, color=red]
DOT	vcl_pass -> pass_do [label="pass"] [style=bold, color=red]
DOT }
DOT pass_do -> fetch [style=bold, color=red]
DOT vcl_pass -> rst_pass [label="restart",color=purple]
DOT rst_pass [label="RESTART",shape=plaintext]
DOT vcl_pass -> err_pass [label="error"]
DOT err_pass [label="ERROR",shape=plaintext]
 */

static enum sess_status
cnt_http_pass(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);
	AZ(sp->obj);

	sp->wrkvar.bereq = sp->wrkvar.http[0];
	http_Setup(sp->wrkvar.bereq, sp->ws);
	http_FilterHeader(sp, HTTPH_R_PASS);

	sp->wrk->connect_timeout = 0;
	sp->wrk->first_byte_timeout = 0;
	sp->wrk->between_bytes_timeout = 0;
	VCL_http_pass_method(sp);
	if (sp->handling == VCL_RET_ERROR) {
		sp->flags |= SESS_F_ERROR;
		sp->step = STP_HTTP_ERROR;
		return (SESS_CONTINUE);
	}
	assert(sp->handling == VCL_RET_PASS);
	sp->acct_tmp.pass++;
	sp->flags |= (SESS_F_SENDBODY | SESS_F_PASS);
	sp->step = STP_HTTP_FETCH_BEGIN;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * Ship the request header to the backend unchanged, then pipe
 * until one of the ends close the connection.
 *
DOT subgraph xcluster_pipe {
DOT	pipe [
DOT		shape=ellipse
DOT		label="Filter req.->bereq."
DOT	]
DOT	vcl_pipe [
DOT		shape=record
DOT		label="vcl_pipe()|req.\nbereq\."
DOT	]
DOT	pipe_do [
DOT		shape=ellipse
DOT		label="send bereq.\npipe until close"
DOT	]
DOT	vcl_pipe -> pipe_do [label="pipe",style=bold,color=orange]
DOT	pipe -> vcl_pipe [style=bold,color=orange]
DOT }
DOT pipe_do -> DONE [style=bold,color=orange]
DOT vcl_pipe -> err_pipe [label="error"]
DOT err_pipe [label="ERROR",shape=plaintext]
 */

static enum sess_status
cnt_http_pipe_begin(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	sp->acct_tmp.pipe++;
	sp->wrkvar.bereq = sp->wrkvar.http[0];
	http_Setup(sp->wrkvar.bereq, sp->ws);
	http_FilterHeader(sp, HTTPH_R_PIPE);

	VCL_http_pipe_method(sp);

	if (sp->handling == VCL_RET_ERROR)
		INCOMPL();
	assert(sp->handling == VCL_RET_PIPE);

	sp->step = STP_HTTP_PIPE_GETBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_getbackend(struct sess *sp)
{
	struct vbe_conn *vc;

	AZ(sp->vc);
	vc = sp->vc = VBE_GetConn(NULL, sp, VBE_TYPE_PIPE);
	if (vc == NULL) {
		assert(0 == 1);
		return (SESS_SLEEP);
	}
	vc->vc_fd = VBE_GetSocket(sp, vc);
	if (vc->vc_fd == -1) {
		VSL_stats->backend_fail++;
		SESS_ERROR(sp, 503, "socket table overflow");
		sp->step = STP_HTTP_PIPE_END;
		return (SESS_CONTINUE);
	}

	sp->step = STP_HTTP_PIPE_CONNECT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_connect(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;
	double timeout;
	int i;
	char abuf1[TCP_ADDRBUFSIZE], abuf2[TCP_ADDRBUFSIZE];
	char pbuf1[TCP_PORTBUFSIZE], pbuf2[TCP_PORTBUFSIZE];

	CAST_OBJ_NOTNULL(vc, sp->vc, VBE_CONN_MAGIC);

	i = connect(vc->vc_fd, (struct sockaddr *)&vc->sa, vc->salen);
	if (i == -1 && errno == EINPROGRESS) {
		FIND_TMO(connect_timeout, timeout, sp, vc->backend);
		SEPTUM_SESSEVENT(sp, vc->vc_fd, SEPTUM_WANT_WRITE,
		    CALLOUT_SECTOTICKS(timeout));
		return (SESS_WAIT);
	}
	if (i == -1 && errno != EISCONN) {
		SESS_ERROR(sp, 503, "connect error for PIPE");
		sp->step = STP_HTTP_PIPE_END;
		return (SESS_CONTINUE);
	}
	TCP_myname(vc->vc_fd, abuf1, sizeof(abuf1), pbuf1, sizeof(pbuf1));
	TCP_name((struct sockaddr *)&vc->sa, vc->salen, abuf2, sizeof(abuf2),
	    pbuf2, sizeof(pbuf2));
	WSL(sp->wrk, SLT_BackendOpen, vc->vc_fd, "%s %s %s -> %s %s",
	    vc->backend->vcl_name, abuf1, pbuf1, abuf2, pbuf2);

	PIE_Init(sp);
	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	PIE_Wakeup(dp);

	/*
	 * If SESS_F_NOFLUSHREQ is set, don't flush the request header to the
	 * backend.
	 */
	if ((sp->flags & SESS_F_NOFLUSHREQ) != 0) {
		sp->step = STP_HTTP_PIPE_RECV;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_PIPE_HDREMIT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_hdremit(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	/* prepare variables before going into the emit */
	WRW_Reserve(sp, &vc->vc_fd, &vc->vc_ssl);

	sp->acct_req.hdrbytes += http_Write(sp, sp->wrkvar.bereq, 0);
	if (sp->htc->pipeline.b != NULL)
		sp->acct_req.bodybytes +=
		    WRW_Write(sp, sp->htc->pipeline.b, Tlen(sp->htc->pipeline));

	sp->step = STP_HTTP_PIPE_HDRFLUSH;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_hdrflush(struct sess *sp)
{
	int i, want;

	i = WRW_Flush(sp, &want);
	if (i == -3)
		return (SESS_CONTINUE);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, *sp->wrkvar.wfd, want,
		    (want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	WRW_Release(sp);
	if (i == -1) {
		SESS_ERROR(sp, 503, "pipe hdrflush error");
		sp->step = STP_HTTP_PIPE_CLOSEWAIT;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_recv(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	dp->buflen[0] = 0;
	sp->step = STP_HTTP_PIPE_RECV_FROMCLIENT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_recv_fromclient(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;
	int i;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	i = CFD_read(&sp->fds, dp->buf[0], dp->bufsize);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, sp->sp_fd, sp->sp_want,
		    (sp->sp_want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i <= 0) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_HTTP_PIPE_CLOSEWAIT;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_HTTP_PIPE_CLOSEWAIT;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	dp->buflen[0] = i;
	sp->step = STP_HTTP_PIPE_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_send(struct sess *sp)
{
	struct pipe *dp;
	struct vbe_conn *vc;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	assert(dp->buflen[0] > 0);
	dp->bufoffset[0] = 0;
	sp->step = STP_HTTP_PIPE_SEND_TOBACKEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_send_tobackend(struct sess *sp)
{
	struct pipe *dp;
	struct septum *st = &sp->septum;
	struct vbe_conn *vc;
	int i, len;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);
	CAST_OBJ_NOTNULL(vc, &dp->vc, VBE_CONN_MAGIC);

	len = dp->buflen[0] - dp->bufoffset[0];
	assert(len != 0);

	i = CFD_write(&vc->fds, dp->buf[0] + dp->bufoffset[0], len);
	if (i == -2) {
		/* XXX a hack; see a comment on TUNNEL_PIPE_SEND_TOBACKEND */
		VSL_stats->pipe_callout_backend++;
		callout_reset(sp->wrk, &st->co, 0, cnt_WakeupCallout, sp);
		SES_Sleep(sp);
		return (SESS_SLEEP);
	}
	if (i <= 0) {
		dp->flags |= PIPE_F_SESSDONE;
		if ((dp->flags & PIPE_F_PIPEDONE) != 0) {
			sp->step = STP_HTTP_PIPE_CLOSEWAIT;
			return (SESS_CONTINUE);
		}
		(void)shutdown(sp->sp_fd, SHUT_RD);	/* XXX */
		(void)shutdown(vc->vc_fd, SHUT_WR);	/* XXX */
		sp->step = STP_HTTP_PIPE_CLOSEWAIT;
		return (SESS_CONTINUE);
	}
	assert(i > 0);
	if (i != len) {
		dp->bufoffset[0] += i;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_PIPE_RECV;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_closewait(struct sess *sp)
{
	struct pipe *dp;

	CAST_PIPE_NOTNULL(dp, sp->vc, PIPE_MAGIC);

	if ((dp->flags & PIPE_F_STARTED) != 0) {
		if ((dp->flags & PIPE_F_PIPEDONE) == 0) {
			SES_Sleep(sp);
			return (SESS_SLEEP);
		}
		assert((dp->flags & PIPE_F_SESSDONE) != 0 &&
		    (dp->flags & PIPE_F_PIPEDONE) != 0);
	}

	sp->step = STP_HTTP_PIPE_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_pipe_end(struct sess *sp)
{

	vca_close_session(sp, "pipe");
	VBE_CloseFd(sp, &sp->vc, 0);

	AZ(sp->wrkvar.wfd);
	sp->wrkvar.bereq = NULL;
	if ((sp->flags & SESS_F_ERROR) != 0) {
		AN(sp->err_code);
		AN(sp->err_reason);
		assert((sp->flags & SESS_F_ERROR) != 0);
		sp->step = STP_HTTP_ERROR;
	} else
		sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * We have a refcounted object on the session, now deliver it.
 *
DOT subgraph xcluster_deliver {
DOT	deliver [
DOT		shape=ellipse
DOT		label="Filter obj.->resp."
DOT	]
DOT	vcl_deliver [
DOT		shape=record
DOT		label="vcl_deliver()|resp."
DOT	]
DOT	deliver2 [
DOT		shape=ellipse
DOT		label="Send resp + body"
DOT	]
DOT	deliver -> vcl_deliver [style=bold,color=green,weight=4]
DOT	vcl_deliver -> deliver2 [style=bold,color=green,weight=4,label=deliver]
DOT     vcl_deliver -> errdeliver [label="error"]
DOT     errdeliver [label="ERROR",shape=plaintext]
DOT     vcl_deliver -> rstdeliver [label="restart",color=purple]
DOT     rstdeliver [label="RESTART",shape=plaintext]
DOT }
DOT deliver2 -> DONE [style=bold,color=green,weight=4]
 *
 * XXX: Ideally we should make the req. available in vcl_deliver() but for
 * XXX: reasons of economy we don't, since that allows us to reuse the space
 * XXX: in sp->req for the response.
 *
 * XXX: Rather than allocate two http's and workspaces for all sessions to
 * XXX: address this deficiency, we could make the VCL compiler set a flag
 * XXX: if req. is used in vcl_deliver().  When the flag is set we would
 * XXX: take the memory overhead, for instance by borrowing a struct bereq
 * XXX: or similar.
 *
 * XXX: For now, wait until somebody asks for it.
 */

static enum sess_status
cnt_http_deliver_begin(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->obj, OBJECT_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vcl, VCL_CONF_MAGIC);

	sp->t_resp = TIM_real();
	if (sp->obj->objcore != NULL) {
		if ((sp->t_resp - sp->obj->last_lru) > params->lru_timeout &&
		    EXP_Touch(sp->obj))
			sp->obj->last_lru = sp->t_resp;	/* XXX: locking ? */
		sp->obj->last_use = sp->t_resp;	/* XXX: locking ? */
	}
	sp->wrkvar.resp = sp->wrkvar.http[2];
	http_Setup(sp->wrkvar.resp, sp->ws);
	RES_BuildHttp(sp);
	VCL_http_deliver_method(sp);
	switch (sp->handling) {
	case VCL_RET_DELIVER:
		break;
	case VCL_RET_RESTART:
		INCOMPL();
		break;
	default:
		WRONG("Illegal action in vcl_deliver{}");
	}

	sp->director = NULL;
	sp->restarts = 0;

	RES_WriteObjHdr(sp);
	sp->step = STP_HTTP_DELIVER_HDR;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_hdr(struct sess *sp)
{
	int i, want;

	i = WRW_Flush(sp, &want);
	if (i == -3)
		return (SESS_CONTINUE);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, *sp->wrkvar.wfd, want,
		    (want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		vca_close_session(sp, "remote closed");
		WRW_Release(sp);
		sp->step = STP_HTTP_DELIVER_END;
		return (SESS_CONTINUE);
	}
	if ((sp->flags & SESS_F_WANTBODY) == 0 ||
	    (sp->obj->flags & OBJECT_F_ZEROLEN) != 0) {
		WRW_Release(sp);
		sp->step = STP_HTTP_DELIVER_END;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_DELIVER_BODY_BEGIN;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_body_begin(struct sess *sp)
{

	if ((sp->flags & SESS_F_RANGE) != 0) {
		/* XXX assumes that the one range is supported */
		SEPTUM_SLOW(&sp->septum, sp->range[0]);
		SEPTUM_SHIGH(&sp->septum, sp->range[1]);
	} else
		SEPTUM_SOFFSET(&sp->septum, 0);

	sp->step = STP_HTTP_DELIVER_BODY_PREPARE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_body_prepare(struct sess *sp)
{
	struct storage *st;
	ssize_t u = 0;
	ssize_t low, high, len, objlen, off, ptr;

	if (sp->obj->len == 0) {
		sp->step = STP_HTTP_DELIVER_BODY_WAIT;
		return (SESS_CONTINUE);
	}

	if ((sp->flags & SESS_F_RANGE) == 0) {
		objlen = sp->obj->len;
		low = SEPTUM_GOFFSET(&sp->septum);
		high = objlen - 1;
	} else {
		low = SEPTUM_GLOW(&sp->septum);
		high = SEPTUM_GHIGH(&sp->septum);
	}
	/*
	 * sending 0 byte never should be happened here; it's a design.  If
	 * high == low, it'll send 1 byte.
	 */
	assert(high >= low);

	ptr = 0;
	VTAILQ_FOREACH(st, &sp->obj->store, list) {
		CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		CHECK_OBJ_NOTNULL(st, STORAGE_MAGIC);
		len = st->len;
		off = 0;
		if (ptr + len <= low) {
			/* This segment is too early */
			ptr += len;
			continue;
		}
		if (ptr < low) {
			/* Chop front of segment off */
			off += (low - ptr);
			len -= (low - ptr);
			ptr += (low - ptr);
		}
		if (ptr + len > high)
			/* Chop tail of segment off */
			len = 1 + high - ptr;

		ptr += len;
		u += len;
		sp->acct_tmp.bodybytes += len;
		VSL_stats->n_objwrite++;
		(void)WRW_Write(sp, st->ptr + off, len);
	}
	assert(u == (high - low + 1));
	/* Sets the next offset. */
	SEPTUM_SOFFSET(&sp->septum, high + 1);

	sp->step = STP_HTTP_DELIVER_BODY_SEND;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_body_send(struct sess *sp)
{
	int i, want;

	i = WRW_Flush(sp, &want);
	if (i == -3)
		return (SESS_CONTINUE);
	if (i == -2) {
		SEPTUM_SESSEVENT(sp, *sp->wrkvar.wfd, want,
		    (want == SEPTUM_WANT_READ) ?
		    CALLOUT_SECTOTICKS(params->recv_timeout) :
		    CALLOUT_SECTOTICKS(params->send_timeout));
		return (SESS_WAIT);
	}
	if (i == -1) {
		vca_close_session(sp, "remote closed");
		/*
		 * The fetcher is still working at this momement so sets a flag
		 * letting him know what's happenning on the client side.
		 */
		sp->flags |= SESS_F_QUICKABORT;
		sp->step = STP_HTTP_DELIVER_BODY_END;
		return (SESS_CONTINUE);
	}
	if ((sp->obj->flags & OBJECT_F_ERROR) != 0) {
		sp->step = STP_HTTP_DELIVER_BODY_END;
		return (SESS_CONTINUE);
	}
	if ((sp->obj->flags & OBJECT_F_DONE) != 0) {
		if ((sp->flags & SESS_F_RANGE) != 0) {
			sp->step = STP_HTTP_DELIVER_BODY_END;
			return (SESS_CONTINUE);
		}
		if (sp->obj->len == SEPTUM_GOFFSET(&sp->septum)) {
			sp->step = STP_HTTP_DELIVER_BODY_END;
			return (SESS_CONTINUE);
		}
		sp->step = STP_HTTP_DELIVER_BODY_PREPARE;
		return (SESS_CONTINUE);
	}
	assert((sp->flags & SESS_F_RANGE) == 0);
	/* something is delivered during flushing the data to client */
	if (sp->obj->len != SEPTUM_GOFFSET(&sp->septum)) {
		sp->step = STP_HTTP_DELIVER_BODY_PREPARE;
		return (SESS_CONTINUE);
	}
	sp->step = STP_HTTP_DELIVER_BODY_WAIT;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_body_wait(struct sess *sp)
{

	assert((sp->obj->flags & OBJECT_F_DONE) == 0);
	HSH_Wait(sp);

	sp->step = STP_HTTP_DELIVER_BODY_WAKEN;
	SES_Sleep(sp);
	return (SESS_SLEEP);
}

static enum sess_status
cnt_http_deliver_body_waken(struct sess *sp)
{

	if ((sp->obj->flags & OBJECT_F_ERROR) != 0) {
		sp->step = STP_HTTP_DELIVER_BODY_END;
		return (SESS_CONTINUE);
	}

	/*
	 * Releases the backend as soon as possible just after waken up
	 * because some sessions could wait for this backend.
	 */
	if ((sp->obj->flags & OBJECT_F_DONE) != 0) {
		if (sp->vc != NULL)
			VBE_CloseFd(sp, &sp->vc,
			    (sp->flags & SESS_F_CLOSE) == 0);
		/*
		 * Even if it's waken and sp->obj->len didn't be increased
		 * we assume that there's no any data.
		 */
		if (SEPTUM_GOFFSET(&sp->septum) == sp->obj->len) {
			sp->step = STP_HTTP_DELIVER_BODY_END;
			return (SESS_CONTINUE);
		}
	} else {
		if (SEPTUM_GOFFSET(&sp->septum) == sp->obj->len) {
			sp->step = STP_HTTP_DELIVER_BODY_WAIT;
			return (SESS_CONTINUE);
		}
	}
	sp->step = STP_HTTP_DELIVER_BODY_PREPARE;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_body_end(struct sess *sp)
{

	sp->step = STP_HTTP_DELIVER_END;
	return (SESS_CONTINUE);
}

static enum sess_status
cnt_http_deliver_end(struct sess *sp)
{
	struct storage *st;

	if ((sp->obj->flags & OBJECT_F_DONE) == 0) {
		HSH_Wait(sp);
		SES_Sleep(sp);
		return (SESS_SLEEP);
	}
	if (sp->vc != NULL)
		VBE_CloseFd(sp, &sp->vc, (sp->flags & SESS_F_CLOSE) == 0);
	if ((sp->obj->flags & OBJECT_F_EOF) != 0)
		vca_close_session(sp, "EOF");

	/* fetch is involved if it turns on. */
	if (sp->flags & SESS_F_NEEDOBJREL) {
		if ((sp->obj->flags & OBJECT_F_ERROR) == 0) {
			sp->acct_tmp.fetch++;
			if (sp->obj->objcore != NULL)
				AN(sp->obj->flags & OBJECT_F_CACHEABLE);
			HSH_Deref(sp->wrk, &sp->obj);
		} else {
			sp->doclose = "fetcherror";

			/*
			 * XXX: Wouldn't this store automatically be
			 * released ?
			 */
			while (!VTAILQ_EMPTY(&sp->obj->store)) {
				st = VTAILQ_FIRST(&sp->obj->store);
				VTAILQ_REMOVE(&sp->obj->store, st, list);
				STV_free(st);
			}
			HSH_Drop(sp);
			AZ(sp->obj);
		}
		sp->wrkvar.body_status = 0;
		AN(sp->wrkvar.bereq);
		sp->wrkvar.bereq = NULL;
		AN(sp->wrkvar.beresp);
		sp->wrkvar.beresp = NULL;
		AN(sp->wrkvar.beresp1);
		sp->wrkvar.beresp1 = NULL;
	} else
		HSH_Deref(sp->wrk, &sp->obj);
	WRW_Release(sp);
	AZ(sp->wrkvar.wfd);
	AZ(sp->wrkvar.bereq);
	AZ(sp->wrkvar.beresp);
	AZ(sp->wrkvar.beresp1);
	AN(sp->wrkvar.resp);
	sp->wrkvar.resp = NULL;
	sp->step = STP_DONE;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * Emit an error
 *
DOT subgraph xcluster_error {
DOT	vcl_error [
DOT		shape=record
DOT		label="vcl_error()|resp."
DOT	]
DOT	ERROR -> vcl_error
DOT	vcl_error-> deliver [label=deliver]
DOT }
 */

static enum sess_status
cnt_http_error(struct sess *sp)
{
	struct worker *w;
	struct http *h;
	char date[40];

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	assert((sp->flags & SESS_F_ERROR) != 0);
	assert((sp->flags & SESS_F_NEEDOBJREL) == 0);

	w = sp->wrk;
	if (sp->obj == NULL) {
		HSH_Prealloc(sp);
		sp->flags &= ~SESS_F_CACHEABLE;
		/* XXX: 1024 is a pure guess */
		sp->obj = STV_NewObject(sp, 1024, 0, params->http_headers);
		sp->obj->flags |= OBJECT_F_DONE;
		sp->obj->xid = sp->xid;
		sp->obj->entered = sp->t_req;
	} else {
		/* XXX: Null the headers ? */
	}
	CHECK_OBJ_NOTNULL(sp->obj, OBJECT_MAGIC);
	h = sp->obj->http;

	if (sp->err_code < 100 || sp->err_code > 999)
		sp->err_code = 501;

	http_PutProtocol(w, sp->sp_fd, h, "HTTP/1.1");
	http_PutStatus(w, sp->sp_fd, h, sp->err_code);
	TIM_format(TIM_real(), date);
	http_PrintfHeader(w, sp->sp_fd, h, "Date: %s", date);
	http_PrintfHeader(w, sp->sp_fd, h, "Server: Cache-Terminator");
	http_PrintfHeader(w, sp->sp_fd, h, "Retry-After: %d",
	    params->err_ttl);

	if (sp->err_reason != NULL)
		http_PutResponse(w, sp->sp_fd, h, sp->err_reason);
	else
		http_PutResponse(w, sp->sp_fd, h,
		    http_StatusMessage(sp->err_code));
	VCL_http_error_method(sp);

	if (sp->handling == VCL_RET_RESTART &&
	    sp->restarts <  params->max_restarts) {
		HSH_Drop(sp);
		sp->director = NULL;
		sp->restarts++;
		sp->step = STP_HTTP_RECV;
		return (SESS_CONTINUE);
	} else if (sp->handling == VCL_RET_RESTART)
		sp->handling = VCL_RET_DELIVER;

	/* We always close when we take this path */
	sp->doclose = "error";
	sp->flags &= ~SESS_F_WANTBODY;
	if (sp->obj->len > 0)
		sp->flags |= SESS_F_WANTBODY;

	assert(sp->handling == VCL_RET_DELIVER);
	sp->err_code = 0;
	sp->err_reason = NULL;
	AZ(sp->wrkvar.bereq);
	sp->step = STP_HTTP_DELIVER_BEGIN;
	return (SESS_CONTINUE);
}

/*--------------------------------------------------------------------
 * This is the final state, figure out if we should close or recycle
 * the client connection
 *
DOT	DONE [
DOT		shape=hexagon
DOT		label="Request completed"
DOT	]
 */

static enum sess_status
cnt_done(struct sess *sp)
{
	struct callout *c;
	double dh, dp, da;
	int i;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_ORNULL(sp->vcl, VCL_CONF_MAGIC);
	CAST_OBJ_NOTNULL(c, &sp->septum.co, CALLOUT_MAGIC);

	AZ(sp->obj);
	AZ(sp->vc);
	assert((c->c_flags & CALLOUT_ACTIVE) == 0);
	sp->director = NULL;
	sp->restarts = 0;

	if (sp->vcl != NULL)
		VCL_Rel(&sp->vcl);
	if (sp->geoip != NULL)
		GEO_Rel(&sp->geoip);

	SES_Charge(sp);

	sp->t_end = TIM_real();
	sp->wrk->lastused = sp->t_end;
	if (sp->xid == 0) {
		sp->t_req = sp->t_end;
		sp->t_resp = sp->t_end;
	} else {
		dp = sp->t_resp - sp->t_req;
		da = sp->t_end - sp->t_resp;
		dh = sp->t_req - sp->t_open;
		/* XXX: Add StatReq == StatSess */
		WSP(sp, SLT_Length, "%u", sp->acct_req.bodybytes);
		WSL(sp->wrk, SLT_ReqEnd, sp->id, "%u %.9f %.9f %.9f %.9f %.9f",
		    sp->xid, sp->t_req, sp->t_end, dh, dp, da);
	}
	sp->xid = 0;
	sp->t_open = sp->t_end;
	sp->t_resp = NAN;
	WSL_Flush(sp->wrk, 0);

	memset(&sp->acct_req, 0, sizeof sp->acct_req);

	sp->t_req = NAN;
	sp->flags = 0;

	if (sp->sp_fd >= 0 && sp->doclose != NULL) {
		/*
		 * This is an orderly close of the connection; ditch nolinger
		 * before we close, to get queued data transmitted.
		 */
		// XXX: not yet (void)TCP_linger(sp->sp_fd, 0);
		vca_close_session(sp, sp->doclose);
	}

	if (sp->sp_fd < 0) {
		sp->wrk->stats.sess_closed++;
		sp->wrk = NULL;
		SES_Delete(sp);
		return (SESS_DONE);
	}

	if (sp->wrk->stats.client_req >= params->wthread_stats_rate)
		WRK_SumStat(sp->wrk);
	/* Reset the workspace to the session-watermark */
	WS_Reset(sp->ws, sp->ws_ses);

	i = HTC_Reinit(sp->htc);
	if (i == 1) {
		sp->wrk->stats.sess_pipeline++;
		sp->step = STP_HTTP_START;
		return (SESS_CONTINUE);
	}
	if (Tlen(sp->htc->rxbuf)) {
		sp->wrk->stats.sess_readahead++;
		sp->step = STP_HTTP_WAIT_BEGIN;
		return (SESS_CONTINUE);
	}
	if (params->session_linger > 0) {
		sp->wrk->stats.sess_linger++;
		sp->step = STP_HTTP_WAIT_BEGIN;
		return (SESS_CONTINUE);
	}
	sp->wrk->stats.sess_herd++;
	sp->wrk = NULL;
	vca_return_session(sp);
	return (SESS_DONE);
}

/*--------------------------------------------------------------------
 * Central state engine dispatcher.
 *
 * Kick the session around until it has had enough.
 *
 */

static void
cnt_diag(struct sess *sp, const char *state)
{
	if (sp->wrk != NULL) {
		WSL(sp->wrk, SLT_Debug, sp->id,
		    "thr %p STP_%s sp %p obj %p vcl %p",
		    pthread_self(), state, sp, sp->obj, sp->vcl);
		WSL_Flush(sp->wrk, 0);
	} else {
		VSL(SLT_Debug, sp->id,
		    "thr %p STP_%s sp %p obj %p vcl %p",
		    pthread_self(), state, sp, sp->obj, sp->vcl);
	}
}

enum sess_status
CNT_Session(struct sess *sp)
{
	enum sess_status status;
	struct worker *w;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	w = sp->wrk;
	CHECK_OBJ_NOTNULL(w, WORKER_MAGIC);

	/*
	 * Possible entrance states
	 */
	assert(
	    sp->step == STP_FIRST ||
	    sp->step == STP_TIMEOUT ||
	    sp->step == STP_HTTP_WAIT_RECV ||
	    sp->step == STP_HTTP_START ||
	    sp->step == STP_HTTP_START_CONTINUE ||
	    sp->step == STP_HTTP_LOOKUP ||
	    sp->step == STP_HTTP_RECV ||
	    sp->step == STP_HTTP_PIPE_CONNECT ||
	    sp->step == STP_HTTP_PIPE_HDRFLUSH ||
	    sp->step == STP_HTTP_PIPE_RECV_FROMCLIENT ||
	    sp->step == STP_HTTP_PIPE_SEND_TOBACKEND ||
	    sp->step == STP_HTTP_PIPE_CLOSEWAIT ||
	    sp->step == STP_HTTP_FETCH_CONNECT ||
	    sp->step == STP_HTTP_FETCH_REQ_BODY_RECV ||
	    sp->step == STP_HTTP_FETCH_REQ_BODY_SEND ||
	    sp->step == STP_HTTP_FETCH_REQ_HDR_FLUSH ||
	    sp->step == STP_HTTP_FETCH_RESP_RECV_FIRSTBYTE ||
	    sp->step == STP_HTTP_FETCH_RESP_RECV_NEXTBYTES ||
	    sp->step == STP_HTTP_HIT_REQ_RECV ||
	    sp->step == STP_HTTP_DELIVER_BODY_WAKEN ||
	    sp->step == STP_HTTP_DELIVER_BODY_SEND ||
	    sp->step == STP_HTTP_DELIVER_END ||
	    sp->step == STP_SOCKS_RECV ||
	    sp->step == STP_SOCKS_PIPE_RECV_FROMCLIENT ||
	    sp->step == STP_SOCKS_PIPE_SEND_TOBACKEND ||
	    sp->step == STP_SOCKS_PIPE_END ||
	    sp->step == STP_SOCKSv4_CONNECT_DO ||
	    sp->step == STP_SOCKSv4_SEND ||
	    sp->step == STP_SOCKSv5_RECV ||
	    sp->step == STP_SOCKSv5_CONNECT_DO ||
	    sp->step == STP_SOCKSv5_SENDAUTH ||
	    sp->step == STP_SOCKSv5_SEND ||
	    sp->step == STP_TUNNEL_CONNECT ||
	    sp->step == STP_TUNNEL_PIPE_RECV_FROMCLIENT ||
	    sp->step == STP_TUNNEL_PIPE_SEND_TOBACKEND ||
	    sp->step == STP_TUNNEL_PIPE_END
	);

	/*
	 * Whenever we come in from the acceptor we need to set non blocking
	 * mode, but there is no point in setting it when we come from
	 * ESI or when a parked sessions returns.
	 * It would be simpler to do this in the acceptor, but we'd rather
	 * do the syscall in the worker thread.
	 */
	if (sp->step == STP_FIRST || sp->step == STP_HTTP_START) {
		(void)TCP_nonblocking(sp->sp_fd);
		if (params->tcp_nodelay)
			(void)TCP_nodelay(sp->sp_fd);
#if defined(__linux__)
		if (params->tcp_quickack)
			(void)TCP_quickack(sp->sp_fd);
#endif
	}

	/*
	 * NB: Once done is set, we can no longer touch sp!
	 */
	for (status = SESS_CONTINUE; status == SESS_CONTINUE; ) {
		assert(sp->wrk == w);
		/*
		 * This is a good place to be paranoid about the various
		 * pointers still pointing to the things we expect.
		 */
		CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		CHECK_OBJ_ORNULL(sp->obj, OBJECT_MAGIC);
		CHECK_OBJ_NOTNULL(sp->wrk, WORKER_MAGIC);
		CHECK_OBJ_ORNULL(w->nobjhead, OBJHEAD_MAGIC);

#ifdef VARNISH_DEBUG
		sp->stephist[sp->stephist_cur++] = sp->step;
		if (sp->stephist_cur >= STEPHIST_MAX)
			sp->stephist_cur = 0;
#endif

		if (params->diag_bitmap & 0x00080000)
			WSL(w, SLT_SessSM, sp->sp_fd, "%s",
			    cnt_stepstr[sp->step]);

		switch (sp->step) {
#define STEP(l,u) \
		    case STP_##u: \
			if (params->diag_bitmap & 0x01) \
				cnt_diag(sp, #u); \
			status = cnt_##l(sp); \
			break;
#include "steps.h"
#undef STEP
		default:
			WRONG("State engine misfire");
		}
		CHECK_OBJ_ORNULL(w->nobjhead, OBJHEAD_MAGIC);

		if (params->diag_bitmap & 0x00080000)
			WSL(w, SLT_SessSM, sp->sp_fd, "%s",
			    cnt_statusstr[status]);
	}
	WSL_Flush(w, 0);

	return (status);
}

/*
DOT }
*/

/*--------------------------------------------------------------------
 * Debugging aids
 */

static void
cli_debug_xid(struct cli *cli, const char * const *av, void *priv)
{
	(void)priv;
	if (av[2] != NULL)
		xids = strtoul(av[2], NULL, 0);
	cli_out(cli, "XID is %u", xids);
}

/*
 * Default to seed=1, this is the only seed value POSIXl guarantees will
 * result in a reproducible random number sequence.
 */
static void
cli_debug_srandom(struct cli *cli, const char * const *av, void *priv)
{
	(void)priv;
	unsigned seed = 1;

	if (av[2] != NULL)
		seed = strtoul(av[2], NULL, 0);
	srandom(seed);
	cli_out(cli, "Random(3) seeded with %lu", seed);
}

static struct cli_proto debug_cmds[] = {
	{ "debug.xid", "debug.xid",
		"\tExamine or set XID\n", 0, 1, "d", cli_debug_xid },
	{ "debug.srandom", "debug.srandom",
		"\tSeed the random(3) function\n", 0, 1, "d",
		cli_debug_srandom },
	{ NULL }
};

/*--------------------------------------------------------------------
 * Main state machine.
 */

void
CNT_Init(void)
{

	srandomdev();
	xids = random();
	CLI_AddFuncs(debug_cmds);
}
