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
 * HTTP protocol requests
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_socks.c 21 2011-03-31 01:35:07Z jwg286 $")

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "shmlog.h"
#include "cache.h"

/*--------------------------------------------------------------------*/

void
SCK_Init(struct socks_conn *stc, struct ws *ws, int fd)
{

	stc->magic = SOCKS_CONN_MAGIC;
	stc->ws = ws;
	stc->fd = fd;
	/* XXX: ->s or ->f ? or param ? */
	(void)WS_Reserve(stc->ws, (stc->ws->e - stc->ws->s) / 2);
	stc->rxbuf.b = ws->f;
	stc->rxbuf.e = ws->f;
	*stc->rxbuf.e = '\0';
	stc->pipeline.b = NULL;
	stc->pipeline.e = NULL;
}

static int
stc_v4_req_complete(txt *t)
{
	const char *p;
	unsigned rlen = 8;	/* VER + CMD + PORT + IP */

	Tcheck(*t);
	assert(*t->e == '\0');
	if (Tlen(*t) < rlen)
		return (0);
	p = t->b;
	assert(p[0] == 0x4);
	assert(p[1] == 0x1 || p[1] == 0x2);
	for (p = p + 8; p < t->e; p++) {
		rlen++;
		if (p[0] == '\0' && p[1] == '\0')
			return (rlen);
	}
	return (0);
}

static int
stc_v5_req_complete(txt *t)
{
	const char *p;
	unsigned rlen = 4;	/* VER + CMD + RSV + ATYP */

	Tcheck(*t);
	assert(*t->e == '\0');
	if (Tlen(*t) < rlen)
		return (0);
	p = t->b;
	assert(p[0] == 0x4 || p[0] == 0x5);
	assert(p[1] == 0x1 || p[1] == 0x2 || p[1] == 0x3);
	assert(p[2] == 0x0);
	if (p[3] == 0x1) {
		rlen += 4;	/* IPv4 */
		rlen += 2;	/* dst port */
	} else if (p[3] == 0x3)
		rlen += 1;
	else if (p[3] == 0x4) {
		rlen += 16;	/* IPv6 */
		rlen += 2;	/* dst port */
	} else
		assert(0 == 1);
	if (Tlen(*t) < rlen)
		return (0);
	if (p[3] == 0x1 || p[3] == 0x4)
		return (rlen);
	assert(p[3] == 0x3);
	rlen += (unsigned char)p[4];
	rlen += 2;		/* dst port */
	if (Tlen(*t) < rlen)
		return (0);
	return (rlen);
}

static int
stc_auth_complete(txt *t)
{
	const char *p;
	unsigned rlen = 2;	/* VER + NMETHODS */

	Tcheck(*t);
	assert(*t->e == '\0');
	if (Tlen(*t) < rlen)
		return (0);
	p = t->b;
	assert(p[0] == 0x5);
	rlen += (unsigned char)p[1];
	if (Tlen(*t) < rlen)
		return (0);
	return (rlen);
}

static int
sck_Complete(struct socks_conn *stc, int type)
{
	txt *t;
	int i;
	const char *p;

	CHECK_OBJ_NOTNULL(stc, SOCKS_CONN_MAGIC);
	Tcheck(stc->rxbuf);
	t = &stc->rxbuf;
	assert(Tlen(*t) >= 1);
	p = t->b;
	switch (type) {
	case SOCKS_T_V4REQ_OR_V5AUTH:
		if (p[0] == 0x4)
			i = stc_v4_req_complete(&stc->rxbuf);
		else if (p[0] == 0x5)
			i = stc_auth_complete(&stc->rxbuf);
		else
			return (-4);
		break;
	case SOCKS_T_V5REQ:
		i = stc_v5_req_complete(&stc->rxbuf);
		break;
	default:
		assert(0 == 1);
	}
	assert(i >= 0);
	if (i == 0)
		return (0);
	WS_ReleaseP(stc->ws, stc->rxbuf.e);
	if (stc->rxbuf.b + i < stc->rxbuf.e) {
		stc->pipeline.b = stc->rxbuf.b + i;
		stc->pipeline.e = stc->rxbuf.e;
		stc->rxbuf.e = stc->pipeline.b;
	}
	return (1);
}

int
SCK_Rx(struct socks_conn *stc, int type)
{
	int i;

	CHECK_OBJ_NOTNULL(stc, SOCKS_CONN_MAGIC);
	AN(stc->ws->r);
	i = (stc->ws->r - stc->rxbuf.e) - 1;	/* space for NUL */
	if (i <= 0) {
		WS_ReleaseP(stc->ws, stc->rxbuf.b);
		return (-2);
	}
	i = read(stc->fd, stc->rxbuf.e, i);
	if (i <= 0) {
		if (i == -1 && errno == EAGAIN)
			return (-3);
		WS_ReleaseP(stc->ws, stc->rxbuf.b);
		return (-1);
	}
	stc->rxbuf.e += i;
	*stc->rxbuf.e = '\0';
	return (sck_Complete(stc, type));
}
