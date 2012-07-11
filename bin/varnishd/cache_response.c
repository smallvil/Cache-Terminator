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
SVNID("$Id: cache_response.c 145 2011-04-15 18:58:22Z jwg286 $")

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>

#include "shmlog.h"
#include "cache.h"
#include "vct.h"

/*--------------------------------------------------------------------*/

static void
res_do_304(struct sess *sp)
{
	char lm[64];
	char *p;

	http_ClrHeader(sp->wrkvar.resp);
	sp->wrkvar.resp->logtag = HTTP_Tx;
	http_SetResp(sp->wrkvar.resp, "HTTP/1.1", "304", "Not Modified");
	TIM_format(sp->t_req, lm);
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Date: %s", lm);
	http_SetHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Via: 1.1 varnish");
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "X-Cache-Terminator: %u", sp->xid);
	if (sp->obj->last_modified) {
		TIM_format(sp->obj->last_modified, lm);
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Last-Modified: %s", lm);
	}

	/* http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.5 */
	if (http_GetHdr(sp->obj->http, H_Cache_Control, &p))
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Cache-Control: %s", p);
	if (http_GetHdr(sp->obj->http, H_Content_Location, &p))
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Content-Location: %s", p);
	if (http_GetHdr(sp->obj->http, H_ETag, &p))
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "ETag: %s", p);
	if (http_GetHdr(sp->obj->http, H_Expires, &p))
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Expires: %s", p);
	if (http_GetHdr(sp->obj->http, H_Vary, &p))
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Vary: %s", p);

	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Connection: %s", sp->doclose ? "close" : "keep-alive");
	sp->flags &= ~SESS_F_WANTBODY;
}

/*--------------------------------------------------------------------*/

static int
res_do_conds(struct sess *sp)
{
	char *p, *e;
	double ims;
	int do_cond = 0;

	/* RFC 2616 13.3.4 states we need to match both ETag
	   and If-Modified-Since if present*/

	if (http_GetHdr(sp->http, H_If_Modified_Since, &p) ) {
		if (!sp->obj->last_modified)
			return (0);
		ims = TIM_parse(p);
		if (ims > sp->t_req)	/* [RFC2616 14.25] */
			return (0);
		if (sp->obj->last_modified > ims)
			return (0);
		do_cond = 1;
	}

	if (http_GetHdr(sp->http, H_If_None_Match, &p) &&
	    http_GetHdr(sp->obj->http, H_ETag, &e)) {
		if (strcmp(p,e) != 0)
			return (0);
		do_cond = 1;
	}

	if (do_cond == 1) {
		res_do_304(sp);
		return (1);
	}
	return (0);
}

/*--------------------------------------------------------------------*/

static void
res_dorange(struct sess *sp, const char *r)
{
	ssize_t low, high;
	unsigned has_low;

	(void)sp;
	if (strncmp(r, "bytes=", 6))
		return;
	r += 6;

	/* The low end of range */
	has_low = low = 0;
	if (!vct_isdigit(*r) && *r != '-')
		return;
	while (vct_isdigit(*r)) {
		has_low = 1;
		low *= 10;
		low += *r - '0';
		r++;
	}

	if (low >= sp->obj->len)
		return;

	if (*r != '-')
		return;
	r++;

	/* The high end of range */
	if (vct_isdigit(*r)) {
		high = 0;
		while (vct_isdigit(*r)) {
			high *= 10;
			high += *r - '0';
			r++;
		}
		if (!has_low) {
			low = sp->obj->len - high;
			high = sp->obj->len - 1;
		}
	} else
		high = sp->obj->len - 1;
	if (*r != '\0')
		return;

	if (high >= sp->obj->len)
		high = sp->obj->len - 1;

	if (low > high)
		return;

	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Content-Range: bytes %zd-%zd/%zd", low, high, sp->obj->len);
	http_Unset(sp->wrkvar.resp, H_Content_Length);
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Content-Length: %zd", 1 + high - low);
	http_SetResp(sp->wrkvar.resp, "HTTP/1.1", "206", "Partial Content");

	/* XXX in current implementation it only supports one range */
	sp->flags |= SESS_F_RANGE;
	sp->range = (unsigned *)WS_Alloc(sp->ws, sizeof(unsigned) * 2);
	AN(sp->range);
	sp->range[0] = low;
	sp->range[1] = high;
	sp->nrange = 1;
}

/*--------------------------------------------------------------------*/

void
RES_BuildHttp(struct sess *sp)
{
	char time_str[30];

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	if (sp->obj->response == 200 && sp->http->conds && res_do_conds(sp))
		return;

	http_ClrHeader(sp->wrkvar.resp);
	sp->wrkvar.resp->logtag = HTTP_Tx;
	http_CopyResp(sp->wrkvar.resp, sp->obj->http);
	http_FilterFields(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    sp->obj->http, HTTPH_A_DELIVER);

	if (params->http_range_support)
		http_SetHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "Accept-Ranges: bytes");

	TIM_format(TIM_real(), time_str);
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp, "Date: %s",
	    time_str);

	if (sp->xid != sp->obj->xid)
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "X-Cache-Terminator: %u %u", sp->xid, sp->obj->xid);
	else
		http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
		    "X-Cache-Terminator: %u", sp->xid);
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp, "Age: %.0f",
	    sp->obj->age + sp->t_resp - sp->obj->entered);
	http_SetHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Via: 1.1 Cache-Terminator");
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.resp,
	    "Connection: %s", sp->doclose ? "close" : "keep-alive");
}

/*--------------------------------------------------------------------*/

void
RES_WriteObjHdr(struct sess *sp)
{
	char *r;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	WRW_Reserve(sp, &sp->sp_fd, &sp->sp_ssl);
	if (params->http_range_support &&
	    sp->obj->response == 200 &&
	    (sp->flags & SESS_F_WANTBODY) != 0 &&
	    (sp->obj->flags & OBJECT_F_DONE) != 0 &&
	    (sp->obj->flags & OBJECT_F_ZEROLEN) == 0 &&
	    http_GetHdr(sp->http, H_Range, &r))
		res_dorange(sp, r);
	sp->acct_tmp.hdrbytes += http_Write(sp, sp->wrkvar.resp, 1);
}
