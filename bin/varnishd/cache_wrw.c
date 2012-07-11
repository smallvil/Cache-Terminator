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
SVNID("$Id: cache_wrw.c 86 2011-04-08 22:52:43Z jwg286 $")

#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include "shmlog.h"
#include "cache.h"

/*--------------------------------------------------------------------
 * Write data to fd
 * We try to use writev() if possible in order to minimize number of
 * syscalls made and packets sent.  It also just might allow the worker
 * thread to complete the request without holding stuff locked.
 */

void
WRW_Reserve(struct sess *sp, int *fd, SSL **ssl)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AZ(sp->wrkvar.wfd);
	sp->wrkvar.liov = 0;
	sp->wrkvar.niov = 0;
	sp->wrkvar.wfd = fd;
	sp->wrkvar.ssl = ssl;
}

void
WRW_Release(struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	sp->wrkvar.liov = 0;
	sp->wrkvar.niov = 0;
	sp->wrkvar.wfd = NULL;
	sp->wrkvar.ssl = NULL;
}

static void
wrw_IOVReorder(struct sess *sp, ssize_t written)
{
	struct iovec iov[IOV_MAX];
	char *ptr;
	ssize_t offset = 0, diff, liov_new;
	unsigned i, j, niov_new;

	/* XXX need better algorithm that the current has three nasty loops */

	for (i = 0; i < sp->wrkvar.niov; i++) {
		if (sp->wrkvar.iov[i].iov_len + offset > written)
			break;
		offset += sp->wrkvar.iov[i].iov_len;
	}
	liov_new = 0;
	niov_new = sp->wrkvar.niov - i;
	for (j = 0; j < niov_new; i++, j++) {
		if (j == 0) {
			ptr = sp->wrkvar.iov[i].iov_base;
			diff = written - offset;
			iov[j].iov_base = TRUST_ME(ptr + diff);
			iov[j].iov_len = sp->wrkvar.iov[i].iov_len - diff;
			assert((ssize_t)iov[j].iov_len > 0);
		} else {
			iov[j].iov_base = sp->wrkvar.iov[i].iov_base;
			iov[j].iov_len = sp->wrkvar.iov[i].iov_len;
		}
		liov_new += iov[j].iov_len;
	}

	sp->wrkvar.liov = liov_new;
	sp->wrkvar.niov = niov_new;
	for (i = 0 ; i < niov_new; i++) {
		sp->wrkvar.iov[i].iov_base = iov[i].iov_base;
		sp->wrkvar.iov[i].iov_len = iov[i].iov_len;
		assert((ssize_t)sp->wrkvar.iov[i].iov_len > 0);
	}
}

unsigned
WRW_Flush(struct sess *sp, int *want)
{
	ssize_t i;
	int r;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AN(sp->wrkvar.wfd);
	if (*sp->wrkvar.wfd >= 0 && sp->wrkvar.niov > 0) {
		if (*sp->wrkvar.ssl == NULL) {
			i = writev(*sp->wrkvar.wfd, sp->wrkvar.iov,
			    sp->wrkvar.niov);
			if (i == -1 && errno == EAGAIN) {
				*want = SEPTUM_WANT_WRITE;
				return (-2);
			}
			if (i == -1) {
				WSL(sp->wrk, SLT_Debug, *sp->wrkvar.wfd,
				    "Write error, retval = %d, len = %d,"
				    " errno = %s",
				    i, sp->wrkvar.liov, strerror(errno));
				return (-1);
			}
			if (i == 0)
				/* XXX something is wrong */
				assert(0 == 1);
		} else {
			i = XXL_writev(*sp->wrkvar.ssl, sp->wrkvar.iov,
			    sp->wrkvar.niov);
			if (i <= 0) {
				r = SSL_get_error(*sp->wrkvar.ssl, i);
				switch (r) {
				case SSL_ERROR_WANT_READ:
					*want = SEPTUM_WANT_READ;
					return (-2);
					/* NOTREACHED */
				case SSL_ERROR_WANT_WRITE:
					*want = SEPTUM_WANT_WRITE;
					return (-2);
					/* NOTREACHED */
				default:
					XXL_error();
					WSL(sp->wrk, SLT_Debug, *sp->wrkvar.wfd,
					    "Write error, retval = %d, "
					    "len = %d, error = %s",
					    i, sp->wrkvar.liov,
					    ERR_error_string(ERR_get_error(),
						NULL));
					return (-1);
					/* NOTREACHED */
				}
			}
		}
		if (i != sp->wrkvar.liov) {
			wrw_IOVReorder(sp, i);
			return (-3);
		}
	}
	sp->wrkvar.liov = 0;
	sp->wrkvar.niov = 0;
	return (0);
}

unsigned
WRW_WriteH(struct sess *sp, const txt *hh, const char *suf)
{
	unsigned u;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AN(sp->wrkvar.wfd);
	AN(sp->wrk);
	AN(hh);
	AN(hh->b);
	AN(hh->e);
	u = WRW_Write(sp, hh->b, hh->e - hh->b);
	if (suf != NULL)
		u += WRW_Write(sp, suf, -1);
	return (u);
}

unsigned
WRW_Write(struct sess *sp, const void *ptr, int len)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	AN(sp->wrkvar.wfd);
	if (len == 0 || *sp->wrkvar.wfd < 0)
		return (0);
	if (len == -1)
		len = strlen(ptr);
	if (sp->wrkvar.niov == sp->wrkvar.siov)
		assert(0 == 1);
	assert(len > 0);
	sp->wrkvar.iov[sp->wrkvar.niov].iov_base = TRUST_ME(ptr);
	sp->wrkvar.iov[sp->wrkvar.niov].iov_len = len;
	sp->wrkvar.liov += len;
	sp->wrkvar.niov++;
	return (len);
}

