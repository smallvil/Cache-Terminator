/*-
 * Copyright (c) 2011 Weongyo Jeong
 * All rights reserved.
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
SVNID("$Id: cache_connfds.c 145 2011-04-15 18:58:22Z jwg286 $")

#include <sys/param.h>
#include <sys/uio.h>
#include <stdio.h>
#include "shmlog.h"
#include "cache.h"

ssize_t
CFD_read(struct conn_fds *cf, void *buf, ssize_t count)
{
	ssize_t i;
	int r;

	if (cf->ssl == NULL) {
		i = read(cf->fd, buf, count);
		if (i == -1 && errno == EAGAIN) {
			cf->want = SEPTUM_WANT_READ;
			return (-2);
		}
		return (i);
	}

	i = SSL_read(cf->ssl, buf, count);
	if (i <= 0) {
		r = SSL_get_error(cf->ssl, i);
		switch (r) {
		case SSL_ERROR_WANT_READ:
			cf->want = SEPTUM_WANT_READ;
			return (-2);
			/* NOTREACHED */
		case SSL_ERROR_WANT_WRITE:
			cf->want = SEPTUM_WANT_WRITE;
			return (-2);
			/* NOTREACHED */
		default:
			XXL_error();
			break;
		}
	}
	return (i);
}

ssize_t
CFD_write(struct conn_fds *cf, const void *buf, ssize_t count)
{
	ssize_t i;
	int r;

	assert(count != 0);

	if (cf->ssl == NULL) {
		i = write(cf->fd, buf, count);
		if (i == -1 && errno == EAGAIN) {
			cf->want = SEPTUM_WANT_READ;
			return (-2);
		}
		return (i);
	}

	i = SSL_write(cf->ssl, buf, count);
	if (i <= 0) {
		r = SSL_get_error(cf->ssl, i);
		switch (r) {
		case SSL_ERROR_WANT_READ:
			cf->want = SEPTUM_WANT_READ;
			return (-2);
			/* NOTREACHED */
		case SSL_ERROR_WANT_WRITE:
			cf->want = SEPTUM_WANT_WRITE;
			return (-2);
			/* NOTREACHED */
		default:
			XXL_error();
			break;
		}
	}
	return (i);
}
