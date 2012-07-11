/*-
 * Copyright (c) 2011 Weongyo Jeong <weongyo@gmail.com>
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
SVNID("$Id: cache_septum.c 2 2011-03-27 07:34:59Z jwg286 $")

#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
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

void
SPT_Wakeup(struct worker *w, struct septum *st)
{
#ifdef VARNISH_DEBUG
	struct septum *entry;
#endif

	Lck_Lock(&w->readylist_mtx);
#ifdef VARNISH_DEBUG
	/* Sanity checking */
	VTAILQ_FOREACH(entry, &w->readylist, list)
		assert(entry != st);
#endif

	VTAILQ_INSERT_TAIL(&w->readylist, st, list);
	w->nreadylist++;
	Lck_Unlock(&w->readylist_mtx);
}

void
SPT_EventAdd(int efd, struct septum *st)
{
	int r, errnum;

	(void)errnum;

#if defined(HAVE_EPOLL_CTL)
	st->ev.data.ptr = st;
	st->ev.events = EPOLLERR;
	if (st->events & SEPTUM_WANT_READ)
		st->ev.events = EPOLLIN | EPOLLPRI;
	else if (st->events & SEPTUM_WANT_WRITE)
		st->ev.events = EPOLLOUT;
	else
		WRONG("Unknown event type");
	r = epoll_ctl(efd, EPOLL_CTL_ADD, st->fd, &st->ev);
	errnum = errno;
	AZ(r);
#elif defined(HAVE_KQUEUE)
	st->ev.udata = st;
	if (st->events & SEPTUM_WANT_READ)
		EV_SET(&st->ev, st->fd, EVFILT_READ, EV_ADD, 0, 0, st);
	else if (st->events & SEPTUM_WANT_WRITE)
		EV_SET(&st->ev, st->fd, EVFILT_WRITE, EV_ADD, 0, 0, st);
	else
		WRONG("Unknown event type");
	r = kevent(efd, &st->ev, 1, NULL, 0, NULL);
	errnum = errno;
	AZ(r);
#else
#error "unsupported event model"
#endif
}

void
SPT_EventDel(int efd, struct septum *st)
{
#if defined(HAVE_EPOLL_CTL)
	struct epoll_event ev = { 0 , { 0 } };
	int errnum, r;

	(void)errnum;

	r = epoll_ctl(efd, EPOLL_CTL_DEL, st->fd, &ev);
	errnum = errno;
	AZ(r);
#elif defined(HAVE_KQUEUE)
	if (st->events & SEPTUM_WANT_READ)
		EV_SET(&st->ev, st->fd, EVFILT_READ, EV_DELETE, 0, 0, st);
	else if (st->events & SEPTUM_WANT_WRITE)
		EV_SET(&st->ev, st->fd, EVFILT_WRITE, EV_DELETE, 0, 0, st);
	else
		WRONG("Unknown event type");
	AZ(kevent(efd, &st->ev, 1, NULL, 0, NULL));
#else
#error "unsupported event model"
#endif
}
