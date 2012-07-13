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
 * Handle backend connections and backend request structures.
 *
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_backend.c 93 2011-04-11 19:03:39Z jwg286 $")

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h>

#include "shmlog.h"
#include "cache.h"
#include "cache_backend.h"
#include "vrt.h"

/*
 * List of cached vbe_conns, used if enabled in params/heritage
 */
static VTAILQ_HEAD(,vbe_conn) vbe_conns = VTAILQ_HEAD_INITIALIZER(vbe_conns);

static void	vbe_RecycleFd(struct sess *sp);

/*--------------------------------------------------------------------
 * Create default Host: header for backend request
 */
void
VBE_AddHostHeader(const struct sess *sp)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->wrkvar.bereq, HTTP_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vc, VBE_CONN_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vc->backend, BACKEND_MAGIC);
	http_PrintfHeader(sp->wrk, sp->sp_fd, sp->wrkvar.bereq,
	    "Host: %s", sp->vc->backend->hosthdr);
}

/* Private interface from backend_cfg.c */
void
VBE_ReleaseConn(struct vbe_conn *vc)
{

	CHECK_OBJ_NOTNULL(vc, VBE_CONN_MAGIC);
	assert(vc->backend == NULL);
	assert(vc->vc_fd < 0);

	vc->recycled = 0;
	if (params->cache_vbe_conns) {
		Lck_Lock(&VBE_mtx);
		VTAILQ_INSERT_HEAD(&vbe_conns, vc, list);
		VSL_stats->backend_unused++;
		Lck_Unlock(&VBE_mtx);
	} else {
		Lck_Lock(&VBE_mtx);
		VSL_stats->n_vbe_conn--;
		Lck_Unlock(&VBE_mtx);
		free(vc);
	}
}

/*--------------------------------------------------------------------*/

static int
vbe_GetSock(const struct sess *sp, int pf)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	return (socket(pf, SOCK_STREAM, 0));
}

/*--------------------------------------------------------------------*/

static int
vbe_gethostbyname(struct sess *sp, struct sockaddr_in *sain, socklen_t *sainlen,
    const char *hostname, const char *port)
{
	struct hostent *hp;
	long val;
	int i = 0;

	WSP(sp, SLT_BackendGetHostByName, "%s %s", hostname, port);

	hp = gethostbyname(hostname);
	if (hp == NULL)
		return (-1);
	while (hp->h_addr_list[i] != NULL) {
		*sainlen = sizeof(struct sockaddr_in);
		sain->sin_family = AF_INET;
		sain->sin_addr = *((struct in_addr *)hp->h_addr_list[i]);
		if (params->wtf_ucloud) {
			in_addr_t ucloud_ext = inet_addr("14.63.214.216");
			in_addr_t ucloud_in = inet_addr("172.27.238.90");
			if (sain->sin_addr.s_addr == ucloud_ext)
				sain->sin_addr.s_addr = ucloud_in;
		}
		if (port == NULL)
			sain->sin_port = htons(80);
		else {
			errno = 0;
			val = strtol(port, NULL, 10);
			if ((errno == ERANGE &&
			     (val == LONG_MAX || val == LONG_MIN)) ||
			    (errno != 0 && val == 0)) {
				WSP(sp, SLT_Error, "Wrong port format: %s",
				    port);
				return (-1);
			} else if (val <= 0 || val >= USHRT_MAX) {
				WSP(sp, SLT_Error,
				    "Invalid port value: %d", val);
				return (-1);
			} else
				sain->sin_port = htons(val);
		}
		i++;
		return (0);
	}
	return (-1);
}

static int
vbe_handleInAddrAny(struct sess *sp, struct backend *bp)
{
	struct sockaddr *sa;
	struct sockaddr_in *sain;
	int r;

	assert((sp->flags & SESS_F_INADDR_ANY) == 0);
	assert((sp->flags & SESS_F_BACKEND_HINT) == 0);

	sa = (struct sockaddr *)bp->ipv4;
	if (sa->sa_family != AF_INET)
		return (-1);
	sain = (struct sockaddr_in *)sa;
	if ((sp->flags & SESS_T_HTTP) != 0 &&
	    sain->sin_addr.s_addr == INADDR_ANY) {
		struct http *hp = sp->wrkvar.bereq;
		char host[NI_MAXHOST];
		char *p = NULL, *port;

		sp->flags |= SESS_F_INADDR_ANY;

		CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
		if (http_IsConnectMethod(hp))
			p = http_GetUrl(hp);
		else if (http_GetHdr(hp, H_Host, &p) == 0)
			return (-1);
		if (p == NULL)
			return (-1);
		strncpy(host, p, sizeof(host));
		port = strchr(host, ':');
		if (port != NULL) {
			*port = '\0';
			port++;
		}
		r = vbe_gethostbyname(sp, (struct sockaddr_in *)&sp->hint,
		    &sp->hintlen, host, port);
		if (r == -1)
			return (-1);
		sp->flags |= SESS_F_BACKEND_HINT;
	}
	return (0);
}

int
VBE_GetSocket(struct sess *sp, struct vbe_conn *vc)
{
	struct backend *bp;
	int ret, s;

	CAST_OBJ_NOTNULL(bp, vc->backend, BACKEND_MAGIC);

	Lck_Lock(&bp->mtx);
	bp->refcount++;
	bp->n_conn++;		/* It mostly works */
	Lck_Unlock(&bp->mtx);

	s = -1;
	assert(bp->ipv6 != NULL || bp->ipv4 != NULL);

	/* release lock during stuff that can take a long time */

	if (params->prefer_ipv6 && bp->ipv6 != NULL) {
		s = vbe_GetSock(sp, PF_INET6);
		bcopy(bp->ipv6, &vc->sa, bp->ipv6len);
		vc->salen = bp->ipv6len;
	}
	if (s == -1 && bp->ipv4 != NULL) {
		s = vbe_GetSock(sp, PF_INET);
		if ((sp->flags & SESS_F_INADDR_ANY) != 0 &&
		    (sp->flags & SESS_F_BACKEND_HINT) != 0) {
			bcopy(&sp->hint, &vc->sa, sp->hintlen);
			vc->salen = sp->hintlen;
		} else {
			bcopy(bp->ipv4, &vc->sa, bp->ipv4len);
			vc->salen = bp->ipv4len;
		}
	}
	if (s == -1 && !params->prefer_ipv6 && bp->ipv6 != NULL) {
		s = vbe_GetSock(sp, PF_INET6);
		bcopy(bp->ipv6, &vc->sa, bp->ipv6len);
		vc->salen = bp->ipv6len;
	}

	TCP_nonblocking(s);
	if (params->tcp_nodelay)
		TCP_nodelay(s);
#if defined(__linux__)
	if (params->tcp_quickack)
		TCP_quickack(s);
#endif

	if (bp->ssl_ctx != NULL) {
		vc->vc_ssl = SSL_new(bp->ssl_ctx);
		AN(vc->vc_ssl);
		SSL_set_connect_state(vc->vc_ssl);
		ret = SSL_set_fd(vc->vc_ssl, s);
		assert(ret == 1);
	}

	if (s < 0) {
		Lck_Lock(&bp->mtx);
		bp->n_conn--;
		bp->refcount--;		/* Only keep ref on success */
		Lck_Unlock(&bp->mtx);
	}
	return (s);
}

/*--------------------------------------------------------------------
 * Check that there is still something at the far end of a given socket.
 * We poll the fd with instant timeout, if there are any events we can't
 * use it (backends are not allowed to pipeline).
 */

static int
vbe_CheckFd(int fd)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	return(poll(&pfd, 1, 0) == 0);
}

/*--------------------------------------------------------------------
 * Manage a pool of vbe_conn structures.
 * XXX: as an experiment, make this caching controled by a parameter
 * XXX: so we can see if it has any effect.
 */

static struct vbe_conn *
vbe_NewConn(void)
{
	struct vbe_conn *vc;

	vc = VTAILQ_FIRST(&vbe_conns);
	if (vc != NULL) {
		Lck_Lock(&VBE_mtx);
		vc = VTAILQ_FIRST(&vbe_conns);
		if (vc != NULL) {
			VSL_stats->backend_unused--;
			VTAILQ_REMOVE(&vbe_conns, vc, list);
		}
		Lck_Unlock(&VBE_mtx);
	}
	if (vc != NULL)
		return (vc);
	vc = calloc(sizeof(union vbe_mem), 1);
	XXXAN(vc);
	vc->common.magic = VBE_COMMON_MAGIC;
	vc->magic = VBE_CONN_MAGIC;
	vc->vc_fd = -1;
	vc->vc_ssl = NULL;
	Lck_Lock(&VBE_mtx);
	VSL_stats->n_vbe_conn++;
	Lck_Unlock(&VBE_mtx);
	return (vc);
}


/*--------------------------------------------------------------------
 * It evaluates if a backend is healthy _for_a_specific_object_.
 * That means that it relies on sp->objhead. This is mainly for saint-mode,
 * but also takes backend->healthy into account. If
 * params->saintmode_threshold is 0, this is basically just a test of
 * backend->healthy.
 *
 * The threshold has to be evaluated _after_ the timeout check, otherwise
 * items would never time out once the threshold is reached.
 */

static unsigned int
vbe_Healthy(double now, uintptr_t target, struct backend *backend)
{
	struct trouble *tr;
	struct trouble *tr2;
	struct trouble *old;
	unsigned i = 0, retval;
	unsigned int threshold;

	CHECK_OBJ_NOTNULL(backend, BACKEND_MAGIC);

	if (!backend->healthy)
		return (0);

	/* VRT/VCC sets threshold to UINT_MAX to mark that it's not
	 * specified by VCL (thus use param).
	 */
	if (backend->saintmode_threshold == UINT_MAX)
		threshold = params->saintmode_threshold;
	else
		threshold = backend->saintmode_threshold;

	/* Saintmode is disabled */
	if (threshold == 0)
		return (1);

	/* No need to test if we don't have an object head to test against.
	 * FIXME: Should check the magic too, but probably not assert?
	 */
	if (target == 0)
		return (1);

	old = NULL;
	retval = 1;
	Lck_Lock(&backend->mtx);
	VTAILQ_FOREACH_SAFE(tr, &backend->troublelist, list, tr2) {
		CHECK_OBJ_NOTNULL(tr, TROUBLE_MAGIC);

		if (tr->timeout < now) {
			VTAILQ_REMOVE(&backend->troublelist, tr, list);
			old = tr;
			retval = 1;
			break;
		}

		if (tr->target == target) {
			retval = 0;
			break;
		}

		/* If the threshold is at 1, a single entry on the list
		 * will disable the backend. Since 0 is disable, ++i
		 * instead of i++ to allow this behavior.
		 */
		if (++i >= threshold) {
			retval = 0;
			break;
		}
	}
	Lck_Unlock(&backend->mtx);

	if (old != NULL)
		FREE_OBJ(old);

	return (retval);
}

/*--------------------------------------------------------------------
 * Get a connection to a particular backend.
 */

static struct vbe_conn *
vbe_GetVbe(struct sess *sp, struct backend *bp, enum vbe_type type)
{
	struct vbe_conn *vc, *vctmp;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(bp, BACKEND_MAGIC);

	vbe_handleInAddrAny(sp, bp);

	/* first look for vbe_conn's we can recycle */
	while (1) {
		Lck_Lock(&bp->mtx);
		VTAILQ_FOREACH_SAFE(vc, &bp->connlist, list, vctmp) {
			if (vc->common.type == type &&
			    ((sp->flags & SESS_F_INADDR_ANY) == 0 ||
			     ((sp->flags & SESS_F_INADDR_ANY) != 0 &&
			      (sp->flags & SESS_F_BACKEND_HINT) != 0 &&
			      bcmp(&sp->hint, &vc->sa, vc->salen) == 0))) {
				bp->refcount++;
				assert(vc->backend == bp);
				assert(vc->vc_fd >= 0);
				VTAILQ_REMOVE(&bp->connlist, vc, list);
				break;
			}
		}
		Lck_Unlock(&bp->mtx);
		if (vc == NULL)
			break;
		if (vbe_CheckFd(vc->vc_fd)) {
			/* XXX locking of stats */
			VSL_stats->backend_reuse += 1;
			WSP(sp, SLT_Backend, "%d %s %s",
			    vc->vc_fd, sp->director->vcl_name, bp->vcl_name);
			vc->recycled = 1;
			return (vc);
		}
		VSL_stats->backend_toolate++;
		WSL(sp->wrk, SLT_BackendClose, vc->vc_fd, "%s", bp->vcl_name);

		/* Checkpoint log to flush all info related to this connection
		   before the OS reuses the FD */
		WSL_Flush(sp->wrk, 0);

		XXL_free(&vc->vc_ssl);
		TCP_close(&vc->vc_fd);
		VBE_DropRefConn(bp);
		vc->backend = NULL;
		VBE_ReleaseConn(vc);
	}

	if (!vbe_Healthy(sp->t_req, (uintptr_t)sp->objhead, bp)) {
		VSL_stats->backend_unhealthy++;
		return (NULL);
	}

	if (bp->max_conn > 0 && bp->n_conn >= bp->max_conn) {
		VSL_stats->backend_busy++;
		return (NULL);
	}

	vc = vbe_NewConn();
	vc->common.type = type;
	assert(vc->vc_fd == -1);
	AZ(vc->backend);
	vc->backend = bp;
	VSL_stats->backend_conn++;
	WSP(sp, SLT_Backend, "%s %s",
	    sp->director->vcl_name, bp->vcl_name);
	return (vc);
}

/* Close a connection ------------------------------------------------*/

void
VBE_CloseFd(struct sess *sp, struct vbe_conn **vc_orig, int recycle)
{
	struct backend *bp;
	struct vbe_conn *vc = *vc_orig;

	CHECK_OBJ_NOTNULL(vc, VBE_CONN_MAGIC);
	CHECK_OBJ_NOTNULL(vc->backend, BACKEND_MAGIC);
	assert(vc->vc_fd >= 0);

	if (recycle) {
		assert(sp->vc == vc);
		vbe_RecycleFd(sp);
		return;
	}

	bp = vc->backend;

	WSL(sp->wrk, SLT_BackendClose, vc->vc_fd, "%s", bp->vcl_name);

	/* Checkpoint log to flush all info related to this connection
	   before the OS reuses the FD */
	WSL_Flush(sp->wrk, 0);

	XXL_free(&vc->vc_ssl);
	TCP_close(&vc->vc_fd);
	VBE_DropRefConn(bp);
	vc->backend = NULL;
	VBE_ReleaseConn(vc);
	*vc_orig = NULL;
}

/* Recycle a connection ----------------------------------------------*/

static void
vbe_RecycleFd(struct sess *sp)
{
	struct backend *bp;

	CHECK_OBJ_NOTNULL(sp->vc, VBE_CONN_MAGIC);
	CHECK_OBJ_NOTNULL(sp->vc->backend, BACKEND_MAGIC);
	assert(sp->vc->vc_fd >= 0);

	bp = sp->vc->backend;

	WSL(sp->wrk, SLT_BackendReuse, sp->vc->vc_fd, "%s", bp->vcl_name);
	/*
	 * Flush the shmlog, so that another session reusing this backend
	 * will log chronologically later than our use of it.
	 */
	WSL_Flush(sp->wrk, 0);
	Lck_Lock(&bp->mtx);
	VSL_stats->backend_recycle++;
	VTAILQ_INSERT_HEAD(&bp->connlist, sp->vc, list);
	sp->vc = NULL;
	VBE_DropRefLocked(bp);
}

/* Get a connection --------------------------------------------------*/

struct vbe_conn *
VBE_GetConn(const struct director *d, struct sess *sp, enum vbe_type type)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	if (d == NULL)
		d = sp->director;
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	return (d->getconn(d, sp, type));
}

/* Check health ------------------------------------------------------
 *
 * The target is really an objhead pointer, but since it can not be
 * dereferenced during health-checks, we pass it as uintptr_t, which
 * hopefully will make people investigate, before mucking about with it.
 */

int
VBE_Healthy_sp(const struct sess *sp, const struct director *d)
{

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	return (d->healthy(sp->t_req, d, (uintptr_t)sp->objhead));
}

int
VBE_Healthy(double now, const struct director *d, uintptr_t target)
{

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	return (d->healthy(now, d, target));
}

/*--------------------------------------------------------------------
 * The "simple" director really isn't, since thats where all the actual
 * connections happen.  Nontheless, pretend it is simple by sequestering
 * the directoricity of it under this line.
 */

struct vdi_simple {
	unsigned		magic;
#define VDI_SIMPLE_MAGIC	0x476d25b7
	struct director		dir;
	struct backend		*backend;
};

/* Returns the backend if and only if the this is a simple director.
 * XXX: Needs a better name and possibly needs a better general approach.
 * XXX: This is mainly used by the DNS director to fetch the actual backend
 * XXX: so it can compare DNS lookups with the actual IP.
 */
struct backend *
vdi_get_backend_if_simple(const struct director *d)
{
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	struct vdi_simple *vs, *vs2;

	vs2 = d->priv;
	if (vs2->magic != VDI_SIMPLE_MAGIC)
		return NULL;
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_SIMPLE_MAGIC);
	return vs->backend;
}

static struct vbe_conn *
vdi_simple_getconn(const struct director *d, struct sess *sp,
    enum vbe_type type)
{
	struct vdi_simple *vs;
	struct vbe_conn *vc;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_SIMPLE_MAGIC);
	vc = vbe_GetVbe(sp, vs->backend, type);
	if (vc != NULL) {
		FIND_TMO(first_byte_timeout,
		    vc->first_byte_timeout, sp, vc->backend);
		FIND_TMO(between_bytes_timeout,
		    vc->between_bytes_timeout, sp, vc->backend);
	}
	return (vc);
}

static unsigned
vdi_simple_healthy(double now, const struct director *d, uintptr_t target)
{
	struct vdi_simple *vs;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_SIMPLE_MAGIC);
	return (vbe_Healthy(now, target, vs->backend));
}

/*lint -e{818} not const-able */
static void
vdi_simple_fini(struct director *d)
{
	struct vdi_simple *vs;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_SIMPLE_MAGIC);

	VBE_DropRef(vs->backend);
	free(vs->dir.vcl_name);
	vs->dir.magic = 0;
	FREE_OBJ(vs);
}

void
VRT_init_dir_simple(struct cli *cli, struct director **bp, int idx,
    const void *priv)
{
	const struct vrt_backend *t;
	struct vdi_simple *vs;

	ASSERT_CLI();
	(void)cli;
	t = priv;

	ALLOC_OBJ(vs, VDI_SIMPLE_MAGIC);
	XXXAN(vs);
	vs->dir.magic = DIRECTOR_MAGIC;
	vs->dir.priv = vs;
	vs->dir.name = "simple";
	REPLACE(vs->dir.vcl_name, t->vcl_name);
	vs->dir.getconn = vdi_simple_getconn;
	vs->dir.fini = vdi_simple_fini;
	vs->dir.healthy = vdi_simple_healthy;

	vs->backend = VBE_AddBackend(cli, t);

	bp[idx] = &vs->dir;
}
