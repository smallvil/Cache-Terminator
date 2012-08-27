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
 * $Id: cache.h 146 2011-04-15 19:58:43Z jwg286 $
 */

/*
 * This macro can be used in .h files to isolate bits that the manager
 * should not (need to) see, such as pthread mutexes etc.
 */
#define VARNISH_CACHE_CHILD	1

#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#if defined(HAVE_EPOLL_CTL)
#include <sys/epoll.h>
#endif
#if defined(HAVE_KQUEUE)
#include <sys/event.h>
#endif

#if defined(HAVE_GEOIP)
#include <GeoIP.h>
#endif

#include "vqueue.h"

#include "vsb.h"

#include "libvarnish.h"

#include "common.h"
#include "heritage.h"
#include "miniobj.h"
#include "vsha256.h"
#include "vtypes.h"

enum {
	/* Fields from the first line of HTTP proto */
	HTTP_HDR_REQ,
	HTTP_HDR_URL,
	HTTP_HDR_PROTO,
	HTTP_HDR_STATUS,
	HTTP_HDR_RESPONSE,
	/* HTTP header lines */
	HTTP_HDR_FIRST,
};

enum sess_status {
	SESS_CONTINUE = 0,
	SESS_DONE,
	SESS_SLEEP,
	SESS_WAIT
};

enum pipe_status {
	PIPE_CONTINUE = 0,
	PIPE_DONE,
	PIPE_SLEEP,
	PIPE_WAIT
};

enum fetch_status {
	FETCH_CONTINUE = 0,
	FETCH_DONE,
	FETCH_SLEEP,
	FETCH_WAIT
};

struct cli;
struct vsb;
struct sess;
struct director;
struct object;
struct objhead;
struct objcore;
struct vrt_backend;
struct cli_proto;
struct ban;
struct SHA256Context;
struct pipe;
struct fetch;

struct smp_object;
struct smp_seg;

struct lock { void *priv; };		// Opaque

#define DIGEST_LEN		32


/*--------------------------------------------------------------------
 * Pointer aligment magic
 */

#define PALGN		(sizeof(void *) - 1)
#define PAOK(p)		(((uintptr_t)(p) & PALGN) == 0)
#define PRNDDN(p)	((uintptr_t)(p) & ~PALGN)
#define PRNDUP(p)	(((uintptr_t)(p) + PALGN) & ~PALGN)

/*--------------------------------------------------------------------*/

typedef struct {
	char			*b;
	char			*e;
} txt;

/*--------------------------------------------------------------------*/

enum step {
#define STEP(l, u)	STP_##u,
#include "steps.h"
#undef STEP
};

enum pipestep {
#define PIPESTEP(l, u)	PIE_##u,
#include "pipesteps.h"
#undef PIPESTEP
};

enum fetchstep {
#define FETCHSTEP(l, u)	FET_##u,
#include "fetchsteps.h"
#undef FETCHSTEP
};

/*--------------------------------------------------------------------
 * Workspace structure for quick memory allocation.
 */

struct ws {
	unsigned		magic;
#define WS_MAGIC		0x35fac554
	const char		*id;		/* identity */
	char			*s;		/* (S)tart of buffer */
	char			*f;		/* (F)ree pointer */
	char			*r;		/* (R)eserved length */
	char			*e;		/* (E)nd of buffer */
	int			overflow;	/* workspace overflowed */
};

/*--------------------------------------------------------------------
 * HTTP Request/Response/Header handling structure.
 */

enum httpwhence {
	HTTP_Rx	 = 1,
	HTTP_Tx  = 2,
	HTTP_Obj = 3
};

/* NB: remember to update http_Copy() if you add fields */
struct http {
	unsigned		magic;
#define HTTP_MAGIC		0x6428b5c9

	struct ws		*ws;

	unsigned char		conds;		/* If-* headers present */
	enum httpwhence		logtag;
	int			status;
	double			protover;

	unsigned		shd;		/* Size of hd space */
	txt			*hd;
	unsigned char		*hdf;
#define HDF_FILTER		(1 << 0)	/* Filtered by Connection */
#define HDF_COPY		(1 << 1)	/* Copy this field */
	unsigned		nhd;		/* Next free hd */
};

/*--------------------------------------------------------------------*/

struct conn_fds {
	int			fd;
	SSL			*ssl;
	int			want;
};

/*--------------------------------------------------------------------
 * HTTP Protocol connection structure
 */

struct http_conn {
	unsigned		magic;
#define HTTP_CONN_MAGIC		0x3e19edd1
	struct conn_fds		fds;
#define	htc_fd			fds.fd
#define	htc_ssl			fds.ssl
#define	htc_want		fds.want
	struct ws		*ws;
	txt			rxbuf;
	txt			pipeline;
};

/*--------------------------------------------------------------------
 * SOCKS Protocol connection structure
 */

#define	SOCKS_VER4		0x4
#define	SOCKS_VER5		0x5
#define	SOCKSv4_C_CONNECT	0x1	/* CONNECT command */
#define	SOCKSv4_C_BIND		0x2	/* BIND command */
#define	SOCKSv4_S_GRANTED	0x5a
#define	SOCKSv4_S_REJECTED	0x5b
#define	SOCKSv5_C_CONNECT	0x1	/* CONNECT command */
#define	SOCKSv5_C_BIND		0x2	/* BIND command */
#define	SOCKSv5_C_UDP_ASSOCIATE	0x3	/* UDP_ASSOCIATE command */
#define	SOCKSv5_S_SUCCESS	0x0	/* succeeded */
#define	SOCKSv5_S_SOCKS_FAIL	0x1	/* general SOCKS server failure */
#define	SOCKSv5_S_NOCONNALLOWED	0x2	/* connection not allowed by ruleset */
#define	SOCKSv5_S_NUNREACHABLE	0x3	/* Network unreachable */
#define	SOCKSv5_S_HUNREACHABLE	0x4	/* Host unreachable */
#define	SOCKSv5_S_CONNREFUSED	0x5	/* Connection refused */
#define	SOCKSv5_S_TTLEXPIRED	0x6	/* TTL expired */
#define	SOCKSv5_S_NOCMDSUPPORT	0x7	/* Command not supported */
#define	SOCKSv5_S_NOADDRSUPPORT	0x8	/* Address type not supported */
#define	SOCKSv5_I_IPV4		0x1	/* IP V4 address */
#define	SOCKSv5_I_DOMAINNAME	0x3	/* DOMAINNAME */
#define	SOCKSv5_I_IPV6		0x4	/* IP V6 address */
#define	SOCKSv5_A_NOAUTH	0x0	/* NO AUTHENTICATION REQUIRED */
#define	SOCKSv5_A_GSSAPI	0x1	/* GSSAPI */
#define	SOCKSv5_A_USERPW	0x2	/* USERNAME / PASSWORD */
#define	SOCKSv5_A_NOACCEPTABLE	0xff	/* NO ACCEPTABLE METHODS */

/* packet sequence */
#define	SOCKS_T_V4REQ_OR_V5AUTH	0
#define	SOCKS_T_V5REQ		1

struct socks_conn {
	unsigned		magic;
#define SOCKS_CONN_MAGIC	0x848977c4

	int			fd;
	struct ws		*ws;
	txt			rxbuf;
	txt			pipeline;
};

struct socksv4_resp {
	uint8_t			nullbyte;
	uint8_t			status;
	uint16_t		rsv1;
	uint32_t		rsv2;
} __attribute__ ((packed));

struct socksv5_authresp {
	uint8_t			ver;
	uint8_t			method;
} __attribute__ ((packed));

/*--------------------------------------------------------------------
 * TUNNELing related headers
 */

#define	TUNNEL_ERROR_CONNECT	0x1

/*--------------------------------------------------------------------*/

struct acct {
	double			first;
#define ACCT(foo)	uint64_t	foo;
#include "acct_fields.h"
#undef ACCT
};

/*--------------------------------------------------------------------*/

#define L0(n)
#define L1(n)			int n;
#define MAC_STAT(n, t, l, f, e)	L##l(n)
struct dstat {
#include "stat_field.h"
};
#undef MAC_STAT
#undef L0
#undef L1

/*--------------------------------------------------------------------*/

VTAILQ_HEAD(callout_tailq, callout);

/* XXX FIXME: has a assumption that CLOCKS_PER_SEC is 100 */
#define	CALLOUT_MSTOTICKS(ms)	((ms) / 10)
#define	CALLOUT_SECTOTICKS(sec)	((sec) * 100)
#define	CALLOUT_ACTIVE		0x0002	/* callout is currently active */
#define	CALLOUT_PENDING		0x0004	/* callout is waiting for timeout */

struct callout {
	unsigned	magic;
#define	CALLOUT_MAGIC	0x2d634820
	union {
		VSLIST_ENTRY(callout) sle;
		VTAILQ_ENTRY(callout) tqe;
	} c_links;
	clock_t	c_time;			/* XXX: ticks to the event */
	void	*c_arg;			/* function argument */
	void	(*c_func)(void *);	/* function to call */
	int	c_flags;		/* state of this entry */
	int	c_id;			/* XXX: sp->id.  really need? */
#ifdef VARNISH_DEBUG
	const char *d_func;		/* func name of caller */
	int	d_line;			/* line num of caller */
#endif
};

struct callout_block {
	clock_t		ticks;
	clock_t		softticks;	/* Like ticks, but for COT_clock(). */
	int		ncallout;	/* maximum # of timer events */
	int		callwheelsize;
	int		callwheelbits;
	int		callwheelmask;
	struct callout_tailq *callwheel;
	struct callout *nextsoftcheck;	/* Next callout to be checked. */
};

/*--------------------------------------------------------------------*/

struct worker {
	unsigned		magic;
#define WORKER_MAGIC		0x6391adcf
	struct objhead		*nobjhead;
	struct objcore		*nobjcore;
	void			*nhashpriv;
	struct dstat		stats;

	double			lastused;

	pthread_cond_t		cond;

	VTAILQ_ENTRY(worker)	list;
	struct septum		*septum;

	unsigned char		*wlb, *wlp, *wle;
	unsigned		wlr;

	/* Timeouts */
	double			connect_timeout;
	double			first_byte_timeout;
	double			between_bytes_timeout;

	struct callout_block	cb;

	/*
	 * This file descriptor manages all events on the state machine which
	 * points to the client side except the pipe operations.
	 */
	int			fd;		/* EP: fd for epoll */
	int			nsocket;	/* EP: num of waiting sockets */

	int			readypipe[2];
	struct lock		readylist_mtx;
	VTAILQ_HEAD(, septum)	readylist;
	unsigned		nreadylist;
	unsigned		nwaiting;
};

/* Storage -----------------------------------------------------------*/

struct storage {
	unsigned		magic;
#define STORAGE_MAGIC		0x1a4e51c0
	VTAILQ_ENTRY(storage)	list;
	struct stevedore	*stevedore;
	void			*priv;

	unsigned char		*ptr;
	ssize_t			len;
	ssize_t			space;

	int			fd;
	off_t			where;
};

/* Object core structure ---------------------------------------------
 * Objects have sideways references in the binary heap and the LRU list
 * and we want to avoid paging in a lot of objects just to move them up
 * or down the binheap or to move a unrelated object on the LRU list.
 * To avoid this we use a proxy object, objcore, to hold the relevant
 * housekeeping fields parts of an object.
 */

struct objcore {
	unsigned		magic;
#define OBJCORE_MAGIC		0x4d301302
	unsigned		refcnt;
	struct object		*obj;
	struct objhead		*objhead;
	double			timer_when;
	unsigned		flags;
#define OC_F_ONLRU		(1<<0)
#define OC_F_BUSY		(1<<1)
#define OC_F_PASS		(1<<2)
#define OC_F_PERSISTENT		(1<<3)
#define OC_F_LRUDONTMOVE	(1<<4)
	unsigned		timer_idx;
	VTAILQ_ENTRY(objcore)	list;
	VLIST_ENTRY(objcore)	lru_list;
	VTAILQ_ENTRY(objcore)	ban_list;
	struct smp_seg		*smp_seg;
	struct ban		*ban;
};

/*--------------------------------------------------------------------*/

struct lru {
	unsigned		magic;
#define LRU_MAGIC		0x3fec7bb0
	VLIST_HEAD(,objcore)	lru_head;
	struct objcore		senteniel;
};

/* Object structure --------------------------------------------------*/

struct object {
	unsigned		magic;
#define OBJECT_MAGIC		0x32851d42
	unsigned		xid;
	unsigned		flags;
#define	OBJECT_F_DONE		0x1
#define	OBJECT_F_ERROR		0x2
#define	OBJECT_F_CACHEABLE	0x4
#define	OBJECT_F_ZEROLEN	0x8
#define	OBJECT_F_EOF		0x10
	struct storage		*objstore;
	struct objcore		*objcore;

	unsigned		smp_index;

	struct ws		ws_o[1];
	unsigned char		*vary;

	double			ban_t;
	struct ban		*ban;	/* XXX --> objcore */
	unsigned		response;

	ssize_t			len;

	double			ttl;
	double			age;
	double			entered;
	double			grace;

	double			last_modified;
	double			last_lru;

	struct http		*http;

	VTAILQ_HEAD(, storage)	store;

	double			last_use;

	int			hits;
};

/* -------------------------------------------------------------------*/

#define	SEPTUM_WANT_READ	0x1
#define	SEPTUM_WANT_WRITE	0x2
#define	SEPTUM_EVENT(_st, _wrk, _fd, _events, _func, _arg, _timeout) do { \
	(_st)->fd = (_fd);						\
	(_st)->events = (_events);					\
	callout_reset((_wrk), &(_st)->co, (_timeout), (_func), (_arg));	\
} while (0)
#define	SEPTUM_SESSEVENT(_sp, _fd, _events, _timeout)	do {		\
	(_sp)->septum.type = SEPTUM_SESS;				\
	(_sp)->septum.arg = (_sp);					\
	SEPTUM_EVENT(&(_sp)->septum, (_sp)->wrk, (_fd), (_events),	\
	    CNT_SessionTimeout, (_sp), (_timeout));			\
} while (0)
#define	SEPTUM_PIPEEVENT(_dp, _fd, _events, _timeout)	do {		\
	(_dp)->septum.type = SEPTUM_PIPE;				\
	(_dp)->septum.arg = (_dp);					\
	SEPTUM_EVENT(&(_dp)->septum, (_dp)->wrk, (_fd), (_events),	\
	    PIE_SessionTimeout, (_dp), (_timeout));			\
} while (0)
#define	SEPTUM_FETCHEVENT(_fp, _fd, _events, _timeout)	do {		\
	(_fp)->septum.type = SEPTUM_FETCH;				\
	(_fp)->septum.arg = (_fp);					\
	SEPTUM_EVENT(&(_fp)->septum, (_fp)->wrk, (_fd), (_events),	\
	    FET_SessionTimeout, (_fp), (_timeout));			\
} while (0)
/*
 * XXX the following macros are very easy to be confused because the variable
 * names are too common.  So please uses very carefully or defines these
 * variables for each macros separately.
 */
/* OFFSET - read or written bytes (tmp var) */
#define	SEPTUM_SOFFSET(_st, _v)	(_st)->var[0] = (_v)
#define	SEPTUM_GOFFSET(_st)	((_st)->var[0])
#define	SEPTUM_SLOW(_st, _v)	(_st)->buflen[0] = (_v)
#define	SEPTUM_GLOW(_st)	((_st)->buflen[0])
#define	SEPTUM_SHIGH(_st, _v)	(_st)->buflen[1] = (_v)
#define	SEPTUM_GHIGH(_st)	((_st)->buflen[1])
/* CL -> Content Length */
#define	SEPTUM_SCL(_st, _v)	(_st)->var[1] = (_v)
#define	SEPTUM_GCL(_st)		((_st)->var[1])
#define	SEPTUM_SBUF(_st, _v)	(_st)->buf[0] = (_v)
#define	SEPTUM_GBUF(_st)	((_st)->buf[0])
#define	SEPTUM_SBUFLEN(_st, _v)	(_st)->buflen[0] = (_v)
#define	SEPTUM_GBUFLEN(_st)	((_st)->buflen[0])
/* SL -> Storage Length (st->len) for fetch sm */
#define	SEPTUM_SSL(_st, _v)	SEPTUM_SBUFLEN(_st, _v)
#define	SEPTUM_GSL(_st)		SEPTUM_GBUFLEN(_st)
/* PTR -> char * */
#define	SEPTUM_SPTR(_st, _v)	SEPTUM_SBUF(_st, _v)
#define	SEPTUM_GPTR(_st)	((char *)SEPTUM_GBUF(_st))
/* ST -> struct storage * */
#define	SEPTUM_SST(_st, _v) 	((_st)->buf[1] = (void *)(_v))
#define	SEPTUM_GST(_st)		((_st)->buf[1])
/* NUMPTR -> only for chunked encoding; a tmp buffer to store the CL string */
#define	SEPTUM_SNUMBUF(_st, _v)	((_st)->buf[2] = (void *)(_v))
#define	SEPTUM_GNUMBUF(_st)	((char *)(_st)->buf[2])
#define	SEPTUM_SNUMBUFLEN(_st, _v) (_st)->buflen[1] = (_v)
#define	SEPTUM_GNUMBUFLEN(_st)	((_st)->buflen[1])
struct septum {
	unsigned		type;
#define	SEPTUM_SESS		1
#define	SEPTUM_PIPE		2
#define	SEPTUM_FETCH		3
#define	SEPTUM_READYPIPE	4
	/*
	 * `struct sess *arg' if TYPE is SEPTUM_SESS.
	 * `struct pipe *arg' if TYPE is SEPTUM_PIPE.
	 * `struct fetch *arg' if TYPE is SEPTUM_FETCH.
	 */
	void			*arg;
	struct callout		co;
	int			fd;
	int			events;
#if defined(HAVE_EPOLL_CTL)
	struct epoll_event	ev;
#elif defined(HAVE_KQUEUE)
	struct kevent		ev;
#else
#error "unsupported event model"
#endif
	void			*buf[3];	/* tmpbuf pointer variable */
	ssize_t			buflen[3];	/* tmpbuf length variable */
	ssize_t			var[2];		/* tmpvar */
	VTAILQ_ENTRY(septum)	list;
};

/* -------------------------------------------------------------------*/

#define	SESS_ERROR(sp, code, reason)	do {	\
	(sp)->flags |= SESS_F_ERROR;		\
	(sp)->err_code = (code);		\
	(sp)->err_reason = (reason);		\
} while (0)

struct sess {
	unsigned		magic;
#define SESS_MAGIC		0x2c2f9c5a
	struct conn_fds		fds;
#define	sp_fd			fds.fd
#define	sp_ssl			fds.ssl
#define	sp_want			fds.want
	int			id;
	unsigned		xid;

	unsigned		flags;
#define	SESS_F_ERROR		0x00000001
#define	SESS_F_PASS		0x00000002
#define	SESS_F_WANTBODY		0x00000004
#define	SESS_F_SENDBODY		0x00000008
#define	SESS_F_CACHEABLE	0x00000010
#define	SESS_F_CLOSE		0x00000020
#define	SESS_F_MKLEN		0x00000040
#define	SESS_F_HASH_IGNORE_BUSY	0x00000080
#define	SESS_F_HASH_ALWAYS_MISS	0x00000100
#define	SESS_F_NEEDOBJREL	0x00000200
#define	SESS_F_RANGE		0x00000400
#define	SESS_F_INADDR_ANY	0x00000800
#define	SESS_F_BACKEND_HINT	0x00001000
#define	SESS_F_NOFLUSHREQ	0x00002000
#define	SESS_F_QUICKABORT	0x00004000
#define	SESS_T_HTTP		0x00010000
#define	SESS_T_SOCKS		0x00020000
#define	SESS_T_TUNNEL		0x00040000
#define	SESS_F_REQBODY		0x00080000	/* if the req includes body */
	struct septum		septum;

	int			restarts;

	struct worker		*wrk;

	socklen_t		sockaddrlen;
	socklen_t		mysockaddrlen;
	struct sockaddr		*sockaddr;
	struct sockaddr		*mysockaddr;
	struct listen_sock	*mylsock;

	/* formatted ascii client address */
	char			*addr;
	char			*port;
	char			*client_identity;

	/* HTTP request */
	const char		*doclose;
	struct http		*http;
	struct http		*http0;

	struct ws		ws[1];
	char			*ws_ses;	/* WS above session data */
	char			*ws_req;	/* WS above request data */
	char			*ws_fet;

	unsigned char		digest[DIGEST_LEN];

	struct http_conn	htc[1];

	/* Timestamps, all on TIM_real() timescale */
	double			t_open;
	double			t_req;
	double			t_resp;
	double			t_end;
	double			t_last;		/* used for TCP_INFO output */

	/* Acceptable grace period */
	double			grace;

#ifdef VARNISH_DEBUG
#define	STEPHIST_MAX		256
	enum step		stephist[STEPHIST_MAX];
	int			stephist_cur;
#endif
	enum step		step;
	unsigned		cur_method;
	unsigned		handling;
	int			err_code;
	const char		*err_reason;

	VTAILQ_ENTRY(sess)	list;

	struct sockaddr_storage	hint;		/* for backend 192.168.0.0/24 */
	socklen_t		hintlen;
	struct director		*director;
	struct vbe_conn		*vc;
	struct object		*obj;
	struct objcore		*objcore;
	struct objhead		*objhead;
	struct VCL_conf		*vcl;
	struct geo_conf		*geoip;

	/* Various internal stuff */
	struct sessmem		*mem;

	struct acct		acct_tmp;
	struct acct		acct_req;
	struct acct		acct_ses;

#if defined(HAVE_EPOLL_CTL)
	/*
	 * XXX it's only for herding handle but need to take some time that
	 * it's really needed at non-blocking IO model.
	 */
	struct epoll_event	ev;
#endif

	/* for Range support */
	unsigned		*range;
	unsigned		nrange;

	struct {
		struct http		*http[3];
		struct http		*resp;
		struct http		*bereq;
		struct http		*beresp;
		struct http		*beresp1;

		struct SHA256Context	sha256ctx;

		int			*wfd;
		SSL			**ssl;
		struct iovec		*iov;	/* points the first entry */
		unsigned		siov;	/* num of alloc IOV entries */
		unsigned		niov;	/* total IOV entries added */
		ssize_t			liov;	/* total IOV buffer length */
		struct http_conn	htc[1];
		enum body_status	body_status;
		double			age;
		double			entered;
		double			ttl;
		double			grace;
	} wrkvar;

	struct {
		struct socks_conn	stc[1];
		char			*domainname;
		struct sockaddr		sockaddr;
		socklen_t		sockaddrlen;
		struct socksv4_resp	resp;
	} socks;
};

/* -------------------------------------------------------------------*/

enum vbe_type {
	VBE_TYPE_PIPE = 1,
	VBE_TYPE_FETCH
};

struct vbe_common {
	unsigned		magic;
#define	VBE_COMMON_MAGIC	0x6108f13f
	enum vbe_type		type;
};

/* Backend connection */
struct vbe_conn {
	struct vbe_common	common;	/* MUST BE FIRST */
	unsigned		magic;
#define VBE_CONN_MAGIC		0x0c5e6592
	VTAILQ_ENTRY(vbe_conn)	list;
	struct backend		*backend;
	struct sockaddr_storage	sa;	/* sockaddr info using for fd */
	socklen_t		salen;
	struct conn_fds		fds;
#define	vc_fd			fds.fd
#define	vc_ssl			fds.ssl
#define	vc_want			fds.want
	uint8_t			recycled;

	/* Timeouts */
	double			first_byte_timeout;
	double			between_bytes_timeout;
};

/* -------------------------------------------------------------------*/

#define	CAST_PIPE_NOTNULL(to, from, type_magic)	do {		\
	struct vbe_conn *_vc;					\
	(to) = (struct pipe *)(from);				\
	assert((to) != NULL);					\
	CAST_OBJ_NOTNULL(_vc, &(to)->vc, VBE_CONN_MAGIC);	\
	CHECK_OBJ_NOTNULL(&((_vc)->common), VBE_COMMON_MAGIC);	\
	assert((_vc)->common.type == VBE_TYPE_PIPE);		\
	CHECK_OBJ(to, type_magic);				\
} while (0)

struct pipe {
	struct vbe_conn		vc;	/* MUST BE FIRST */
	unsigned		magic;
#define	PIPE_MAGIC		0x23891018
	unsigned		flags;
#define	PIPE_F_STARTED		0x1	/* set when PIPE SM is started */
#define	PIPE_F_SESSDONE		0x2	/* sp->fd --> vbe->fd completed */
#define	PIPE_F_PIPEDONE		0x4	/* vbe->fd --> sp->fd completed */
	struct worker		*wrk;
	struct sess		*sess;
	enum pipestep		step;
#ifdef VARNISH_DEBUG
	enum pipestep		stephist[STEPHIST_MAX];
	int			stephist_cur;
#endif
	struct septum		septum;
	/*
	 * needs 2 buffers; one for client another for backend.  These buffer
	 * space comes from WS.
	 */
	char			*buf[2];
	ssize_t			bufsize;	/* allocated buffer size */
	ssize_t			buflen[2];
	ssize_t			bufoffset[2];
	double			t_last;

	char			addr[TCP_ADDRBUFSIZE];
	char			port[TCP_PORTBUFSIZE];
};

/* -------------------------------------------------------------------*/

#define	CAST_FETCH_NOTNULL(to, from, type_magic)	do {	\
	struct vbe_conn *_vc;					\
	(to) = (struct fetch *)(from);				\
	assert((to) != NULL);					\
	CAST_OBJ_NOTNULL(_vc, &(to)->vc, VBE_CONN_MAGIC);	\
	CHECK_OBJ_NOTNULL(&((_vc)->common), VBE_COMMON_MAGIC);	\
	assert((_vc)->common.type == VBE_TYPE_FETCH);		\
	CHECK_OBJ(to, type_magic);				\
} while (0)

struct fetch {
	struct vbe_conn		vc;	/* MUST BE FIRST AT THIS MOMENT */
	unsigned		magic;
#define	FETCH_MAGIC		0x03091910
	unsigned		flags;
#define	FETCH_F_WANTWAKEUP	0x1
	struct worker		*wrk;
	struct sess		*sess;
	enum fetchstep		step;
#ifdef VARNISH_DEBUG
	enum fetchstep		stephist[STEPHIST_MAX];
	int			stephist_cur;
#endif
	struct septum		septum;
};

/* -------------------------------------------------------------------*/

union vbe_mem {
	struct vbe_common	common;
	struct vbe_conn		vc;
	struct pipe		pipe;
	struct fetch		fetch;
};

/* Prototypes etc ----------------------------------------------------*/

/* cache_acceptor.c */
void vca_return_session(struct sess *sp);
void vca_close_session(struct sess *sp, const char *why);
void VCA_Prep(struct sess *sp);
void VCA_Init(void);
void VCA_Shutdown(void);
const char *VCA_waiter_name(void);
extern pthread_t *VCA_thread;

/* cache_backend.c */

struct vbe_conn *VBE_GetConn(const struct director *, struct sess *sp,
    enum vbe_type type);
int VBE_Healthy(double now, const struct director *, uintptr_t target);
int VBE_Healthy_sp(const struct sess *sp, const struct director *);
void VBE_CloseFd(struct sess *sp, struct vbe_conn **vbe_orig, int recycle);
void VBE_RecycleFd(struct sess *sp);
void VBE_AddHostHeader(const struct sess *sp);
void VBE_Poll(void);
int VBE_GetSocket(struct sess *sp, struct vbe_conn *vbe);

/* cache_backend_cfg.c */
void VBE_Init(void);
struct backend *VBE_AddBackend(struct cli *cli, const struct vrt_backend *vb);

/* cache_backend_poll.c */
void VBP_Init(void);

/* cache_ban.c */
struct ban *BAN_New(void);
int BAN_AddTest(struct cli *, struct ban *, const char *, const char *,
    const char *);
void BAN_Free(struct ban *b);
void BAN_Insert(struct ban *b);
void BAN_Init(void);
void BAN_NewObj(struct object *o);
void BAN_DestroyObj(struct object *o);
int BAN_CheckObject(struct object *o, const struct sess *sp);
void BAN_Reload(double t0, unsigned flags, const char *ban);
struct ban *BAN_TailRef(void);
void BAN_Compile(void);
struct ban *BAN_RefBan(struct objcore *oc, double t0, const struct ban *tail);
void BAN_Deref(struct ban **ban);

/* cache_callout.c [COT] */
#define	callout_stop(w, c)	_callout_stop_safe(w, c)
void	COT_init(struct worker *);
void	COT_fini(struct worker *);
void	COT_clock(struct worker *);
void	COT_ticks(struct worker *);
void	callout_init(struct callout *, int);
#ifdef VARNISH_DEBUG
#define	callout_reset(w, c, to, func, arg) \
	    _callout_reset(w, c, to, func, arg, __func__, __LINE__)
int	_callout_reset(struct worker *, struct callout *, int,
	    void (*)(void *), void *, const char *, int);
#else
int	callout_reset(struct worker *, struct callout *, int,
	    void (*)(void *), void *);
#endif
int	_callout_stop_safe(struct worker *, struct callout *);

/* cache_center.c [CNT] */
extern const char *cnt_stepstr[];
enum sess_status CNT_Session(struct sess *sp);
void CNT_Init(void);
void CNT_EmitTCPInfo(struct sess *sp, int fd, double *last, const char *prefix,
    const char *addr, const char *port, int force);

/* cache_cli.c [CLI] */
void CLI_Init(void);
void CLI_Run(void);
void CLI_AddFuncs(struct cli_proto *p);
extern pthread_t cli_thread;
#define ASSERT_CLI() do {assert(pthread_self() == cli_thread);} while (0)

/* cache_connfds.c [CFD] */
ssize_t CFD_read(struct conn_fds *cf, void *buf, ssize_t count);
ssize_t CFD_write(struct conn_fds *cf, const void *buf, ssize_t count);

/* cache_expiry.c */
void EXP_Insert(struct object *o);
void EXP_Inject(struct objcore *oc, struct lru *lru, double ttl);
void EXP_Init(void);
void EXP_Rearm(const struct object *o);
int EXP_Touch(const struct object *o);
int EXP_NukeOne(const struct sess *sp, const struct lru *lru);

/* cache_fetch.c */
extern const char *fet_stepstr[];
int FetchHdr(struct sess *sp);
int FetchBody(struct sess *sp);
int FetchReqBody(struct sess *sp);
void FET_Wakeup(struct fetch *fp);
void FET_EventAdd(struct fetch *fp);
void FET_EventDel(struct fetch *fp);
enum fetch_status FET_Session(struct fetch *fp);
void FET_Init(struct sess *sp);

/* cache_geoip.c */
#ifdef HAVE_GEOIP
struct geo_conf;
void GEO_Init(void);
void GEO_Refresh(struct geo_conf **gcc);
void GEO_Rel(struct geo_conf **gcc);
void GEO_Get(struct geo_conf **gcc);
void GEO_Poll(void);
void *GEO_GetPriv(struct geo_conf *gc);
#endif

/* cache_hash.c */
void HSH_Rush(struct sess *sp);
void HSH_Wait(struct sess *sp);

/* cache_http.c */
unsigned HTTP_estimate(unsigned nhttp);
void HTTP_Copy(struct http *to, const struct http * const fm);
struct http *HTTP_create(void *p, unsigned nhttp);
const char *http_StatusMessage(unsigned);
unsigned http_EstimateWS(const struct http *fm, unsigned how, unsigned *nhd);
void HTTP_Init(void);
void http_ClrHeader(struct http *to);
unsigned http_Write(struct sess *sp, const struct http *hp, int resp);
void http_CopyResp(const struct http *to, const struct http *fm);
void http_SetResp(const struct http *to, const char *proto, const char *status,
    const char *response);
void http_FilterFields(struct worker *w, int fd, struct http *to,
    const struct http *fm, unsigned how);
void http_FilterHeader(const struct sess *sp, unsigned how);
void http_PutProtocol(struct worker *w, int fd, const struct http *to,
    const char *protocol);
void http_PutStatus(struct worker *w, int fd, struct http *to, int status);
void http_PutResponse(struct worker *w, int fd, const struct http *to,
    const char *response);
void http_PrintfHeader(struct worker *w, int fd, struct http *to,
    const char *fmt, ...);
void http_SetHeader(struct worker *w, int fd, struct http *to, const char *hdr);
void http_SetH(const struct http *to, unsigned n, const char *fm);
void http_ForceGet(const struct http *to);
void http_Setup(struct http *ht, struct ws *ws);
int http_GetHdr(const struct http *hp, const char *hdr, char **ptr);
int http_GetHdrField(const struct http *hp, const char *hdr,
    const char *field, char **ptr);
int http_GetStatus(const struct http *hp);
const char *http_GetReq(const struct http *hp);
char *http_GetUrl(const struct http *hp);
int http_IsConnectMethod(const struct http *hp);
int http_HdrIs(const struct http *hp, const char *hdr, const char *val);
int http_DissectRequest(struct sess *sp);
int http_DissectResponse(struct worker *w, const struct http_conn *htc,
    struct http *sp);
const char *http_DoConnection(const struct http *hp);
void http_CopyHome(struct worker *w, int fd, const struct http *hp);
void http_Unset(struct http *hp, const char *hdr);
void http_CollectHdr(struct http *hp, const char *hdr);
void http_DumpHdr(const struct http *hp);

/* cache_httpconn.c */
void HTC_Init(struct http_conn *htc, struct ws *ws, int fd, SSL *ssl);
int HTC_Reinit(struct http_conn *htc);
int HTC_Rx(struct http_conn *htc);
int HTC_RxNoCompleteCheck(struct http_conn *htc);
int HTC_Read(struct http_conn *htc, void *d, unsigned len);
int HTC_Complete(struct http_conn *htc);

#define HTTPH(a, b, c, d, e, f, g) extern char b[];
#include "http_headers.h"
#undef HTTPH

/* cache_main.c */
void THR_SetName(const char *name);
const char* THR_GetName(void);
void THR_SetSession(const struct sess *sp);
const struct sess * THR_GetSession(void);

/* cache_lck.c */

/* Internal functions, call only through macros below */
void Lck__Lock(struct lock *lck, const char *p, const char *f, int l);
void Lck__Unlock(struct lock *lck, const char *p, const char *f, int l);
int Lck__Trylock(struct lock *lck, const char *p, const char *f, int l);
void Lck__New(struct lock *lck, const char *w);
void Lck__Assert(const struct lock *lck, int held);

/* public interface: */
void LCK_Init(void);
void Lck_Delete(struct lock *lck);
void Lck_CondWait(pthread_cond_t *cond, struct lock *lck);

#define Lck_New(a) Lck__New(a, #a);
#define Lck_Lock(a) Lck__Lock(a, __func__, __FILE__, __LINE__)
#define Lck_Unlock(a) Lck__Unlock(a, __func__, __FILE__, __LINE__)
#define Lck_Trylock(a) Lck__Trylock(a, __func__, __FILE__, __LINE__)
#define Lck_AssertHeld(a) Lck__Assert(a, 1)
#define Lck_AssertNotHeld(a) Lck__Assert(a, 0)

/* cache_panic.c */
void PAN_Init(void);

/* cache_pipe.c */
extern const char *pie_stepstr[];
void PIE_EventAdd(struct pipe *dp);
void PIE_EventDel(struct pipe *dp);
enum pipe_status PIE_Session(struct pipe *dp);
void PIE_Wakeup(struct pipe *dp);
void PIE_Sleep(struct pipe *dp);
void PipeSession(struct sess *sp);
void PIE_Init(struct sess *sp);

/* cache_pool.c */
void WRK_Init(void);
int WRK_Queue(struct septum *st);
int WRK_QueueSession(struct sess *sp);
void WRK_SumStat(struct worker *w);
void WRK_runsm_sess(struct worker *w, struct sess *sp);
void WRK_runsm_pipe(struct worker *w, struct pipe *dp);
void WRK_runsm_fetch(struct worker *w, struct fetch *fp);

void WRW_Reserve(struct sess *sp, int *fd, SSL **);
unsigned WRW_Flush(struct sess *sp, int *);
unsigned WRW_Write(struct sess *sp, const void *ptr, int len);
unsigned WRW_WriteH(struct sess *sp, const txt *hh, const char *suf);
void WRW_Release(struct sess *sp);

typedef void *bgthread_t(struct sess *, void *priv);
void WRK_BgThread(pthread_t *thr, const char *name, bgthread_t *func,
    void *priv);

/* cache_septum.c */
void SPT_Wakeup(struct worker *w, struct septum *st);
void SPT_EventAdd(int efd, struct septum *st);
void SPT_EventDel(int efd, struct septum *st);

/* cache_session.c [SES] */
void SES_Init(void);
struct sess *SES_New(void);
struct sess *SES_Alloc(void);
void SES_Delete(struct sess *sp);
void SES_Charge(struct sess *sp);
void SES_EventAdd(struct sess *sp);
void SES_EventDel(struct sess *sp);
void SES_RunSM(struct sess *sp);
void SES_Wakeup(struct sess *sp);
void SES_Sleep(struct sess *sp);

/* cache_shmlog.c */
void VSL_Init(void);
#ifdef SHMLOGHEAD_MAGIC
void VSL(enum shmlogtag tag, int id, const char *fmt, ...);
void WSLR(struct worker *w, enum shmlogtag tag, int id, txt t);
void WSL(struct worker *w, enum shmlogtag tag, int id, const char *fmt, ...);
void WSL_Flush(struct worker *w, int overflow);

#define DSL(flag, tag, id, ...)					\
	do {							\
		if (params->diag_bitmap & (flag))		\
			VSL((tag), (id), __VA_ARGS__);		\
	} while (0)

#define WSP(sess, tag, ...)					\
	WSL((sess)->wrk, tag, (sess)->sp_fd, __VA_ARGS__)

#define WSPR(sess, tag, txt)					\
	WSLR((sess)->wrk, tag, (sess)->sp_fd, txt)

#define INCOMPL() do {							\
	VSL(SLT_Debug, 0, "INCOMPLETE AT: %s(%d)", __func__, __LINE__); \
	fprintf(stderr,							\
	    "INCOMPLETE AT: %s(%d)\n",					\
	    (const char *)__func__, __LINE__);				\
	abort();							\
} while (0)
#endif

/* cache_socks.c */
void SCK_Init(struct socks_conn *stc, struct ws *ws, int fd);
int SCK_Rx(struct socks_conn *stc, int);

/* cache_ssl.c */
void XXL_Init(void);
ssize_t XXL_writev(SSL *ssl, const struct iovec *vector, int count);
void XXL_free(SSL **ssl);
void XXL_error(void);

/* cache_response.c */
void RES_BuildHttp(struct sess *sp);
void RES_WriteObjHdr(struct sess *sp);

/* cache_vary.c */
struct vsb *VRY_Create(const struct sess *sp, const struct http *hp);
int VRY_Match(const struct sess *sp, const unsigned char *vary);

/* cache_vcl.c */
void VCL_Init(void);
void VCL_Refresh(struct VCL_conf **vcc);
void VCL_Rel(struct VCL_conf **vcc);
void VCL_Get(struct VCL_conf **vcc);
void VCL_Poll(void);

#define VCL_MET_MAC(l,u,b) void VCL_##l##_method(struct sess *);
#include "vcl_returns.h"
#undef VCL_MET_MAC

/* cache_ws.c */

void WS_Init(struct ws *ws, const char *id, void *space, unsigned len);
unsigned WS_Reserve(struct ws *ws, unsigned bytes);
void WS_Release(struct ws *ws, unsigned bytes);
void WS_ReleaseP(struct ws *ws, char *ptr);
void WS_Assert(const struct ws *ws);
void WS_Reset(struct ws *ws, char *p);
char *WS_Alloc(struct ws *ws, unsigned bytes);
char *WS_Dup(struct ws *ws, const char *);
char *WS_nDup(struct ws *ws, const char *s, size_t l);
char *WS_Snapshot(struct ws *ws);
unsigned WS_Free(const struct ws *ws);

/* rfc2616.c */
double RFC2616_Ttl(struct sess *sp);
enum body_status RFC2616_Body(const struct sess *sp);

/* storage_synth.c */
struct vsb *SMS_Makesynth(struct object *obj);
void SMS_Finish(struct object *obj);

/* storage_persistent.c */
void SMP_Fixup(struct sess *sp, const struct objhead *oh, struct objcore *oc);
void SMP_BANchanged(const struct object *o, double t);
void SMP_TTLchanged(const struct object *o);
void SMP_FreeObj(const struct object *o);
void SMP_Ready(void);
void SMP_NewBan(double t0, const char *ban);

/*
 * A normal pointer difference is signed, but we never want a negative value
 * so this little tool will make sure we don't get that.
 */

static inline unsigned
pdiff(const void *b, const void *e)
{

	assert(b <= e);
	return
	    ((unsigned)((const unsigned char *)e - (const unsigned char *)b));
}

static inline void
Tcheck(const txt t)
{

	AN(t.b);
	AN(t.e);
	assert(t.b <= t.e);
}

/*
 * unsigned length of a txt
 */

static inline unsigned
Tlen(const txt t)
{

	Tcheck(t);
	return ((unsigned)(t.e - t.b));
}

static inline void
Tadd(txt *t, const char *p, int l)
{
	Tcheck(*t);

	if (l <= 0) {
	} if (t->b + l < t->e) {
		memcpy(t->b, p, l);
		t->b += l;
	} else {
		t->b = t->e;
	}
}

static inline unsigned
ObjIsBusy(const struct object *o)
{
	CHECK_OBJ_NOTNULL(o, OBJECT_MAGIC);
	CHECK_OBJ_NOTNULL(o->objcore, OBJCORE_MAGIC);
	return (o->objcore->flags & OC_F_BUSY);
}
