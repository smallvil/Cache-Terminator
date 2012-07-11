/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2009 Linpro AS
 * All rights reserved.
 *
 * Author: Anders Berg <andersb@vgnett.no>
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
 * Obtain log data from the shared memory log, order it by session ID, and
 * display it in Apache / NCSA combined log format:
 *
 *	%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
 *
 * where the fields are defined as follows:
 *
 *	%h		Client host name or IP address (always the latter)
 *	%l		Client user ID as reported by identd (always "-")
 *	%u		User ID if using HTTP authentication, or "-"
 *	%t		Date and time of request
 *	%r		Request line
 *	%s		Status code
 *	%b		Length of reply body, or "-"
 *	%{Referer}i	Contents of "Referer" request header
 *	%{User-agent}i	Contents of "User-agent" request header
 *
 * Actually, we cheat a little and replace "%r" with something close to
 * "%m http://%{Host}i%U%q %H", where the additional fields are:
 *
 *	%m		Request method
 *	%{Host}i	Contents of "Host" request header
 *	%U		URL path
 *	%q		Query string
 *	%H		Protocol version
 *
 * TODO:	- Log in any format one wants
 *		- Maybe rotate/compress log
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: varnishmap.c 145 2011-04-15 18:58:22Z jwg286 $")

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_GEOIP
#include <GeoIP.h>
#endif

#include "compat/daemon.h"

#include "miniobj.h"
#include "vsb.h"
#include "vpf.h"
#include "vqueue.h"

#include "libvarnish.h"
#include "shmlog.h"
#include "varnishapi.h"

#define	MAPNODE_INTERVAL	10	/* secs for granularity */

struct mapnode {
	unsigned		magic;
#define	MAPNODE_MAGIC		0x44cc3294
	unsigned		flags;
#define	MAPNODE_F_RUNNING	0x1
	int			family;
	int			socktype;
	int			protocol;
	void			*addr;
	socklen_t		addrlen;
	time_t			lasttime;
	time_t			regtime;
#ifdef HAVE_GEOIP
	const char		*country;	/* from GeoIP */
#endif
	double			rtt;	/* Smoothed RTT in usecs. */
	double			rttvar;	/* RTT variance in usecs. */

	int			fd;
	struct kevent		ev;
	VTAILQ_ENTRY(mapnode)	list;
};

#ifdef HAVE_GEOIP
static GeoIP			*map_geoip;
#endif
static volatile sig_atomic_t reopen;
static int			map_verbose;
static int			map_busy;
static pthread_t		map_tp;
static pthread_mutex_t		map_mtx;
static VTAILQ_HEAD(, mapnode)	map_list;
/*
 * interval to perform tests.
 */
static int			i_flag = 60 * 10;	/* 10 minutes */

/*
 * Returns a copy of the first consecutive sequence of non-space
 * characters in the string.
 */
static char *
trimfield(const char *str, const char *end, const char **ptr)
{
	ssize_t len;
	char *p;

	/* skip leading space */
	while (str < end && *str && (*str == ' ' || *str == '\t'))
		++str;

	/* seek to end of field */
	for (len = 0; &str[len] < end && str[len]; ++len)
		if (str[len] == ' ' || str[len] == '\t' ||
		    str[len] == '\r' || str[len] == '\n')
			break;

	if (ptr != NULL)
		*ptr = str + len;

	/* copy and return */
	p = malloc(len + 1);
	assert(p != NULL);
	memcpy(p, str, len);
	p[len] = '\0';
	return (p);
}

static void
dump_list(void)
{
	struct mapnode *mn;
	time_t now;
	char abuf[TCP_ADDRBUFSIZE], pbuf[TCP_PORTBUFSIZE], *nowstr;

	now = time(NULL);
	nowstr = ctime(&now);

	AZ(pthread_mutex_lock(&map_mtx));
	VTAILQ_FOREACH(mn, &map_list, list) {
		TCP_name(mn->addr, mn->addrlen, abuf, sizeof(abuf),
		    pbuf, sizeof(pbuf));

		printf("%.*s", 24, nowstr);
		printf(" %s %-15s %5s %4zd %6.1fms %.1fms\n", mn->country,
		    abuf, pbuf, time(NULL) - mn->regtime, mn->rtt, mn->rttvar);
	}
	AZ(pthread_mutex_unlock(&map_mtx));
}

static void
enqueue_all(int kfd)
{
	struct mapnode *mn;
	time_t now = time(NULL);
	int ret;

	AZ(pthread_mutex_lock(&map_mtx));
	VTAILQ_FOREACH(mn, &map_list, list) {
		if ((mn->flags & MAPNODE_F_RUNNING) != 0)
			continue;
		if ((now - mn->lasttime) < MAPNODE_INTERVAL)
			continue;
		map_busy++;
		mn->flags |= MAPNODE_F_RUNNING;
		mn->fd = socket(mn->family, mn->socktype, mn->protocol);
		if (mn->fd == -1)
			printf("%s\n", strerror(errno));
		assert(mn->fd >= 0);
		TCP_nonblocking(mn->fd);
		ret = connect(mn->fd, mn->addr, mn->addrlen);
		if (ret == -1 && errno != EINPROGRESS)
			assert(0 == 1);
		EV_SET(&mn->ev, mn->fd, EVFILT_WRITE, EV_ADD, 0, 0, mn);
		AZ(kevent(kfd, &mn->ev, 1, NULL, 0, NULL));
	}
	AZ(pthread_mutex_unlock(&map_mtx));
}

static void
done(int kfd, struct mapnode *mn)
{
	struct tcp_info ti;
	socklen_t size;

	size = sizeof(struct tcp_info);
	bzero(&ti, size);
	if (getsockopt(mn->fd, IPPROTO_TCP, TCP_INFO, (void *)&ti, &size) < 0)
		perror("getsockopt");
	EV_SET(&mn->ev, mn->fd, EVFILT_WRITE, EV_DELETE, 0, 0, mn);
	AZ(kevent(kfd, &mn->ev, 1, NULL, 0, NULL));
	close(mn->fd);
	mn->rtt = (double)ti.tcpi_rtt / 1000;
	mn->rttvar = (double)ti.tcpi_rttvar / 1000;
	mn->flags &= ~MAPNODE_F_RUNNING;
	mn->lasttime = time(NULL);
	map_busy--;
}

static void *
map_thread(void *arg)
{
#define	KQEVENT_MAX	(8 * 1024)
	struct kevent ev[KQEVENT_MAX], *ep;
	struct timespec tmout = { 0, 1000000 }; /* waits 1 milisecond */
	int kfd, i, n;

	(void)arg;
	(void)ev;
	(void)ep;

	kfd = kqueue();

	while (1) {
		enqueue_all(kfd);

		n = kevent(kfd, NULL, 0, ev, KQEVENT_MAX, &tmout);
		for (ep = ev, i = 0; i < n; i++, ep++)
			done(kfd, ep->udata);
		if (map_busy == 0) {
			dump_list();
			sleep(i_flag);
		}
	}
}

static void
register_addr(struct addrinfo *res, const char *ip)
{
	struct mapnode *mn;
#ifdef HAVE_GEOIP
	int id;
#endif

	AZ(pthread_mutex_lock(&map_mtx));

	/* Check whether there's a duplicate */
	VTAILQ_FOREACH(mn, &map_list, list)
		if (mn->addrlen == res->ai_addrlen &&
		    !bcmp(mn->addr, res->ai_addr, res->ai_addrlen))
			goto done;
	ALLOC_OBJ(mn, MAPNODE_MAGIC);
	AN(mn);
	mn->family = res->ai_family;
	mn->socktype = res->ai_socktype;
	mn->protocol = res->ai_protocol;
	mn->addr = malloc(res->ai_addrlen);
	AN(mn->addr);
	bcopy(res->ai_addr, mn->addr, res->ai_addrlen);
	mn->addrlen = res->ai_addrlen;
	mn->lasttime = time(NULL) - MAPNODE_INTERVAL;
	mn->regtime = time(NULL);
#ifdef HAVE_GEOIP
	id = GeoIP_id_by_addr(map_geoip, ip);
	mn->country = GeoIP_country_code[id];
#endif
	VTAILQ_INSERT_TAIL(&map_list, mn, list);
done:
	AZ(pthread_mutex_unlock(&map_mtx));
}

static void
handle_addrport(char *ip, char *port)
{
	struct addrinfo hint, *res, *res0;
	int error, n4, n6;
	const char *emit, *multiple;

	if (map_verbose > 0)
		printf("AddHost: %s %s\n", ip, port);

	memset(&hint, 0, sizeof hint);
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(ip, port, &hint, &res0);
	if (error)
		assert(0 == 1);

	AZ(error);
	n4 = n6 = 0;
	multiple = NULL;

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET) {
			if (n4++ == 0)
				emit = "ipv4";
			else
				multiple = "IPv4";
		} else if (res->ai_family == PF_INET6) {
			if (n6++ == 0)
				emit = "ipv6";
			else
				multiple = "IPv6";
		} else
			continue;
		if (multiple != NULL)
			assert(0 == 1);
		AN(emit);
		register_addr(res, ip);
	}
	freeaddrinfo(res0);
}

static int
collect_backend(enum shmlogtag tag, unsigned spec, const char *ptr,
    unsigned len)
{
	const char *end, *next, *eptr;
	char *ip, *port;

	(void)spec;

	end = ptr + len;

	switch (tag) {
	case SLT_BackendAdd:
		ip = trimfield(ptr, end, &eptr);
		port = trimfield(eptr, end, NULL);
		handle_addrport(ip, port);
		free(ip);
		free(port);
		break;
	case SLT_BackendOpen:
		next = ptr;
		while (next < end) {
			if (*next == '-' && *(next + 1) == '>')
				break;
			next++;
		}
		next += 2;
		ip = trimfield(next, end, &eptr);
		port = trimfield(eptr, end, NULL);
		handle_addrport(ip, port);
		free(ip);
		free(port);
		break;
	default:
		break;
	}

	return (1);
}

static int
h_map(void *priv, enum shmlogtag tag, unsigned fd,
    unsigned len, unsigned spec, const char *ptr)
{

	(void)priv;
	(void)fd;

	collect_backend(tag, spec, ptr, len);
	return (reopen);
}

static void
handle_mapfile(const char *file)
{
	FILE *fp;
	char *lp, line[BUFSIZ];
	char *ip, *port;
	const char *end, *eptr;

	fp = fopen(file, "r");
	AN(fp);
	while ((lp = fgets(line, sizeof(line), fp)) != NULL) {
		end = lp + strlen(line);
		ip = trimfield(lp, end, &eptr);
		port = trimfield(eptr, end, NULL);
		handle_addrport(ip, port);
		free(ip);
		free(port);
	}
	fclose(fp);
}

/*--------------------------------------------------------------------*/

static void
sighup(int sig)
{

	(void)sig;
	reopen = 1;
}

static FILE *
open_log(const char *ofn, int append)
{
	FILE *of;

	if ((of = fopen(ofn, append ? "a" : "w")) == NULL) {
		perror(ofn);
		exit(1);
	}
	return (of);
}

/*--------------------------------------------------------------------*/

static void
usage(void)
{

	fprintf(stderr,
	    "usage: varnishmap %s [-aDV] [-n varnish_name] "
	    "[-P file] [-w file]\n", VSL_USAGE);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	int a_flag = 0, D_flag = 0;
	const char *m_arg = NULL;
	const char *n_arg = NULL;
	const char *P_arg = NULL;
	const char *w_arg = NULL;
	struct pidfh *pfh = NULL;
	struct VSL_data *vd;
	FILE *of;

	AZ(pthread_mutex_init(&map_mtx, NULL));
	VTAILQ_INIT(&map_list);
	AZ(pthread_create(&map_tp, NULL, map_thread, NULL));
#ifdef HAVE_GEOIP
	map_geoip = GeoIP_new(GEOIP_STANDARD);
	AN(map_geoip);
#endif

	vd = VSL_New();

	while ((c = getopt(argc, argv, VSL_ARGS "aDi:m:n:P:Vvw:")) != -1) {
		switch (c) {
		case 'a':
			a_flag = 1;
			break;
		case 'D':
			D_flag = 1;
			break;
		case 'i':
			i_flag = (int)strtol(optarg, (char **)NULL, 10);
			break;
		case 'm':
			m_arg = optarg;
			break;
		case 'n':
			n_arg = optarg;
			break;
		case 'P':
			P_arg = optarg;
			break;
		case 'V':
			varnish_version("varnishmap");
			exit(0);
		case 'v':
			map_verbose++;
			break;
		case 'w':
			w_arg = optarg;
			break;
		case 'b':
			fprintf(stderr, "-b is not valid for varnishmap\n");
			exit(1);
			break;
		case 'c':
			/* XXX: Silently ignored: it's required anyway */
			break;
		default:
			if (VSL_Arg(vd, c, optarg) > 0)
				break;
			usage();
		}
	}

	VSL_Arg(vd, 'c', optarg);

	if (VSL_OpenLog(vd, n_arg))
		exit(1);

	if (P_arg && (pfh = vpf_open(P_arg, 0644, NULL)) == NULL) {
		perror(P_arg);
		exit(1);
	}

	if (D_flag && varnish_daemon(0, 0) == -1) {
		perror("daemon()");
		if (pfh != NULL)
			vpf_remove(pfh);
		exit(1);
	}

	if (pfh != NULL)
		vpf_write(pfh);

	if (m_arg)
		handle_mapfile(m_arg);

	if (w_arg) {
		of = open_log(w_arg, a_flag);
		signal(SIGHUP, sighup);
	} else {
		w_arg = "stdout";
		of = stdout;
	}

	/* Explicitly set what we're interesting. */
	VSL_Select(vd, SLT_BackendAdd);
	VSL_Select(vd, SLT_BackendOpen);
	while (VSL_Dispatch(vd, h_map, of) >= 0) {
		if (fflush(of) != 0) {
			perror(w_arg);
			exit(1);
		}
		if (reopen && of != stdout) {
			fclose(of);
			of = open_log(w_arg, a_flag);
			reopen = 0;
		}
	}

	exit(0);
}
