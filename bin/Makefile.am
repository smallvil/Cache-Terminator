# $Id$

SUBDIRS = varnishadm varnishd varnishlog \
	  varnishncsa varnishreplay varnishtest

if HAVE_KQUEUE
SUBDIRS += varnishmap
endif

if HAVE_CURSES
SUBDIRS += varnishhist varnishstat varnishtop varnishsizes
endif
