# $Id$

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = varnishmap

dist_man_MANS = varnishmap.1

varnishmap_SOURCES = varnishmap.c

varnishmap_CFLAGS = \
	${GEOIP_CFLAGS}

varnishmap_LDADD = \
	$(top_builddir)/lib/libvarnish/libvarnish.la \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	${GEOIP_LIBS} \
	${PTHREAD_LIBS}

varnishmap.1: $(top_srcdir)/doc/sphinx/reference/varnishmap.rst
if HAVE_RST2MAN
	${RST2MAN} $? $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif
