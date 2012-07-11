/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2009 Linpro AS
 * All rights reserved.
 *
 * Author: Weongyo Jeong <weongyo@gmail.com>
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
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_vcl.c 2 2011-03-27 07:34:59Z jwg286 $")

#ifdef HAVE_GEOIP

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <GeoIP.h>

#include "cli.h"
#include "cli_priv.h"
#include "shmlog.h"
#include "vcl.h"
#include "cache.h"
#include "libvcl.h"

struct geo_conf {
	unsigned		magic;
#define GEO_CONF_MAGIC		0xa5ddbe4c
	GeoIP			*gi;
	unsigned		busy;
	unsigned		discard;
};

struct geo_info {
	unsigned		magic;
#define GEOS_MAGIC		0x412188f2
	VTAILQ_ENTRY(geo_info)	list;
	char			*name;
	char			*filename;
	struct geo_conf		conf[1];
};

/*
 * XXX: Presently all modifications to this list happen from the
 * CLI event-engine, so no locking is necessary
 */
static VTAILQ_HEAD(, geo_info)	geo_head =
    VTAILQ_HEAD_INITIALIZER(geo_head);

static struct lock		geo_mtx;
static struct geo_info		*geo_active; /* protected by geo_mtx */

/*--------------------------------------------------------------------*/

void
GEO_Refresh(struct geo_conf **gcc)
{

	if (geo_active == NULL)
		return;
	if (*gcc == geo_active->conf)
		return;
	if (*gcc != NULL)
		GEO_Rel(gcc);	/* XXX: optimize locking */
	GEO_Get(gcc);
}

void
GEO_Get(struct geo_conf **gcc)
{

	if (geo_active == NULL)
		return;
	Lck_Lock(&geo_mtx);
	AN(geo_active);
	*gcc = geo_active->conf;
	AN(*gcc);
	AZ((*gcc)->discard);
	(*gcc)->busy++;
	Lck_Unlock(&geo_mtx);
}

void
GEO_Rel(struct geo_conf **gcc)
{
	struct geo_conf *gc;

	gc = *gcc;
	if (gc == NULL)
		return;
	*gcc = NULL;

	Lck_Lock(&geo_mtx);
	assert(gc->busy > 0);
	gc->busy--;
	/*
	 * We do not garbage collect discarded GEO's here, that happens
	 * in GEO_Poll() which is called from the CLI thread.
	 */
	Lck_Unlock(&geo_mtx);
}

void *
GEO_GetPriv(struct geo_conf *gc)
{

	AN(gc);
	return (gc->gi);
}

/*--------------------------------------------------------------------*/

static struct geo_info *
geo_find(const char *name)
{
	struct geo_info *geo;

	ASSERT_CLI();
	VTAILQ_FOREACH(geo, &geo_head, list) {
		if (geo->conf->discard)
			continue;
		if (!strcmp(geo->name, name))
			return (geo);
	}
	return (NULL);
}

static int
GEO_Load(const char *fn, const char *name, struct cli *cli)
{
	struct geo_conf *gc;
	struct geo_info *geo;

	ASSERT_CLI();
	geo = geo_find(name);
	if (geo != NULL) {
		cli_out(cli, "Config '%s' already loaded", name);
		return (1);
	}

	ALLOC_OBJ(geo, GEOS_MAGIC);
	XXXAN(geo);
	REPLACE(geo->name, name);
	REPLACE(geo->filename, fn);
	gc = geo->conf;
	gc->magic = GEO_CONF_MAGIC;
	gc->gi = GeoIP_open(fn, GEOIP_STANDARD);
	if (gc->gi == NULL) {
		free(geo->filename);
		free(geo->name);
		free(geo);
		cli_out(cli, "failed to load GeoIP DB '%s'", fn);
		return (1);
	}
	VTAILQ_INSERT_TAIL(&geo_head, geo, list);
	Lck_Lock(&geo_mtx);
	if (geo_active == NULL)
		geo_active = geo;
	Lck_Unlock(&geo_mtx);
	cli_out(cli, "Loaded \"%s\" as \"%s\"", fn , name);
	VSL_stats->n_geoip++;
	VSL_stats->n_geoip_avail++;
	return (0);
}

/*--------------------------------------------------------------------
 * This function is polled from the CLI thread to dispose of any non-busy
 * GEOs which have been discarded.
 */

static void
GEO_Nuke(struct geo_info *geo)
{

	ASSERT_CLI();
	assert(geo != geo_active);
	assert(geo->conf->discard);
	assert(geo->conf->busy == 0);
	VTAILQ_REMOVE(&geo_head, geo, list);
	GeoIP_delete(geo->conf->gi);
	free(geo->filename);
	free(geo->name);
	FREE_OBJ(geo);
	VSL_stats->n_geoip--;
	VSL_stats->n_geoip_discard--;
}

/*--------------------------------------------------------------------*/

void
GEO_Poll(void)
{
	struct geo_info *geo, *geo2;

	ASSERT_CLI();
	VTAILQ_FOREACH_SAFE(geo, &geo_head, list, geo2)
		if (geo->conf->discard && geo->conf->busy == 0)
			GEO_Nuke(geo);
}

/*--------------------------------------------------------------------*/

static void
geo_config_list(struct cli *cli, const char * const *av, void *priv)
{
	struct geo_info *geo;
	const char *flg;

	(void)av;
	(void)priv;
	ASSERT_CLI();
	VTAILQ_FOREACH(geo, &geo_head, list) {
		if (geo == geo_active) {
			flg = "active";
		} else if (geo->conf->discard) {
			flg = "discarded";
		} else
			flg = "available";
		cli_out(cli, "%-10s %6u %s\n",
		    flg,
		    geo->conf->busy,
		    geo->name);
	}
}

static void
geo_config_load(struct cli *cli, const char * const *av, void *priv)
{

	(void)av;
	(void)priv;
	ASSERT_CLI();
	if (GEO_Load(av[3], av[2], cli))
		cli_result(cli, CLIS_PARAM);
	return;
}

static void
geo_config_discard(struct cli *cli, const char * const *av, void *priv)
{
	struct geo_info *geo;

	ASSERT_CLI();
	(void)av;
	(void)priv;
	geo = geo_find(av[2]);
	if (geo == NULL) {
		cli_result(cli, CLIS_PARAM);
		cli_out(cli, "GeoIP DB '%s' unknown", av[2]);
		return;
	}
	Lck_Lock(&geo_mtx);
	if (geo == geo_active) {
		Lck_Unlock(&geo_mtx);
		cli_result(cli, CLIS_PARAM);
		cli_out(cli, "GEO %s is the active GeoIP DB", av[2]);
		return;
	}
	VSL_stats->n_geoip_discard++;
	VSL_stats->n_geoip_avail--;
	geo->conf->discard = 1;
	Lck_Unlock(&geo_mtx);
	if (geo->conf->busy == 0)
		GEO_Nuke(geo);
}

static void
geo_config_use(struct cli *cli, const char * const *av, void *priv)
{
	struct geo_info *geo;

	(void)av;
	(void)priv;
	geo = geo_find(av[2]);
	if (geo == NULL) {
		cli_out(cli, "No GeoIP DB named '%s'", av[2]);
		cli_result(cli, CLIS_PARAM);
		return;
	}
	Lck_Lock(&geo_mtx);
	geo_active = geo;
	Lck_Unlock(&geo_mtx);
}

static struct cli_proto geo_cmds[] = {
	{ CLI_GEOIP_LOAD,         "i", geo_config_load },
	{ CLI_GEOIP_LIST,         "i", geo_config_list },
	{ CLI_GEOIP_DISCARD,      "i", geo_config_discard },
	{ CLI_GEOIP_USE,          "i", geo_config_use },
	{ NULL }
};

void
GEO_Init(void)
{

	CLI_AddFuncs(geo_cmds);
	Lck_New(&geo_mtx);
}

#endif	/* HAVE_GEOIP */
