/*
 * $Id$
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit and run vcc_gen_fixed_token.tcl instead
 */

struct sess;
struct cli;

typedef void vcl_init_f(struct cli *);
typedef void vcl_fini_f(struct cli *);
typedef int vcl_func_f(struct sess *sp);

/* VCL Methods */
#define VCL_MET_ACCEPT		(1U << 0)
#define VCL_MET_SOCKS_REQ	(1U << 1)
#define VCL_MET_HTTP_RECV	(1U << 2)
#define VCL_MET_HTTP_PIPE	(1U << 3)
#define VCL_MET_HTTP_PASS	(1U << 4)
#define VCL_MET_HTTP_HASH	(1U << 5)
#define VCL_MET_HTTP_MISS	(1U << 6)
#define VCL_MET_HTTP_HIT	(1U << 7)
#define VCL_MET_HTTP_FETCH	(1U << 8)
#define VCL_MET_HTTP_DELIVER	(1U << 9)
#define VCL_MET_HTTP_ERROR	(1U << 10)

#define VCL_MET_MAX		11

/* VCL Returns */
#define VCL_RET_DELIVER		0
#define VCL_RET_DROP		1
#define VCL_RET_ERROR		2
#define VCL_RET_FETCH		3
#define VCL_RET_HASH		4
#define VCL_RET_HTTP		5
#define VCL_RET_LOOKUP		6
#define VCL_RET_PASS		7
#define VCL_RET_PIPE		8
#define VCL_RET_RESTART		9
#define VCL_RET_SOCKS		10

#define VCL_RET_MAX		11

struct VCL_conf {
	unsigned	magic;
#define VCL_CONF_MAGIC	0x7406c509	/* from /dev/random */

	struct director	**director;
	unsigned	ndirector;
	struct vrt_ref	*ref;
	unsigned	nref;
	unsigned	busy;
	unsigned	discard;

	unsigned	nsrc;
	const char	**srcname;
	const char	**srcbody;

	vcl_init_f	*init_func;
	vcl_fini_f	*fini_func;

	vcl_func_f	*accept_func;
	vcl_func_f	*socks_req_func;
	vcl_func_f	*http_recv_func;
	vcl_func_f	*http_pipe_func;
	vcl_func_f	*http_pass_func;
	vcl_func_f	*http_hash_func;
	vcl_func_f	*http_miss_func;
	vcl_func_f	*http_hit_func;
	vcl_func_f	*http_fetch_func;
	vcl_func_f	*http_deliver_func;
	vcl_func_f	*http_error_func;
};
