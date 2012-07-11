/*
 * $Id$
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit and run vcc_gen_fixed_token.tcl instead
 */

#include "config.h"
#include <stdio.h>
#include "vcc_compile.h"

struct var vcc_vars[] = {
	{ "client.ip", IP, 9,
	    "VRT_r_client_ip(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "client.identity", STRING, 15,
	    "VRT_r_client_identity(sp)",
	    "VRT_l_client_identity(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "client.country", STRING, 14,
	    "VRT_r_client_country(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "server.ip", IP, 9,
	    "VRT_r_server_ip(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "server.hostname", STRING, 15,
	    "VRT_r_server_hostname(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "server.identity", STRING, 15,
	    "VRT_r_server_identity(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "server.port", INT, 11,
	    "VRT_r_server_port(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.request", STRING, 11,
	    "VRT_r_req_request(sp)",
	    "VRT_l_req_request(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.url", STRING, 7,
	    "VRT_r_req_url(sp)",
	    "VRT_l_req_url(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.proto", STRING, 9,
	    "VRT_r_req_proto(sp)",
	    "VRT_l_req_proto(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.http.", HEADER, 9,
	    "VRT_r_req_http_(sp)",
	    "VRT_l_req_http_(sp, ",
	    V_RW,	    "HDR_REQ",
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.hash", HASH, 8,
	    NULL,
	    "VRT_l_req_hash(sp, ",
	    V_WO,	    0,
	    VCL_MET_HTTP_HASH | VCL_MET_HTTP_ERROR
	},
	{ "req.backend", BACKEND, 11,
	    "VRT_r_req_backend(sp)",
	    "VRT_l_req_backend(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.restarts", INT, 12,
	    "VRT_r_req_restarts(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.grace", RTIME, 9,
	    "VRT_r_req_grace(sp)",
	    "VRT_l_req_grace(sp, ",
	    V_RW,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.xid", STRING, 7,
	    "VRT_r_req_xid(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.backend.healthy", BOOL, 19,
	    "VRT_r_req_backend_healthy(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ "req.hash_ignore_busy", BOOL, 20,
	    "VRT_r_req_hash_ignore_busy(sp)",
	    "VRT_l_req_hash_ignore_busy(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_RECV
	},
	{ "req.hash_always_miss", BOOL, 20,
	    "VRT_r_req_hash_always_miss(sp)",
	    "VRT_l_req_hash_always_miss(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_RECV
	},
	{ "bereq.request", STRING, 13,
	    "VRT_r_bereq_request(sp)",
	    "VRT_l_bereq_request(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PIPE | VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_FETCH
	},
	{ "bereq.url", STRING, 9,
	    "VRT_r_bereq_url(sp)",
	    "VRT_l_bereq_url(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PIPE | VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_FETCH
	},
	{ "bereq.proto", STRING, 11,
	    "VRT_r_bereq_proto(sp)",
	    "VRT_l_bereq_proto(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PIPE | VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_FETCH
	},
	{ "bereq.http.", HEADER, 11,
	    "VRT_r_bereq_http_(sp)",
	    "VRT_l_bereq_http_(sp, ",
	    V_RW,	    "HDR_BEREQ",
	    VCL_MET_HTTP_PIPE | VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_FETCH
	},
	{ "bereq.connect_timeout", RTIME, 21,
	    "VRT_r_bereq_connect_timeout(sp)",
	    "VRT_l_bereq_connect_timeout(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	},
	{ "bereq.first_byte_timeout", RTIME, 24,
	    "VRT_r_bereq_first_byte_timeout(sp)",
	    "VRT_l_bereq_first_byte_timeout(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	},
	{ "bereq.between_bytes_timeout", RTIME, 27,
	    "VRT_r_bereq_between_bytes_timeout(sp)",
	    "VRT_l_bereq_between_bytes_timeout(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PASS | VCL_MET_HTTP_MISS
	},
	{ "bereq.noflushreq", BOOL, 16,
	    "VRT_r_bereq_noflushreq(sp)",
	    "VRT_l_bereq_noflushreq(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_PIPE
	},
	{ "beresp.proto", STRING, 12,
	    "VRT_r_beresp_proto(sp)",
	    "VRT_l_beresp_proto(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.saintmode", RTIME, 16,
	    NULL,
	    "VRT_l_beresp_saintmode(sp, ",
	    V_WO,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.status", INT, 13,
	    "VRT_r_beresp_status(sp)",
	    "VRT_l_beresp_status(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.response", STRING, 15,
	    "VRT_r_beresp_response(sp)",
	    "VRT_l_beresp_response(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.http.", HEADER, 12,
	    "VRT_r_beresp_http_(sp)",
	    "VRT_l_beresp_http_(sp, ",
	    V_RW,	    "HDR_BERESP",
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.cacheable", BOOL, 16,
	    "VRT_r_beresp_cacheable(sp)",
	    "VRT_l_beresp_cacheable(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.ttl", RTIME, 10,
	    "VRT_r_beresp_ttl(sp)",
	    "VRT_l_beresp_ttl(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "beresp.grace", RTIME, 12,
	    "VRT_r_beresp_grace(sp)",
	    "VRT_l_beresp_grace(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_FETCH
	},
	{ "obj.proto", STRING, 9,
	    "VRT_r_obj_proto(sp)",
	    "VRT_l_obj_proto(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_ERROR
	},
	{ "obj.status", INT, 10,
	    "VRT_r_obj_status(sp)",
	    "VRT_l_obj_status(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_ERROR
	},
	{ "obj.response", STRING, 12,
	    "VRT_r_obj_response(sp)",
	    "VRT_l_obj_response(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_ERROR
	},
	{ "obj.hits", INT, 8,
	    "VRT_r_obj_hits(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_DELIVER
	},
	{ "obj.http.", HEADER, 9,
	    "VRT_r_obj_http_(sp)",
	    "VRT_l_obj_http_(sp, ",
	    V_RW,	    "HDR_OBJ",
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_ERROR
	},
	{ "obj.cacheable", BOOL, 13,
	    "VRT_r_obj_cacheable(sp)",
	    "VRT_l_obj_cacheable(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_HIT
	},
	{ "obj.ttl", RTIME, 7,
	    "VRT_r_obj_ttl(sp)",
	    "VRT_l_obj_ttl(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_ERROR
	},
	{ "obj.grace", RTIME, 9,
	    "VRT_r_obj_grace(sp)",
	    "VRT_l_obj_grace(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_ERROR
	},
	{ "obj.lastuse", RTIME, 11,
	    "VRT_r_obj_lastuse(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_HTTP_HIT | VCL_MET_HTTP_DELIVER | VCL_MET_HTTP_ERROR
	},
	{ "resp.proto", STRING, 10,
	    "VRT_r_resp_proto(sp)",
	    "VRT_l_resp_proto(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_DELIVER
	},
	{ "resp.status", INT, 11,
	    "VRT_r_resp_status(sp)",
	    "VRT_l_resp_status(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_DELIVER
	},
	{ "resp.response", STRING, 13,
	    "VRT_r_resp_response(sp)",
	    "VRT_l_resp_response(sp, ",
	    V_RW,	    0,
	    VCL_MET_HTTP_DELIVER
	},
	{ "resp.http.", HEADER, 10,
	    "VRT_r_resp_http_(sp)",
	    "VRT_l_resp_http_(sp, ",
	    V_RW,	    "HDR_RESP",
	    VCL_MET_HTTP_DELIVER
	},
	{ "socks.type", STRING, 10,
	    "VRT_r_socks_type(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_SOCKS_REQ
	},
	{ "socks.ip", IP, 8,
	    "VRT_r_socks_ip(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_SOCKS_REQ
	},
	{ "socks.backend", BACKEND, 13,
	    "VRT_r_socks_backend(sp)",
	    "VRT_l_socks_backend(sp, ",
	    V_RW,	    0,
	    VCL_MET_SOCKS_REQ
	},
	{ "now", TIME, 3,
	    "VRT_r_now(sp)",
	    NULL,
	    V_RO,	    0,
	    VCL_MET_ACCEPT | VCL_MET_SOCKS_REQ | VCL_MET_HTTP_RECV | VCL_MET_HTTP_PIPE
	     | VCL_MET_HTTP_PASS | VCL_MET_HTTP_HASH | VCL_MET_HTTP_MISS
	     | VCL_MET_HTTP_HIT | VCL_MET_HTTP_FETCH | VCL_MET_HTTP_DELIVER
	     | VCL_MET_HTTP_ERROR
	},
	{ NULL }
};
