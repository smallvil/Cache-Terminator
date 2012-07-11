/*
 * $Id$
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit and run vcc_gen_fixed_token.tcl instead
 */

#ifdef VCL_RET_MAC
VCL_RET_MAC(deliver, DELIVER)
VCL_RET_MAC(drop, DROP)
VCL_RET_MAC(error, ERROR)
VCL_RET_MAC(fetch, FETCH)
VCL_RET_MAC(hash, HASH)
VCL_RET_MAC(http, HTTP)
VCL_RET_MAC(lookup, LOOKUP)
VCL_RET_MAC(pass, PASS)
VCL_RET_MAC(pipe, PIPE)
VCL_RET_MAC(restart, RESTART)
VCL_RET_MAC(socks, SOCKS)
#endif

#ifdef VCL_MET_MAC
VCL_MET_MAC(accept,ACCEPT,
     ((1U << VCL_RET_HTTP)
    | (1U << VCL_RET_PIPE)
    | (1U << VCL_RET_SOCKS)
))
VCL_MET_MAC(socks_req,SOCKS_REQ,
     ((1U << VCL_RET_DROP)
    | (1U << VCL_RET_PIPE)
))
VCL_MET_MAC(http_recv,HTTP_RECV,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_PASS)
    | (1U << VCL_RET_PIPE)
    | (1U << VCL_RET_LOOKUP)
))
VCL_MET_MAC(http_pipe,HTTP_PIPE,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_PIPE)
))
VCL_MET_MAC(http_pass,HTTP_PASS,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_RESTART)
    | (1U << VCL_RET_PASS)
))
VCL_MET_MAC(http_hash,HTTP_HASH,
     ((1U << VCL_RET_HASH)
))
VCL_MET_MAC(http_miss,HTTP_MISS,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_RESTART)
    | (1U << VCL_RET_PASS)
    | (1U << VCL_RET_FETCH)
))
VCL_MET_MAC(http_hit,HTTP_HIT,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_RESTART)
    | (1U << VCL_RET_PASS)
    | (1U << VCL_RET_DELIVER)
))
VCL_MET_MAC(http_fetch,HTTP_FETCH,
     ((1U << VCL_RET_ERROR)
    | (1U << VCL_RET_RESTART)
    | (1U << VCL_RET_PASS)
    | (1U << VCL_RET_DELIVER)
))
VCL_MET_MAC(http_deliver,HTTP_DELIVER,
     ((1U << VCL_RET_RESTART)
    | (1U << VCL_RET_DELIVER)
))
VCL_MET_MAC(http_error,HTTP_ERROR,
     ((1U << VCL_RET_RESTART)
    | (1U << VCL_RET_DELIVER)
))
#endif
