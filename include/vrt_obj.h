/*
 * $Id$
 *
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit and run vcc_gen_fixed_token.tcl instead
 */

struct sockaddr * VRT_r_client_ip(const struct sess *);
const char * VRT_r_client_identity(struct sess *);
void VRT_l_client_identity(struct sess *, const char *, ...);
const char * VRT_r_client_country(const struct sess *);
struct sockaddr * VRT_r_server_ip(struct sess *);
const char * VRT_r_server_hostname(struct sess *);
const char * VRT_r_server_identity(struct sess *);
int VRT_r_server_port(struct sess *);
const char * VRT_r_req_request(const struct sess *);
void VRT_l_req_request(const struct sess *, const char *, ...);
const char * VRT_r_req_url(const struct sess *);
void VRT_l_req_url(const struct sess *, const char *, ...);
const char * VRT_r_req_proto(const struct sess *);
void VRT_l_req_proto(const struct sess *, const char *, ...);
void VRT_l_req_hash(struct sess *, const char *);
struct director * VRT_r_req_backend(struct sess *);
void VRT_l_req_backend(struct sess *, struct director *);
int VRT_r_req_restarts(const struct sess *);
double VRT_r_req_grace(struct sess *);
void VRT_l_req_grace(struct sess *, double);
const char * VRT_r_req_xid(struct sess *);
unsigned VRT_r_req_backend_healthy(const struct sess *);
unsigned VRT_r_req_hash_ignore_busy(struct sess *);
void VRT_l_req_hash_ignore_busy(struct sess *, unsigned);
unsigned VRT_r_req_hash_always_miss(struct sess *);
void VRT_l_req_hash_always_miss(struct sess *, unsigned);
const char * VRT_r_bereq_request(const struct sess *);
void VRT_l_bereq_request(const struct sess *, const char *, ...);
const char * VRT_r_bereq_url(const struct sess *);
void VRT_l_bereq_url(const struct sess *, const char *, ...);
const char * VRT_r_bereq_proto(const struct sess *);
void VRT_l_bereq_proto(const struct sess *, const char *, ...);
double VRT_r_bereq_connect_timeout(struct sess *);
void VRT_l_bereq_connect_timeout(struct sess *, double);
double VRT_r_bereq_first_byte_timeout(struct sess *);
void VRT_l_bereq_first_byte_timeout(struct sess *, double);
double VRT_r_bereq_between_bytes_timeout(struct sess *);
void VRT_l_bereq_between_bytes_timeout(struct sess *, double);
unsigned VRT_r_bereq_noflushreq(struct sess *);
void VRT_l_bereq_noflushreq(struct sess *, unsigned);
const char * VRT_r_beresp_proto(const struct sess *);
void VRT_l_beresp_proto(const struct sess *, const char *, ...);
void VRT_l_beresp_saintmode(const struct sess *, double);
int VRT_r_beresp_status(const struct sess *);
void VRT_l_beresp_status(const struct sess *, int);
const char * VRT_r_beresp_response(const struct sess *);
void VRT_l_beresp_response(const struct sess *, const char *, ...);
unsigned VRT_r_beresp_cacheable(struct sess *);
void VRT_l_beresp_cacheable(struct sess *, unsigned);
double VRT_r_beresp_ttl(struct sess *);
void VRT_l_beresp_ttl(struct sess *, double);
double VRT_r_beresp_grace(struct sess *);
void VRT_l_beresp_grace(struct sess *, double);
const char * VRT_r_obj_proto(const struct sess *);
void VRT_l_obj_proto(const struct sess *, const char *, ...);
int VRT_r_obj_status(const struct sess *);
void VRT_l_obj_status(const struct sess *, int);
const char * VRT_r_obj_response(const struct sess *);
void VRT_l_obj_response(const struct sess *, const char *, ...);
int VRT_r_obj_hits(const struct sess *);
unsigned VRT_r_obj_cacheable(struct sess *);
void VRT_l_obj_cacheable(struct sess *, unsigned);
double VRT_r_obj_ttl(const struct sess *);
void VRT_l_obj_ttl(const struct sess *, double);
double VRT_r_obj_grace(const struct sess *);
void VRT_l_obj_grace(const struct sess *, double);
double VRT_r_obj_lastuse(const struct sess *);
const char * VRT_r_resp_proto(const struct sess *);
void VRT_l_resp_proto(const struct sess *, const char *, ...);
int VRT_r_resp_status(const struct sess *);
void VRT_l_resp_status(const struct sess *, int);
const char * VRT_r_resp_response(const struct sess *);
void VRT_l_resp_response(const struct sess *, const char *, ...);
const char * VRT_r_socks_type(const struct sess *);
struct sockaddr * VRT_r_socks_ip(struct sess *);
struct director * VRT_r_socks_backend(struct sess *);
void VRT_l_socks_backend(struct sess *, struct director *);
double VRT_r_now(const struct sess *);
