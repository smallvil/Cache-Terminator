/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2009 Linpro AS
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
 * $Id: stat_field.h 103 2011-04-12 06:54:31Z jwg286 $
 *
 * 3rd argument marks fields for inclusion in the per worker-thread
 * stats structure.
 */

MAC_STAT(client_conn,		uint64_t, 0, 'a', "Client connections accepted")
MAC_STAT(client_drop,		uint64_t, 0, 'a', "Connection dropped, no sess/wrk")
MAC_STAT(client_req,		uint64_t, 1, 'a', "Client requests received")

MAC_STAT(cache_hit,		uint64_t, 1, 'a', "Cache hits")
MAC_STAT(cache_hitpass,		uint64_t, 1, 'a', "Cache hits for pass")
MAC_STAT(cache_miss,		uint64_t, 1, 'a', "Cache misses")

MAC_STAT(backend_conn,		uint64_t, 0, 'a', "Backend conn. success")
MAC_STAT(backend_unhealthy,	uint64_t, 0, 'a', "Backend conn. not attempted")
MAC_STAT(backend_busy,		uint64_t, 0, 'a', "Backend conn. too many")
MAC_STAT(backend_fail,		uint64_t, 0, 'a', "Backend conn. failures")
MAC_STAT(backend_reuse,		uint64_t, 0, 'a', "Backend conn. reuses")
MAC_STAT(backend_toolate,	uint64_t, 0, 'a', "Backend conn. was closed")
MAC_STAT(backend_recycle,	uint64_t, 0, 'a', "Backend conn. recycles")
MAC_STAT(backend_unused,	uint64_t, 0, 'a', "Backend conn. unused")

MAC_STAT(fetch_head,		uint64_t, 1, 'a', "Fetch head")
MAC_STAT(fetch_length,		uint64_t, 1, 'a', "Fetch with Length")
MAC_STAT(fetch_chunked,		uint64_t, 1, 'a', "Fetch chunked")
MAC_STAT(fetch_eof,		uint64_t, 1, 'a', "Fetch EOF")
MAC_STAT(fetch_bad,		uint64_t, 1, 'a', "Fetch had bad headers")
MAC_STAT(fetch_close,		uint64_t, 1, 'a', "Fetch wanted close")
MAC_STAT(fetch_oldhttp,		uint64_t, 1, 'a', "Fetch pre HTTP/1.1 closed")
MAC_STAT(fetch_zero,		uint64_t, 1, 'a', "Fetch zero len")
MAC_STAT(fetch_failed,		uint64_t, 1, 'a', "Fetch failed")

MAC_STAT(n_sess_mem,		uint64_t, 0, 'i', "N struct sess_mem")
MAC_STAT(n_sess,		uint64_t, 0, 'i', "N struct sess")
MAC_STAT(n_object,		uint64_t, 1, 'i', "N struct object")
MAC_STAT(n_vampireobject,	uint64_t, 1, 'i', "N unresurrected objects")
MAC_STAT(n_objectcore,		uint64_t, 1, 'i', "N struct objectcore")
MAC_STAT(n_objecthead,		uint64_t, 1, 'i', "N struct objecthead")
MAC_STAT(n_smf,			uint64_t, 0, 'i', "N struct smf")
MAC_STAT(n_smf_frag,		uint64_t, 0, 'i', "N small free smf")
MAC_STAT(n_smf_large,		uint64_t, 0, 'i', "N large free smf")
MAC_STAT(n_vbe_conn,		uint64_t, 0, 'i', "N struct vbe_conn")
MAC_STAT(n_wrk,			uint64_t, 0, 'i', "N worker threads")
MAC_STAT(n_wrk_create,		uint64_t, 0, 'a', "N worker threads created")
MAC_STAT(n_wrk_failed,		uint64_t, 0, 'a',
					"N worker threads not created")
MAC_STAT(n_wrk_max,		uint64_t, 0, 'a', "N worker threads limited")
MAC_STAT(n_wrk_queue,		uint64_t, 0, 'a', "N queued work requests")
MAC_STAT(n_wrk_overflow,	uint64_t, 0, 'a', "N overflowed work requests")
MAC_STAT(n_wrk_drop,		uint64_t, 0, 'a', "N dropped work requests")
MAC_STAT(n_backend,		uint64_t, 0, 'i', "N backends")

MAC_STAT(n_expired,		uint64_t, 0, 'i', "N expired objects")
MAC_STAT(n_lru_nuked,		uint64_t, 0, 'i', "N LRU nuked objects")
MAC_STAT(n_lru_saved,		uint64_t, 0, 'i', "N LRU saved objects")
MAC_STAT(n_lru_moved,		uint64_t, 0, 'i', "N LRU moved objects")
MAC_STAT(n_deathrow,		uint64_t, 0, 'i', "N objects on deathrow")

MAC_STAT(losthdr,		uint64_t, 0, 'a', "HTTP header overflows")

MAC_STAT(n_objsendfile,		uint64_t, 0, 'a', "Objects sent with sendfile")
MAC_STAT(n_objwrite,		uint64_t, 0, 'a', "Objects sent with write")
MAC_STAT(n_objoverflow,		uint64_t, 1, 'a',
					"Objects overflowing workspace")

MAC_STAT(s_sess,		uint64_t, 1, 'a', "Total Sessions")
MAC_STAT(s_sess_timeout,	uint64_t, 1, 'a', "Total Session timeout")
MAC_STAT(s_req,			uint64_t, 1, 'a', "Total Requests")
MAC_STAT(s_pipe,		uint64_t, 1, 'a', "Total pipe")
MAC_STAT(s_pass,		uint64_t, 1, 'a', "Total pass")
MAC_STAT(s_fetch,		uint64_t, 1, 'a', "Total fetch")
MAC_STAT(s_hdrbytes,		uint64_t, 1, 'a', "Total header bytes")
MAC_STAT(s_bodybytes,		uint64_t, 1, 'a', "Total body bytes")

MAC_STAT(sess_closed,		uint64_t, 1, 'a', "Session Closed")
MAC_STAT(sess_pipeline,		uint64_t, 1, 'a', "Session Pipeline")
MAC_STAT(sess_readahead,	uint64_t, 1, 'a', "Session Read Ahead")
MAC_STAT(sess_linger,		uint64_t, 1, 'a', "Session Linger")
MAC_STAT(sess_herd,		uint64_t, 1, 'a', "Session herd")

MAC_STAT(shm_records,		uint64_t, 0, 'a', "SHM records")
MAC_STAT(shm_writes,		uint64_t, 0, 'a', "SHM writes")
MAC_STAT(shm_flushes,		uint64_t, 0, 'a', "SHM flushes due to overflow")
MAC_STAT(shm_cont,		uint64_t, 0, 'a', "SHM MTX contention")
MAC_STAT(shm_cycles,		uint64_t, 0, 'a', "SHM cycles through buffer")

MAC_STAT(sm_nreq,		uint64_t, 0, 'a', "allocator requests")
MAC_STAT(sm_nobj,		uint64_t, 0, 'i', "outstanding allocations")
MAC_STAT(sm_balloc,		uint64_t, 0, 'i', "bytes allocated")
MAC_STAT(sm_bfree,		uint64_t, 0, 'i', "bytes free")

MAC_STAT(sma_nreq,		uint64_t, 0, 'a', "SMA allocator requests")
MAC_STAT(sma_nobj,		uint64_t, 0, 'i', "SMA outstanding allocations")
MAC_STAT(sma_nbytes,		uint64_t, 0, 'i', "SMA outstanding bytes")
MAC_STAT(sma_balloc,		uint64_t, 0, 'i', "SMA bytes allocated")
MAC_STAT(sma_bfree,		uint64_t, 0, 'i', "SMA bytes free")

MAC_STAT(sms_nreq,		uint64_t, 0, 'a', "SMS allocator requests")
MAC_STAT(sms_nobj,		uint64_t, 0, 'i', "SMS outstanding allocations")
MAC_STAT(sms_nbytes,		uint64_t, 0, 'i', "SMS outstanding bytes")
MAC_STAT(sms_balloc,		uint64_t, 0, 'i', "SMS bytes allocated")
MAC_STAT(sms_bfree,		uint64_t, 0, 'i', "SMS bytes freed")

MAC_STAT(backend_req,		uint64_t, 0, 'a', "Backend requests made")

MAC_STAT(n_vcl,			uint64_t, 0, 'a', "N vcl total")
MAC_STAT(n_vcl_avail,		uint64_t, 0, 'a', "N vcl available")
MAC_STAT(n_vcl_discard,		uint64_t, 0, 'a', "N vcl discarded")

MAC_STAT(n_purge,		uint64_t, 0, 'i', "N total active purges")
MAC_STAT(n_purge_add,		uint64_t, 0, 'a', "N new purges added")
MAC_STAT(n_purge_retire,	uint64_t, 0, 'a', "N old purges deleted")
MAC_STAT(n_purge_obj_test,	uint64_t, 0, 'a', "N objects tested")
MAC_STAT(n_purge_re_test,	uint64_t, 0, 'a', "N regexps tested against")
MAC_STAT(n_purge_dups,		uint64_t, 0, 'a', "N duplicate purges removed")

MAC_STAT(hcb_nolock,		uint64_t, 0, 'a', "HCB Lookups without lock")
MAC_STAT(hcb_lock,		uint64_t, 0, 'a', "HCB Lookups with lock")
MAC_STAT(hcb_insert,		uint64_t, 0, 'a', "HCB Inserts")

MAC_STAT(esi_parse,		uint64_t, 0, 'a', "Objects ESI parsed (unlock)")
MAC_STAT(esi_errors,		uint64_t, 0, 'a', "ESI parse errors (unlock)")
MAC_STAT(accept_fail,		uint64_t, 0, 'a', "Accept failures")
MAC_STAT(client_drop_late,	uint64_t, 0, 'a', "Connection dropped late")
MAC_STAT(uptime,		uint64_t, 0, 'a', "Client uptime")

MAC_STAT(backend_retry,		uint64_t, 0, 'a', "Backend conn. retry")

MAC_STAT(dir_dns_lookups,	uint64_t, 0, 'a', "DNS director lookups")
MAC_STAT(dir_dns_failed,	uint64_t, 0, 'a', "DNS director failed lookups")
MAC_STAT(dir_dns_hit,		uint64_t, 0, 'a', "DNS director cached lookups hit")
MAC_STAT(dir_dns_cache_full,	uint64_t, 0, 'a', "DNS director full dnscache")

MAC_STAT(fetch_1xx,		uint64_t, 1, 'a', "Fetch no body (1xx)")
MAC_STAT(fetch_204,		uint64_t, 1, 'a', "Fetch no body (204)")
MAC_STAT(fetch_304,		uint64_t, 1, 'a', "Fetch no body (304)")

MAC_STAT(n_drainpipe_mem,	uint64_t, 0, 'a', "N drainpipe entry")
MAC_STAT(n_drainpipe,		uint64_t, 0, 'a', "N drainpipe active")
MAC_STAT(n_drainpipe_wait,	uint64_t, 0, 'a', "N drainpipe on the waiting")

MAC_STAT(socks_req,		uint64_t, 1, 'a', "SOCKS request received")
MAC_STAT(socks_v4_req,		uint64_t, 1, 'a', "SOCKSv4 request received")
MAC_STAT(socks_v4a_req,		uint64_t, 1, 'a', "SOCKSv4a request received")
MAC_STAT(socks_v4_error,	uint64_t, 1, 'a', "SOCKSv4 error")
MAC_STAT(socks_v5_auth,		uint64_t, 1, 'a', "SOCKSv5 auth received")
MAC_STAT(socks_v5_error,	uint64_t, 1, 'a', "SOCKSv5 error")
MAC_STAT(socks_timeout,		uint64_t, 1, 'a', "SOCKS timeout")

MAC_STAT(tunnel_req,		uint64_t, 1, 'a', "TUNNEL request received")

MAC_STAT(pipe_callout_client,	uint64_t, 0, 'a', "client callout PIPE write")
MAC_STAT(pipe_callout_backend,	uint64_t, 0, 'a', "backend callout PIPE write")

MAC_STAT(n_geoip,		uint64_t, 0, 'a', "N GeoIP total")
MAC_STAT(n_geoip_avail,		uint64_t, 0, 'a', "N GeoIP available")
MAC_STAT(n_geoip_discard,	uint64_t, 0, 'a', "N GeoIP discarded")

MAC_STAT(range_req,		uint64_t, 0, 'a', "N range requests")
MAC_STAT(range_single,		uint64_t, 0, 'a', "Single range byte")
MAC_STAT(range_multi,		uint64_t, 0, 'a', "Multiple range bytes")
MAC_STAT(range_badfmt,		uint64_t, 0, 'a', "Bad range format")

MAC_STAT(readypipe_readfail,	uint64_t, 0, 'a', "read(2) failed to the readypipe")
MAC_STAT(readypipe_writefail,	uint64_t, 0, 'a', "write(2) faileed to the readypipe")

MAC_STAT(n_gethostbyname,	uint64_t, 0, 'a', "N gethostbyname(3) call")
