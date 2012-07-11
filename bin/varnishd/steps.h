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
 * $Id: steps.h 42 2011-04-02 06:21:26Z jwg286 $
 */

STEP(first,				FIRST)
STEP(timeout,				TIMEOUT)
STEP(done,				DONE)
/*
 * HTTP protocol
 */
STEP(http_wait_begin,			HTTP_WAIT_BEGIN)
STEP(http_wait_recv,			HTTP_WAIT_RECV)
STEP(http_wait_end,			HTTP_WAIT_END)
STEP(http_recv,				HTTP_RECV)
STEP(http_start,			HTTP_START)
STEP(http_start_continue,		HTTP_START_CONTINUE)
STEP(http_pipe_begin,			HTTP_PIPE_BEGIN)
STEP(http_pipe_getbackend,		HTTP_PIPE_GETBACKEND)
STEP(http_pipe_connect,			HTTP_PIPE_CONNECT)
STEP(http_pipe_hdremit,			HTTP_PIPE_HDREMIT)
STEP(http_pipe_hdrflush,		HTTP_PIPE_HDRFLUSH)
STEP(http_pipe_recv,			HTTP_PIPE_RECV)
STEP(http_pipe_recv_fromclient,		HTTP_PIPE_RECV_FROMCLIENT)
STEP(http_pipe_send,			HTTP_PIPE_SEND)
STEP(http_pipe_send_tobackend,		HTTP_PIPE_SEND_TOBACKEND)
STEP(http_pipe_closewait,		HTTP_PIPE_CLOSEWAIT)
STEP(http_pipe_end,			HTTP_PIPE_END)
STEP(http_pass,				HTTP_PASS)
STEP(http_lookup,			HTTP_LOOKUP)
STEP(http_miss,				HTTP_MISS)
STEP(http_hit,				HTTP_HIT)
STEP(http_hit_req_begin,		HTTP_HIT_REQ_BEGIN)
STEP(http_hit_req_recv,			HTTP_HIT_REQ_RECV)
STEP(http_hit_req_end,			HTTP_HIT_REQ_END)
STEP(http_fetch_begin,			HTTP_FETCH_BEGIN)
STEP(http_fetch_error,			HTTP_FETCH_ERROR)
STEP(http_fetch_retry,			HTTP_FETCH_RETRY)
STEP(http_fetch_getbackend,		HTTP_FETCH_GETBACKEND)
STEP(http_fetch_connect,		HTTP_FETCH_CONNECT)
STEP(http_fetch_prepare,		HTTP_FETCH_PREPARE)
STEP(http_fetch_req,			HTTP_FETCH_REQ)
STEP(http_fetch_req_hdr_flush,		HTTP_FETCH_REQ_HDR_FLUSH)
STEP(http_fetch_req_body_begin,		HTTP_FETCH_REQ_BODY_BEGIN)
STEP(http_fetch_req_body_recv,		HTTP_FETCH_REQ_BODY_RECV)
STEP(http_fetch_req_body_send,		HTTP_FETCH_REQ_BODY_SEND)
STEP(http_fetch_req_body_end,		HTTP_FETCH_REQ_BODY_END)
STEP(http_fetch_resp,			HTTP_FETCH_RESP)
STEP(http_fetch_resp_recv_firstbyte,	HTTP_FETCH_RESP_RECV_FIRSTBYTE)
STEP(http_fetch_resp_recv_nextbytes,	HTTP_FETCH_RESP_RECV_NEXTBYTES)
STEP(http_fetch_resp_hdrdissect,	HTTP_FETCH_RESP_HDRDISSECT)
STEP(http_fetch_resp_body,		HTTP_FETCH_RESP_BODY)
STEP(http_deliver_begin,		HTTP_DELIVER_BEGIN)
STEP(http_deliver_hdr,			HTTP_DELIVER_HDR)
STEP(http_deliver_body_begin,		HTTP_DELIVER_BODY_BEGIN)
STEP(http_deliver_body_wait,		HTTP_DELIVER_BODY_WAIT)
STEP(http_deliver_body_waken,		HTTP_DELIVER_BODY_WAKEN)
STEP(http_deliver_body_prepare,		HTTP_DELIVER_BODY_PREPARE)
STEP(http_deliver_body_send,		HTTP_DELIVER_BODY_SEND)
STEP(http_deliver_body_end,		HTTP_DELIVER_BODY_END)
STEP(http_deliver_end,			HTTP_DELIVER_END)
STEP(http_error,			HTTP_ERROR)
/*
 * SOCKS protocol
 */
STEP(socks_start,			SOCKS_START)
STEP(socks_recv,			SOCKS_RECV)
STEP(socksv4_req,			SOCKSv4_REQ)
STEP(socksv4_connect,			SOCKSv4_CONNECT)
STEP(socksv4_connect_do,		SOCKSv4_CONNECT_DO)
STEP(socksv4_resp,			SOCKSv4_RESP)
STEP(socksv4_send,			SOCKSv4_SEND)
STEP(socksv4_error,			SOCKSv4_ERROR)
STEP(socksv5_auth,			SOCKSv5_AUTH)
STEP(socksv5_sendauth,			SOCKSv5_SENDAUTH)
STEP(socksv5_recv_prepare,		SOCKSv5_RECV_PREPARE)
STEP(socksv5_recv,			SOCKSv5_RECV)
STEP(socksv5_req,			SOCKSv5_REQ)
STEP(socksv5_connect,			SOCKSv5_CONNECT)
STEP(socksv5_connect_do,		SOCKSv5_CONNECT_DO)
STEP(socksv5_resp,			SOCKSv5_RESP)
STEP(socksv5_send,			SOCKSv5_SEND)
STEP(socksv5_error,			SOCKSv5_ERROR)
STEP(socks_pipe,			SOCKS_PIPE)
STEP(socks_pipe_recv,			SOCKS_PIPE_RECV)
STEP(socks_pipe_recv_fromclient,	SOCKS_PIPE_RECV_FROMCLIENT)
STEP(socks_pipe_send,			SOCKS_PIPE_SEND)
STEP(socks_pipe_send_tobackend,		SOCKS_PIPE_SEND_TOBACKEND)
STEP(socks_pipe_end,			SOCKS_PIPE_END)
STEP(socks_end,				SOCKS_END)

/*
 * Transparent tunneling
 */
STEP(tunnel_start,			TUNNEL_START)
STEP(tunnel_connect,			TUNNEL_CONNECT)
STEP(tunnel_pipe,			TUNNEL_PIPE)
STEP(tunnel_pipe_recv,			TUNNEL_PIPE_RECV)
STEP(tunnel_pipe_recv_fromclient,	TUNNEL_PIPE_RECV_FROMCLIENT)
STEP(tunnel_pipe_send,			TUNNEL_PIPE_SEND)
STEP(tunnel_pipe_send_tobackend,	TUNNEL_PIPE_SEND_TOBACKEND)
STEP(tunnel_pipe_end,			TUNNEL_PIPE_END)
STEP(tunnel_end,			TUNNEL_END)
