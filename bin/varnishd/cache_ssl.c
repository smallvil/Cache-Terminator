/*-
 * Copyright (c) 2011 Weongyo Jeong
 * All rights reserved.
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
 */

#include "config.h"

#include "svnid.h"
SVNID("$Id: cache_ssl.c 145 2011-04-15 18:58:22Z jwg286 $")

#include <sys/param.h>
#include <sys/uio.h>
#include <stdio.h>
#include "shmlog.h"
#include "cache.h"

static pthread_rwlock_t *ssl_lock;

ssize_t
XXL_writev(SSL *ssl, const struct iovec *vector, int count)
{
	char *bp, *buffer;
	ssize_t bytes, copy, to_copy;
	int i;

	bytes = 0;
	for (i = 0; i < count; ++i)
		bytes += vector[i].iov_len;
	/* XXX SEGFAULT if data is over stack size. */
	buffer = (char *)alloca(bytes);
	to_copy = bytes;
	bp = buffer;
	for (i = 0; i < count; ++i) {
		copy = MIN(vector[i].iov_len, to_copy);
		memcpy ((void *) bp, (void *) vector[i].iov_base, copy);
		bp += copy;

		to_copy -= copy;
		if (to_copy == 0)
			break;
	}
	return SSL_write(ssl, buffer, bytes);
}

void
XXL_free(SSL **ssl)
{

	SSL_free(*ssl);
	*ssl = NULL;
}

void
XXL_error(void)
{
	unsigned long error;
	char buf[BUFSIZ];

	while ((error = ERR_get_error()) != 0) {
		buf[0] = '\0';
		ERR_error_string_n(error, buf, sizeof(buf));
		printf("%s\n", buf);
	}
}

static unsigned long
XXL_thrid_cb(void)
{

	return ((unsigned long)pthread_self());
}

static void
XXL_lock_cb(int mode, int type, const char *file, int line)
{
	int n;
	(void)file;
	(void)line;

	assert((mode & (CRYPTO_READ | CRYPTO_WRITE)) !=
	    (CRYPTO_READ | CRYPTO_WRITE));
	if (mode & CRYPTO_LOCK) {
		/*
		 * If neither CRYPTO_READ nor CRYPTO_WRITE defined
		 * assume exclusive lock.
		 */
		if (mode & CRYPTO_READ)
			n = pthread_rwlock_rdlock(&ssl_lock[type]);
		else
			n = pthread_rwlock_wrlock(&ssl_lock[type]);
	} else if (mode & CRYPTO_UNLOCK) {
		n = pthread_rwlock_unlock(&ssl_lock[type]);
	} else
		assert(0 == 1);
	assert(n == 0);
}

void
XXL_Init(void)
{
	int i, n, rc;

	SSL_load_error_strings();
	SSL_library_init();
	rc =RAND_status();
	assert(rc == 1);

	n = CRYPTO_num_locks();
	ssl_lock = (pthread_rwlock_t *)OPENSSL_malloc(n *
	    sizeof(pthread_rwlock_t));
	bzero(ssl_lock, n * sizeof(pthread_rwlock_t));
	for (i = 0; i < n; i++) {
		rc = pthread_rwlock_init(&ssl_lock[i], NULL);
		assert(rc == 0);
	}
	/* Set callbacks for static locking. */
        CRYPTO_set_id_callback(XXL_thrid_cb);
        CRYPTO_set_locking_callback(XXL_lock_cb);

}
