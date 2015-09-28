/*-
* Kevin Spinar (Alipha) adapted Colin Percival's PBKDF2_SHA256 algorithm to be
* PBKDF2_SHA512 using Colin's crypto_auth_hmacsha512
*
*
* Copyright 2005,2007,2009 Colin Percival
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
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define XHASH_BUILD_LIB

#include "pbkdf2_sha512.h"
#include "hmacsha512.h"
#include "sha512.h"


static void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;

	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

/**
* PBKDF2_SHA512(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
* Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA512 as the PRF, and
* write the output to buf.  The value dkLen must be at most 64 * (2^32 - 1).
*/
void PBKDF2_SHA512(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
	crypto_auth_hmacsha512_state PShctx, hctx;
	size_t          i;
	uint8_t         ivec[4];
	uint8_t         U[64];
	uint8_t         T[64];
	uint64_t        j;
	int             k;
	size_t          clen;

	if (dkLen > 0x1fffffffe0UL) {
		abort();
	}
	crypto_auth_hmacsha512_init(&PShctx, passwd, passwdlen);
	crypto_auth_hmacsha512_update(&PShctx, salt, saltlen);

	for (i = 0; i * 64 < dkLen; i++) {
		be32enc(ivec, (uint32_t)(i + 1));
		memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha512_state));
		crypto_auth_hmacsha512_update(&hctx, ivec, 4);
		crypto_auth_hmacsha512_final(&hctx, U);

		memcpy(T, U, 64);
		/* LCOV_EXCL_START */
		for (j = 2; j <= c; j++) {
			crypto_auth_hmacsha512_init(&hctx, passwd, passwdlen);
			crypto_auth_hmacsha512_update(&hctx, U, 64);
			crypto_auth_hmacsha512_final(&hctx, U);

			for (k = 0; k < 64; k++) {
				T[k] ^= U[k];
			}
		}
		/* LCOV_EXCL_STOP */

		clen = dkLen - i * 64;
		if (clen > 64) {
			clen = 64;
		}
		memcpy(&buf[i * 64], T, clen);
	}
	memset(&PShctx, 0, sizeof PShctx);
}
