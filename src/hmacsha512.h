#ifndef crypto_auth_hmacsha512_H
#define crypto_auth_hmacsha512_H

#include <stddef.h>
#include "sha512.h"

#ifdef __cplusplus
# if __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_auth_hmacsha512_BYTES 64U
#define crypto_auth_hmacsha512_KEYBYTES 32U

	size_t crypto_auth_hmacsha512_bytes(void);

	size_t crypto_auth_hmacsha512_keybytes(void);

	int crypto_auth_hmacsha512(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k);

	int crypto_auth_hmacsha512_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k);

	/* ------------------------------------------------------------------------- */

	typedef struct crypto_auth_hmacsha512_state {
		crypto_hash_sha512_state ictx;
		crypto_hash_sha512_state octx;
	} crypto_auth_hmacsha512_state;

	size_t crypto_auth_hmacsha512_statebytes(void);

	int crypto_auth_hmacsha512_init(crypto_auth_hmacsha512_state *state, const unsigned char *key, size_t keylen);

	int crypto_auth_hmacsha512_update(crypto_auth_hmacsha512_state *state, const unsigned char *in, unsigned long long inlen);

	int crypto_auth_hmacsha512_final(crypto_auth_hmacsha512_state *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
