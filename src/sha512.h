#ifndef SHA512_H
#define SHA512_H

#define SHA512_DIGEST_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

	void sha512(unsigned char *digest, const unsigned char *message, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif
