#ifndef PBKDF2_SHA512_H
#define PBKDF2_SHA512_H

#include <stdint.h>
#include <stdlib.h>

#ifdef WIN32
#ifdef XHASH_BUILD_LIB
#define XHASH_EXPORT __declspec(dllexport)
#else
#define XHASH_EXPORT __declspec(dllimport)
#endif
#else
#define XHASH_EXPORT
#endif

XHASH_EXPORT
void PBKDF2_SHA512(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#endif