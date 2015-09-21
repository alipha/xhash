/*
The MIT License (MIT)

Copyright (c) 2015 Kevin Spinar (Alipha)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef XHASH_H
#define XHASH_H

#include <inttypes.h>

#define XHASH_DEFAULT_ITERATIONS 12500
#define XHASH_DEFAULT_MEMORY_BITS 4

#define XHASH_MAX_MEMORY_BITS 4
#define XHASH_MIN_ITERATIONS 3

#define XHASH_DIGEST_SIZE 64
#define XHASH_BASE64_DIGEST_SIZE 89

#define XHASH_SUCCESS 0
#define XHASH_ERROR_NULL_HANDLE -1
#define XHASH_ERROR_HANDLE_NOT_INIT -2
/* iterations must be >= 3 */
#define XHASH_ERROR_INVALID_ITERATIONS -3
/* memory_multiplier_bits must be between 0 and 4 inclusive */
#define XHASH_ERROR_INVALID_MEMORY_MULTIPLIER -4
#define XHASH_ERROR_NULL_DIGEST -5
#define XHASH_ERROR_NULL_DATA -6
#define XHASH_ERROR_NULL_SALT -7
#define XHASH_ERROR_MALLOC_FAILED -8

#ifdef WIN32
	#ifdef XHASH_BUILD_LIB
		#define XHASH_EXPORT __declspec(dllexport)
	#else
		#define XHASH_EXPORT __declspec(dllimport)
	#endif
#else
	#define XHASH_EXPORT
#endif

/*
Memory usage:
Find the largest power of two <= (iterations / 3)
memory_used == power_of_2 * (1 << memory_multiplier_bits) * 64
*/

/* Do not modify this struct yourself. Use xhash_init */
typedef struct xhash_settings
{
	unsigned char *system_salt;
	size_t system_salt_len;
	size_t iterations;
	size_t multiplier;
	size_t mixing_iterations;
	size_t hash_array_size;		/* memory usage: hash_array_size * XHASH_DIGEST_SIZE */
	unsigned char *hash_array;
} xhash_settings;


#ifdef __cplusplus
extern "C" {
#endif

	/* call one of the init functions first, passing in a pointer to a xhash_settings to fill */
	XHASH_EXPORT
	int xhash_init(xhash_settings *handle, const void *system_salt, size_t system_salt_len,
	size_t iterations, size_t memory_multiplier_bits);

	XHASH_EXPORT
	int xhash_init_defaults(xhash_settings *handle, const void *system_salt, size_t system_salt_len);

	XHASH_EXPORT
	int xhash(xhash_settings *handle, unsigned char *digest, const void *data, size_t data_len,
	const void *salt, size_t salt_len, int free_after);

	XHASH_EXPORT
	int xhash_text(xhash_settings *handle, char *base64_digest, const char *password, const char *user_salt, int free_after);

	XHASH_EXPORT
	void xhash_free(xhash_settings *handle);

#ifdef __cplusplus
}
#endif

#endif
