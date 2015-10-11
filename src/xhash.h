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

#include <stddef.h>

/*********************************************************************
 *
 * MODIFY THE BELOW SALT SO THAT YOUR APPLICATION WILL HAVE A UNIQUE
 * SALT, MAKING PASSWORDS MORE DIFFICULT TO CRACK
 * (You can use https://www.grc.com/passwords.htm to generate a value)
 *
 ********************************************************************/
#define INTERNAL_SALT "AXHwyuIHKoC1jeOgl0Di2f3s9hSDpjOaVP8xD7X6bVu"

#define XHASH_MULTIPLIER_BITS 4
#define XHASH_MULTIPLIER (1 << XHASH_MULTIPLIER_BITS)

#define XHASH_DIGEST_BITS 6
#define XHASH_DIGEST_SIZE (1 << XHASH_DIGEST_BITS)

/* Besides the error codes, this is probably the only #define you'll use. 
   The size includes the terminating null. */
#define XHASH_BASE64_DIGEST_SIZE 89

#define XHASH_DEFAULT_MEMORY_BITS 22

#define XHASH_MIN_MEMORY_BITS (XHASH_MULTIPLIER_BITS + XHASH_DIGEST_BITS)
#define XHASH_MAX_MEMORY_BITS 31

#define XHASH_SUCCESS 0
#define XHASH_ERROR_NULL_HANDLE -1
#define XHASH_ERROR_HANDLE_NOT_INIT -2
/* memory_multiplier_bits must be between 10 and 31 inclusive. default is 22 */
#define XHASH_ERROR_INVALID_MEMORY_BITS -3
#define XHASH_ERROR_NULL_DIGEST -4
#define XHASH_ERROR_NULL_DATA -5
#define XHASH_ERROR_NULL_SALT -6
#define XHASH_ERROR_MALLOC_FAILED -7

#ifdef WIN32
	#ifdef XHASH_BUILD_LIB
		#define XHASH_EXPORT __declspec(dllexport)
	#else
		#define XHASH_EXPORT __declspec(dllimport)
	#endif
#else
	#define XHASH_EXPORT
#endif

/* Do not modify this struct yourself. Use xhash_init */
typedef struct xhash_settings
{
	unsigned char *system_salt;
	size_t system_salt_len;
	size_t mixing_iterations;
	size_t fill_amount;
	size_t memory_blocks;
	size_t memory_usage;	/* Memory usage in bytes. The only member of this struct you'll probably use */
	unsigned char *hash_array;
} xhash_settings;


#ifdef __cplusplus
extern "C" {
#endif

	/* Call one of the init functions first, passing in a pointer to a xhash_settings struct to fill. */
	/* Use a good source of randomness to generate at least 32 bytes for the system_salt.
	   Store the system_salt somewhere separate from the per-user salt.
	   Allocates (1 << memory_bits) bytes of memory and xhash will perform (1 << (memory_bits - 10)) iterations by default.
	   E.g., with the memory_bits default of 22, then 4 MB of memory is allocated and 4192 iterations are performed. */
	XHASH_EXPORT
	int xhash_init(xhash_settings *handle, const void *system_salt, size_t system_salt_len, size_t memory_bits, size_t additional_iterations);

	XHASH_EXPORT
	int xhash_init_defaults(xhash_settings *handle, const void *system_salt, size_t system_salt_len);

	/* Hash the specified data with the specified salt and return the resulting hash in digest
	   (digest must point to an unsigned char[XHASH_DIGEST_SIZE]).
	   Use xhash_text for a friendlier interface when working with null-terminated passwords
	   and user salts.
	   May call xhash or xhash_text as many times as you'd like after calling 
	   xhash_init or xhash_init_defaults and before calling xhash_free.
	   Pass 1 for free_after to avoid having to call xhash_free. You must then call xhash_init
	   again before calling xhash or xhash_text again. */
	XHASH_EXPORT
	int xhash(xhash_settings *handle, unsigned char *digest, const void *data, size_t data_len, const void *salt, size_t salt_len, int free_after);

	/* Hashes the null-terminated password with the null-terminated user_salt and
	   returns a base64-encoded result into base64_digest. 
	   (base64_digest must point to a char[XHASH_BASE64_DIGEST_SIZE]) */
	XHASH_EXPORT
	int xhash_text(xhash_settings *handle, char *base64_digest, const char *password, const char *user_salt, int free_after);

	/* Frees the memory referenced by xhash_settings. Must call once per xhash_init and before
	   calling xhash_init again with the same xhash_settings handle.
	   Does not free the memory used by xhash_settings itself, if it was allocated dynamically 
	   (But there's generally no reason to do so; the xhash_settings object should have 
	   automatic or static scope.) */
	XHASH_EXPORT
	void xhash_free(xhash_settings *handle);

#ifdef __cplusplus
}
#endif

#endif
