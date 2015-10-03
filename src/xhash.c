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

/* The Hash algorithm is divided into two parts. First, we fill an array with
each iterative result of a SHA512 hash of the password+salt.
Then we "randomly" select cells in this array to hash with the running hash
and then xor back into that cell, which makes "random" changes to the array,
forcing the runner of this algorithm to maintain the state of the whole array
and not being able to easily reproduce what a specific cell contains.
We divide the number of requested iterations between the two parts such that
there is at least twice as many iterations done in the second part as the
first so that the array is sufficientally "mixed up"
*/

#define XHASH_BUILD_LIB
#include "xhash.h"
#include "base64.h"
#include "sha512.h"
#include "pbkdf2_sha512.h"
#include <string.h>
#include <stdlib.h>

#define INTERNAL_SALT_LEN (sizeof internal_salt - 1)

char internal_salt[] = "AXHwyuIHKoC1jeOgl0Di2f3s9hSDpjOaVP8xD7X6bVu";


int xhash_init(xhash_settings *handle, const void *system_salt, size_t system_salt_len, size_t memory_bits, size_t additional_iterations)
{
	size_t fill_blocks;
	size_t fill_amount;
	size_t memory_usage;

	if (memory_bits < XHASH_MIN_MEMORY_BITS || memory_bits > XHASH_MAX_MEMORY_BITS)
		return XHASH_ERROR_INVALID_MEMORY_BITS;
	if (!handle)
		return XHASH_ERROR_NULL_HANDLE;
	if (!system_salt && system_salt_len > 0)
		return XHASH_ERROR_NULL_SALT;

	handle->system_salt = malloc(system_salt_len + INTERNAL_SALT_LEN);

	if (!handle->system_salt)
		return XHASH_ERROR_MALLOC_FAILED;

	memcpy(handle->system_salt, internal_salt, INTERNAL_SALT_LEN);
	memcpy(handle->system_salt + INTERNAL_SALT_LEN, system_salt, system_salt_len);

	fill_blocks = (1 << (memory_bits - XHASH_MULTIPLIER_BITS - XHASH_DIGEST_BITS));
	fill_amount = fill_blocks * XHASH_DIGEST_SIZE;
	memory_usage = fill_amount * XHASH_MULTIPLIER;

	handle->system_salt_len = system_salt_len + INTERNAL_SALT_LEN;
	handle->mixing_iterations = fill_blocks * 2 + additional_iterations;  /* # of times we call crypto_hash_sha512 */
	handle->fill_amount = fill_amount;
	handle->memory_blocks = fill_blocks * XHASH_MULTIPLIER;
	handle->memory_usage = memory_usage;

	handle->hash_array = malloc(memory_usage + XHASH_DIGEST_SIZE); /* add one because we'll store the running hash there */

	if (!handle->hash_array)
	{
		free(handle->system_salt);
		return XHASH_ERROR_MALLOC_FAILED;
	}

	return XHASH_SUCCESS;
}


int xhash_init_defaults(xhash_settings *handle, const void *system_salt, size_t system_salt_len)
{
	return xhash_init(handle, system_salt, system_salt_len, XHASH_DEFAULT_MEMORY_BITS, 0);
}


void xhash_free(xhash_settings *handle)
{
	free(handle->system_salt);
	free(handle->hash_array);

	handle->system_salt = 0;
	handle->hash_array = 0;
	handle->system_salt_len = handle->mixing_iterations = handle->fill_amount = handle->memory_usage = 0;
}


int xhash(xhash_settings *handle, unsigned char *digest, const void *data, size_t data_len, const void *salt, size_t salt_len, int free_after)
{
	int error = XHASH_SUCCESS;
	size_t bitmask;
	size_t combined_hash_len;
	size_t combined_salt_len;
	size_t system_salt_len;
	size_t memory_blocks;
	size_t fill_amount;
	size_t mixing_iterations;
	size_t i, m, b;
	size_t next_index;

	/* we have a single running hash, but then we combine it with "randomly"-selected cells from the array */
	unsigned char combined_hash[(XHASH_MULTIPLIER + 1) * XHASH_DIGEST_SIZE];
	unsigned char *block_starts[XHASH_MULTIPLIER];
	unsigned char *block_start;
	unsigned char *dest;
	unsigned char *source;
	unsigned char *hash_array;
	unsigned char *combined_salt;
	unsigned char *system_salt;

	if (!handle)
		return XHASH_ERROR_NULL_HANDLE;
	if (!handle->system_salt || !handle->hash_array || handle->fill_amount == 0 || handle->memory_usage == 0)
		return XHASH_ERROR_HANDLE_NOT_INIT;
	if (!digest)
		error = XHASH_ERROR_NULL_DIGEST;
	if (!data && data_len > 0)
		error = XHASH_ERROR_NULL_DATA;
	if (!salt && salt_len > 0)
		error = XHASH_ERROR_NULL_SALT;

	if (error)
	{
		if (free_after) 
			xhash_free(handle);
		return error;
	}

	system_salt = handle->system_salt;
	system_salt_len = handle->system_salt_len;
	hash_array = handle->hash_array;
	memory_blocks = handle->memory_blocks;
	mixing_iterations = handle->mixing_iterations;

	/* memory_blocks is always a power of 2 */
	bitmask = memory_blocks - 1;
	combined_hash_len = (XHASH_MULTIPLIER + 1) * XHASH_DIGEST_SIZE;
	fill_amount = handle->fill_amount;

	source = dest = handle->hash_array;

	combined_salt_len = system_salt_len + salt_len;
	combined_salt = malloc(combined_salt_len);

	if (!combined_salt)
	{
		if (free_after)
			xhash_free(handle);
		return XHASH_ERROR_MALLOC_FAILED;
	}

	memcpy(combined_salt, system_salt, system_salt_len);
	memcpy(combined_salt + system_salt_len, salt, salt_len);

	PBKDF2_SHA512(data, data_len, combined_salt, combined_salt_len, 1, hash_array, fill_amount + XHASH_DIGEST_SIZE);

	/* initialize the running hash to what comes out of PBKDF2 after the hash_array is filled */
	memcpy(digest, hash_array + fill_amount, XHASH_DIGEST_SIZE);

	for (i = 1; i < XHASH_MULTIPLIER; i++)
	{
		dest += fill_amount;
		memcpy(dest, source, fill_amount);
	}


	/* now "randomly mix up" the hash array */
	for (i = 0; i < mixing_iterations; i++)
	{
		size_t combined_hash_end = XHASH_DIGEST_SIZE;

		/* combine the running hash with... */
		memcpy(combined_hash, digest, XHASH_DIGEST_SIZE);

		/* ..."randomly"-selected cells in the hash array */
		for (m = 0; m < XHASH_MULTIPLIER; m++)
		{
			/* create a random int from bytes in the running hash and interpret the int as which cell to get a hash from.
			Since hashes are 64 bytes long and ints are 4 bytes, we can only get 16 random indexes from the hash,
			which is why _multiplier is limited to 16. */
			next_index = ((unsigned int)(digest[m * 4] + (digest[m * 4 + 1] << 8) + (digest[m * 4 + 2] << 16)) + 
				((unsigned int)digest[m * 4 + 3] << 24U)) & bitmask;

			/* add that selected hash to the combined hash */
			block_starts[m] = block_start = hash_array + (next_index * XHASH_DIGEST_SIZE);
			memcpy(combined_hash + combined_hash_end, block_start, XHASH_DIGEST_SIZE);
			combined_hash_end += XHASH_DIGEST_SIZE;
		}

		/* update the running hash */
		crypto_hash_sha512(digest, combined_hash, combined_hash_len);

		for (m = 0; m < XHASH_MULTIPLIER; m++)
		{
			block_start = block_starts[m];
			/* xor the selected hash with the running hash so that the hash array is constantly being modified */
			for (b = 0; b < XHASH_DIGEST_SIZE; b++)
				block_start[b] ^= digest[b];
		}
	}

	crypto_hash_sha512(digest, hash_array, handle->memory_usage);

	if (free_after)
		xhash_free(handle);

	return XHASH_SUCCESS;
}


int xhash_text(xhash_settings *handle, char *base64_digest, const char *password, const char *user_salt, int free_after)
{
	unsigned char digest[XHASH_DIGEST_SIZE];
	int error = xhash(handle, digest, password, strlen(password), user_salt, strlen(user_salt), free_after);

	if (error)
		return error;

	base64encode(digest, XHASH_DIGEST_SIZE, base64_digest, XHASH_BASE64_DIGEST_SIZE);
	return XHASH_SUCCESS;
}
