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
#include <string.h>
#include <stdlib.h>

#define XHASH_MAX_MULTIPLIER (1 << XHASH_MAX_MEMORY_BITS)
#define INTERNAL_SALT_LEN (sizeof internal_salt - 1)

char internal_salt[] = "AXHwyuIHKoC1jeOgl0Di2f3s9hSDpjOaVP8xD7X6bVu";


int xhash_init(xhash_settings *handle, const void *system_salt, size_t system_salt_len,
size_t iterations, size_t memory_multiplier_bits)
{
	size_t hash_array_size = 3; /* 2; */

	if (iterations < XHASH_MIN_ITERATIONS) /* 2) */
		return XHASH_ERROR_INVALID_ITERATIONS;
	if (memory_multiplier_bits < 0 || memory_multiplier_bits > XHASH_MAX_MEMORY_BITS)
		return XHASH_ERROR_INVALID_MEMORY_MULTIPLIER;
	if (!handle)
		return XHASH_ERROR_NULL_HANDLE;
	if (!system_salt && system_salt_len > 0)
		return XHASH_ERROR_NULL_SALT;

	handle->system_salt = malloc(system_salt_len + INTERNAL_SALT_LEN);

	if (!handle->system_salt)
		return XHASH_ERROR_MALLOC_FAILED;

	memcpy(handle->system_salt, internal_salt, INTERNAL_SALT_LEN);
	memcpy(handle->system_salt + INTERNAL_SALT_LEN, system_salt, system_salt_len);

	handle->system_salt_len = system_salt_len + INTERNAL_SALT_LEN;
	handle->iterations = iterations;  /* # of times we call SHA512.ComputeHash */
	handle->multiplier = 1 << memory_multiplier_bits;

	/* We want to pick an array size that's a power of two so that the "random" selection of the next cell is fast to perform */
	while (hash_array_size <= iterations)
		hash_array_size *= 2;

	/* since we started with 3, hash_array_size is, e.g., 1100000, so remove that second 1, making it a power of 2 */
	hash_array_size &= hash_array_size - 1;

	/* Dividing by 4 guarantees that the number of iterations performed in the "random mixing up" step is at least twice as
	many as the # of cells (and potentionally up to 6 times as many) */
	hash_array_size /= 4;

	handle->mixing_iterations = handle->iterations - hash_array_size;
	hash_array_size *= handle->multiplier;

	handle->hash_array_size = hash_array_size;
	handle->hash_array = malloc((hash_array_size + 1) * XHASH_DIGEST_SIZE);

	if (!handle->hash_array)
	{
		free(handle->system_salt);
		return XHASH_ERROR_MALLOC_FAILED;
	}

	return XHASH_SUCCESS;
}


int xhash_init_defaults(xhash_settings *handle, const void *system_salt, size_t system_salt_len)
{
	return xhash_init(handle, system_salt, system_salt_len, XHASH_DEFAULT_ITERATIONS, XHASH_DEFAULT_MEMORY_BITS);
}


void xhash_free(xhash_settings *handle)
{
	free(handle->system_salt);
	free(handle->hash_array);

	handle->system_salt = 0;
	handle->hash_array = 0;
	handle->system_salt_len = handle->hash_array_size = 0;
}


int xhash(xhash_settings *handle, unsigned char *digest, const void *data, size_t data_len,
const void *salt, size_t salt_len, int free_after)
{
	int error = XHASH_SUCCESS;
	size_t bitmask;
	size_t combined_hash_len;
	size_t combined_data_len;
	size_t hash_array_size;
	size_t multiplier;
	size_t mixing_iterations;
	size_t i, m, b;
	size_t next_index;

	/* we have a single running hash, but then we combine it with "randomly"-selected cells from the array */
	unsigned char combined_hash[(XHASH_MAX_MULTIPLIER + 1) * XHASH_DIGEST_SIZE];
	unsigned char *block_starts[XHASH_MAX_MULTIPLIER];
	unsigned char *block_start;
	unsigned char *dest;
	unsigned char *source;
	unsigned char *hash;
	unsigned char *hash_array;
	unsigned char *combined_data;

	if (!handle)
		return XHASH_ERROR_NULL_HANDLE;
	if (!handle->system_salt || !handle->hash_array || handle->hash_array_size == 0)
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


	hash_array = handle->hash_array;
	hash_array_size = handle->hash_array_size;
	multiplier = handle->multiplier;
	mixing_iterations = handle->mixing_iterations;

	/* hash_array_size is always a power of 2 */
	bitmask = hash_array_size - 1;
	combined_hash_len = (multiplier + 1) * XHASH_DIGEST_SIZE;

	source = dest = handle->hash_array;

	combined_data_len = handle->system_salt_len + data_len + salt_len;
	combined_data = malloc(combined_data_len);

	if (!combined_data)
	{
		if (free_after)
			xhash_free(handle);
		return XHASH_ERROR_MALLOC_FAILED;
	}

	/* initialize the hash */
	memcpy(combined_data, data, data_len);
	memcpy(combined_data + data_len, handle->system_salt, handle->system_salt_len);
	memcpy(combined_data + data_len + handle->system_salt_len, salt, salt_len);

	sha512(dest, combined_data, combined_data_len);


	for (i = 0; i < hash_array_size; i += multiplier)
	{
		/* we compute a hash and then we repeat that hash, storing the same hash into "multiplier" # of adjacent cells  */
		for (m = 1; m < multiplier; m++)
		{
			dest += XHASH_DIGEST_SIZE;
			memcpy(dest, source, XHASH_DIGEST_SIZE);
		}

		/* update the running hash */
		dest += XHASH_DIGEST_SIZE;
		sha512(dest, source, XHASH_DIGEST_SIZE);
		source = dest;
	}


	hash = dest;

	/* now "randomly mix up" the hash array for the remaining iterations */
	for (i = 0; i < mixing_iterations; i++)
	{
		/* combine the running hash with... */
		memcpy(combined_hash, hash, XHASH_DIGEST_SIZE);

		/* ..."randomly"-selected cells in the hash array */
		for (m = 0; m < multiplier; m++)
		{
			/* create a random int from bytes in the running hash and interpret the int as which cell to get a hash from.
			Since hashes are 64 bytes long and ints are 4 bytes, we can only get 16 random indexes from the hash,
			which is why _multiplier is limited to 16.
			(We're actually only using 24 bits per int, since that is enough for now, but could expand to 32 bits) */
			next_index = (hash[m * 4] + (hash[m * 4 + 1] << 8) + (hash[m * 4 + 2] << 16)) & bitmask;

			/* add that selected hash to the combined hash */
			block_starts[m] = block_start = hash_array + (next_index * XHASH_DIGEST_SIZE);
			memcpy(combined_hash + XHASH_DIGEST_SIZE * (m + 1), block_start, XHASH_DIGEST_SIZE);
		}

		/* update the running hash */
		sha512(hash, combined_hash, combined_hash_len);

		for (m = 0; m < multiplier; m++)
		{
			block_start = block_starts[m];
			/* xor the selected hash with the running hash so that the hash array is constantly being modified */
			for (b = 0; b < XHASH_DIGEST_SIZE; b++)
				block_start[b] ^= hash[b];
		}
	}

	memcpy(digest, hash, XHASH_DIGEST_SIZE);

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
