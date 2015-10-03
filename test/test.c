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

#include "xhash.h"
#include <stdio.h>
#include <time.h>

//#include "pbkdf2_sha512.h"

char system_salt[] = "Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=";
char user_salt[] = "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp";
char password[] = "foo1";

int main(void) {
	/*
	unsigned char buf[128];
	PBKDF2_SHA512(password, sizeof password - 1, user_salt, sizeof user_salt - 1, 50, buf, sizeof buf);

	for (size_t i = 0; i < sizeof buf; i++)
		printf("%02X", buf[i]);
	puts("\n");
	return 0;
	*/

	xhash_settings hasher;
	char base64_digest[XHASH_BASE64_DIGEST_SIZE];

	//int error = xhash_init_defaults(&hasher, system_salt, sizeof system_salt - 1);
	int error = xhash_init(&hasher, system_salt, sizeof system_salt - 1, 22, 212);

	if (!error)
	{
		long startTime = clock();
		error = xhash_text(&hasher, base64_digest, password, user_salt, 0);
		printf("%ld\n", (clock() - startTime) / (CLOCKS_PER_SEC / 1000));
		printf("%d KB\n", hasher.memory_usage / 1024);
		printf("%d\n", hasher.mixing_iterations);

		xhash_free(&hasher);

		if (!error)
			puts(base64_digest);
	}

	if (error)
		printf("error: %d\n", error);

	getchar();
	return 0;
}
