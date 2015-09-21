#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize);

#ifdef __cplusplus
}
#endif

#endif
