#ifndef __HMAC_SHA256_H__
#define __HMAC_SHA256_H__

#include <stdint.h>
#include <sys/types.h>


uint8_t *HMAC_SHA256(uint8_t *result, const uint8_t *key, const size_t keysize, const uint8_t *data, const size_t datasize);

#endif
