#ifndef __HMAC_SHA256_H__
#define __HMAC_SHA256_H__

#include <stdint.h>
#include <sys/types.h>

#include "sha256.h"

struct hmac_sha256_state_struct {
  struct sha256_state_struct s;
  uint8_t inner_key[SHA256_BLOCK_SIZE];
  uint8_t outer_key[SHA256_BLOCK_SIZE];
  uint8_t key[SHA256_DIGEST_SIZE];
};
typedef struct hmac_sha256_state_struct *Hmac_state_t;

int hmac_sha256_set_key(Hmac_state_t h, const uint8_t *key, size_t key_size);

int hmac_sha256_init(Hmac_state_t h);

int hmac_sha256_update(Hmac_state_t h, const uint8_t *data, size_t data_size);

int hmac_sha256_final(uint8_t *digest, Hmac_state_t h);
 
#endif
