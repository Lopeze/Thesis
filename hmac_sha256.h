#ifndef __HMAC_SHA256_H__
#define __HMAC_SHA256_H__

#include <stdint.h>
#include <sys/types.h>

<<<<<<< HEAD
#include "sha256.h"

struct hmac_sha256_state_struct {
  struct sha256_state_struct s;
  uint8_t inner_key[SHA256_BLOCK_SIZE];
  uint8_t outer_key[SHA256_BLOCK_SIZE];
  uint8_t key[SHA256_DIGEST_SIZE];
  /* uint8_t digest[SHA256_DIGEST_SIZE]; */
};
typedef struct hmac_sha256_state_struct *Hmac_state_t;


/* uint8_t *HMAC_SHA256(uint8_t *result, const uint8_t *key, const size_t keysize, const uint8_t *data, const size_t datasize); */

int hmac_sha256_set_key(Hmac_state_t h, const uint8_t *key, size_t key_size);

int hmac_sha256_init(Hmac_state_t h);

int hmac_sha256_update(Hmac_state_t h, const uint8_t *data, size_t data_size);

int hmac_sha256_final(uint8_t *digest, Hmac_state_t h);
 
=======

uint8_t *HMAC_SHA256(uint8_t *result, const uint8_t *key, const size_t keysize, const uint8_t *data, const size_t datasize);
>>>>>>> f23ec8d6e6321f6e2c620d3d105d6b75dd93940f

#endif
