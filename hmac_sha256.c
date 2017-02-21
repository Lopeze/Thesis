#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h> // should all of the includes be in alphabetical order?
#include <stdlib.h>
#include <inttypes.h>

#include "sha256.h"
#include "hmac_sha256.h"


int hmac_sha256_set_key(Hmac_state_t h, const uint8_t *key, size_t key_size) {
  if (h == (Hmac_state_t) 0) {
    return 0;
  }
  int i;
  (void) sha256_init(&h->s);

  if (key_size > SHA256_DIGEST_SIZE) {
    (void) sha256_update(&h->s, key, key_size);
    (void) sha256_final(h->key, &h->s);
  }
  if (key_size < SHA256_DIGEST_SIZE) {
    memcpy(h->key, key, key_size);
  }

  for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
    if (i < key_size) {
      h->inner_key[i] = key[i] ^ 0x36;
      h->outer_key[i] = key[i] ^ 0x5c;
    }
    else {
      h->inner_key[i] = 0x36;
      h->outer_key[i] = 0x5c;
    }
  }  
  return 1;
}

int hmac_sha256_init(Hmac_state_t h) {
  /* memset(h->digest, 0x00, SHA256_DIGEST_SIZE); */
  (void) sha256_init(&h->s);
  (void) sha256_update(&h->s, h->inner_key, SHA256_BLOCK_SIZE);
  return 1;
}

int hmac_sha256_update(Hmac_state_t h, const uint8_t *data, size_t data_size) {
  (void) sha256_update(&h->s, data, data_size);
  return 1;
}
int hmac_sha256_final(uint8_t *digest, Hmac_state_t h) {
  (void) sha256_final(digest, &h->s);
  (void) sha256_init(&h->s);
  (void) sha256_update(&h->s, &h->outer_key, SHA256_BLOCK_SIZE);
  (void) sha256_update(&h->s, digest, SHA256_DIGEST_SIZE);
  (void) sha256_final(digest, &h->s);
  return 1;
}
