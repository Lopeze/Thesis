#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h> // should all of the includes be in alphabetical order?
#include <stdlib.h>
#include <inttypes.h>

#include "sha256.h"
#include "hmac_sha256.h"

<<<<<<< HEAD

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
=======
// using scatter-gather interface
uint8_t *HMAC_SHA256(uint8_t *result, const uint8_t *key, const size_t keysize, const uint8_t *data, const size_t datasize) {
  struct sha256_state_struct s; // going to keep reusing this struct for hashes
  int i;
  uint8_t digest[SHA256_DIGEST_SIZE]; // hash output
  (void) sha256_init(&s); // sets initialization vectors
  
  (void) memset(digest, 0x00, sizeof(digest)); // do this before if/else to make sure that when key>blocksize the elements digest[32] to digest[64] are 0x00

  if (keysize > SHA256_DIGEST_SIZE) {
    // if key is bigger than 64 bytes hash
    sha256_update(&s, (const uint8_t *) key, keysize); // hash key
    (void) sha256_final(digest, &s); // key = sha256(key)
    (void) sha256_init(&s); //
  }
  else {
    // if key is less than 64 bytes pad key to be 64 bytes
    (void) memcpy(digest, key, keysize);
  }

  uint8_t o_key_pad[SHA256_BLOCK_SIZE];
  uint8_t i_key_pad[SHA256_BLOCK_SIZE];
  for (i = 0; i < SHA256_DIGEST_SIZE; i++) { // to account for both key < blocksize and key > blocksize
    i_key_pad[i] = digest[i] ^ 0x36;
    o_key_pad[i] = digest[i] ^ 0x5c;
  }
  for (; i < SHA256_BLOCK_SIZE; i++) {
    i_key_pad[i] = 0x36;
    o_key_pad[i] = 0x5c;
  }

  (void) sha256_update(&s, i_key_pad, sizeof(i_key_pad));
  (void) sha256_update(&s, data, datasize);
  sha256_final(digest, &s);

  (void) sha256_init(&s);
  (void) sha256_update(&s, o_key_pad, sizeof(o_key_pad));
  (void) sha256_update(&s, digest, sizeof(digest));
  sha256_final(digest, &s);

  memcpy(result, digest, sizeof(digest));
  return result;

  // This is another implementation that doesn't work that I tried to use to resolve my current bug

  /* uint8_t holdme[SHA256_BLOCK_SIZE + datasize]; */
  /* /\* memset(holdme, i_key_pad, sizeof(i_key_pad)); *\/ */
  /* for (i = 0; i < (sizeof(i_key_pad) + datasize); i++) { */
  /*   if (i < sizeof(i_key_pad)) { */
  /*     holdme[i] = i_key_pad[i]; */
  /*   } */
  /*   else { */
  /*   holdme[i] = *(data+(i-sizeof(i_key_pad))); */
  /*   } */
  /* } */
  /* (void) sha256_update(&s, holdme, sizeof(holdme)); */
  /* (void) sha256_final(digest, &s); */
  /* sha256_init(&s); */

  /* uint8_t holdme2[SHA256_BLOCK_SIZE + sizeof(digest)]; */
  /* /\* memset(holdme2, o_key_pad, sizeof(o_key_pad)); *\/ */
  /* for (i = 0; i < (sizeof(o_key_pad) + sizeof(digest)); i++) { */
  /*   if (i < sizeof(o_key_pad)) { */
  /*     holdme[i] = i_key_pad[i]; */
  /*   } */
  /*   else { */
  /*   holdme[i] = digest[+(i-sizeof(o_key_pad))]; */
  /*   } */
  /* } */
  /* (void) sha256_update(&s, holdme2, sizeof(holdme2)); */
  /* (void) sha256_final(digest, &s); */
  /* memcmp(result, digest, sizeof(digest)); */
  /* return result; */
>>>>>>> f23ec8d6e6321f6e2c620d3d105d6b75dd93940f
}
