#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "sha256.h"
#include "hmac_sha256.h"

void show(const char *label, const uint8_t *s);
void test1(void);
void test2(void);
void test3(void);

int main(void) {
  test1();
  test2();
  test3();

  return 0;
}
void show (const char *label, const uint8_t *s) {
  int i;
  fprintf (stderr, "%s = ", label);
  for (i = 0; i < 32; ++i) {
    fprintf (stderr, "%02x", s[i]);
  }
  fprintf (stderr, "\n\n\n");
}

void test1(void) {
  // HMAC test case 1
  // key is shorter than the length of the HMAC output
  const uint8_t expected[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 
    0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
  };
  uint8_t data[8] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
  uint8_t key[20];
  uint8_t keysize = sizeof(key);
  uint8_t datasize = sizeof(data);
  (void) memset(key, 0x0b, keysize);

  uint8_t digest[SHA256_DIGEST_SIZE];
  (void) HMAC_SHA256((uint8_t *) digest, key, keysize, data, datasize);
  /* uint8_t *digest = HMAC_SHA256((uint8_t *) digest, key, data, keysize, datasize); */

  printf("FINISHED--------CALLING--------HMAC\n");
  if (memcmp(digest, expected, sizeof(digest)) != 0) {
    fprintf(stderr, "test 1 failed\n");
    show("expected", expected);
    show("computed", digest);
    exit(-1);
  }
  printf("passed test 1!\n\n\n");
}

void test2(void) {
  // HMAC test case 3
  // (key + message) > sha256_block_size
  uint8_t digest[SHA256_DIGEST_SIZE];
  const uint8_t expected[32] = {
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb,
    0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
    0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
  };
  uint8_t key[20];
  uint8_t data[50];
  uint8_t keysize = sizeof(key);
  uint8_t datasize = sizeof(data);
  memset(key, 0xaa, keysize);
  memset(data, 0xdd, datasize);

  (void) HMAC_SHA256((uint8_t *) digest, key, keysize, data, datasize);
  printf("FINISHED-----------WITH---------HMAC\n");
  if (memcmp(digest, expected, sizeof(digest)) != 0) {
    fprintf(stderr, "test 3 failed\n");
    show("expected", expected);
    show("computed", digest);
    exit(-1);
  }
  printf("Passed Test 2!\n");
}

void test3(void) {
  // HMAC test case 6
  // key/data > sha256_block_size
  const uint8_t expected[32] = {
    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa,
    0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
    0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
  };
  uint8_t key[131];
  uint8_t data[54] = {
    0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
    0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
    0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
    0x20, 0x46, 0x69, 0x72, 0x73, 0x74
  };
  uint8_t digest[SHA256_DIGEST_SIZE];
  uint8_t keysize = sizeof(key);
  uint8_t datasize = sizeof(data);
  memset(key, 0xaa, keysize);

  
  (void) HMAC_SHA256((uint8_t *) digest, key, keysize, data, datasize);
  printf("FINISHED--------CALLING--------HMAC\n");
  if (memcmp(digest, expected, sizeof(digest)) != 0) {
    fprintf(stderr, "test 3 failed\n");
    show("expected", expected);
    show("computed", digest);
    exit(-1);
  }
  printf("Passed Test 3!\n\n\n");
}
