
/*
 *  sha256.c -- implementation of the SHA-256 cryptographic hash algorithm
 */

#include "sha256.h"

#include <string.h>

static void compress (unsigned int *iv, const uint8_t *data);

int sha256_init (Sha256State_t s) {
  if (s == (Sha256State_t) 0) {
    return 0;
  }

  (void) memset ((uint8_t *) s, 0x00, sizeof (*s));
  s->iv[0] = 0x6a09e667;
  s->iv[1] = 0xbb67ae85;
  s->iv[2] = 0x3c6ef372;
  s->iv[3] = 0xa54ff53a;
  s->iv[4] = 0x510e527f;
  s->iv[5] = 0x9b05688c;
  s->iv[6] = 0x1f83d9ab;
  s->iv[7] = 0x5be0cd19;

  return 1;
}

int sha256_update (Sha256State_t s, const void* data, size_t data_length) {
  if (s == (Sha256State_t) 0) {
    return 0;
  } else if (data_length == 0) {
    return  1;
  } else if (data == (void *) 0) {
    return 0;
  }

  while (data_length-- > 0) {
    s->leftover[s->leftover_offset++] = *((const uint8_t *) data++);
    if (s->leftover_offset >= SHA256_BLOCK_SIZE) {
      compress (s->iv, s->leftover);
      s->leftover_offset = 0;
      s->bits_hashed += (SHA256_BLOCK_SIZE << 3);
    }
  }

  return 1;
}

int sha256_final (uint8_t *digest, Sha256State_t s) {
  int i;

  if (digest == (uint8_t *) 0) {
    return 0;
  } else if (s == (Sha256State_t) 0) {
    return 0;
  }

  s->bits_hashed += (s->leftover_offset << 3);

  s->leftover[s->leftover_offset++] = 0x80; /* always room for one byte */
  if (s->leftover_offset > (sizeof (s->leftover) - 8)) {
    /* there is not room for all the padding in this block */
    (void) memset (s->leftover + s->leftover_offset, 0x00,
        sizeof (s->leftover) - s->leftover_offset);
    compress (s->iv, s->leftover);
    s->leftover_offset = 0;
  }

  /* add the padding and the length in big-Endian format */
  (void) memset (s->leftover + s->leftover_offset, 0x00,
       sizeof (s->leftover) - 8 - s->leftover_offset);
  s->leftover[sizeof (s->leftover) - 1] = (uint8_t)(s->bits_hashed);
  s->leftover[sizeof (s->leftover) - 2] = (uint8_t)(s->bits_hashed >> 8);
  s->leftover[sizeof (s->leftover) - 3] = (uint8_t)(s->bits_hashed >> 16);
  s->leftover[sizeof (s->leftover) - 4] = (uint8_t)(s->bits_hashed >> 24);
  s->leftover[sizeof (s->leftover) - 5] = (uint8_t)(s->bits_hashed >> 32);
  s->leftover[sizeof (s->leftover) - 6] = (uint8_t)(s->bits_hashed >> 40);
  s->leftover[sizeof (s->leftover) - 7] = (uint8_t)(s->bits_hashed >> 48);
  s->leftover[sizeof (s->leftover) - 8] = (uint8_t)(s->bits_hashed >> 56);

  /* hash the padding and length */
  compress (s->iv, s->leftover);

  /* copy the iv out to digest */
  for (i = 0; i < SHA256_STATE_BLOCKS; ++i) {
    uint32_t t = *((uint32_t *) &s->iv[i]);
    *digest++ = (uint8_t)(t >> 24);
    *digest++ = (uint8_t)(t >> 16);
    *digest++ = (uint8_t)(t >> 8);
    *digest++ = (uint8_t)(t);
  }

  return 1;
}

/* SHA-256 Hash constant words K: */
static const uint32_t k256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(a,n) (((a) >> n) | ((a) << (32 - n)))

#define Sigma0(a) (ROTR((a),2) ^ ROTR((a),13) ^ ROTR((a),22))
#define Sigma1(a) (ROTR((a),6) ^ ROTR((a),11) ^ ROTR((a),25))
#define sigma0(a) (ROTR((a),7) ^ ROTR((a),18) ^ ((a) >> 3))
#define sigma1(a) (ROTR((a),17) ^ ROTR((a),19) ^ ((a) >> 10))

#define Ch(a,b,c) (((a) & (b)) ^ ((~(a)) & (c)))
#define Maj(a,b,c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

#define BigEndian(n,c) (n = (((uint32_t)(*((c)++))) << 24), \
  n |= ((uint32_t)(*((c)++)) << 16), \
  n |= ((uint32_t)(*((c)++)) << 8), \
  n |= ((uint32_t)(*((c)++)))) /* ,	\
  n */

static void compress (uint32_t *iv, const uint8_t *data) {
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t s0, s1;
  uint32_t t1, t2;
  uint32_t key_sched[16];
  uint32_t n;
  int i;

  a = iv[0]; b = iv[1]; c = iv[2]; d = iv[3];
  e = iv[4]; f = iv[5]; g = iv[6]; h = iv[7];

  for (i = 0; i < 16; ++i) {
    BigEndian(n,data);
    t1 = key_sched[i] = n;
    t1 += h + Sigma1(e) + Ch(e,f,g) + k256[i];
    t2 = Sigma0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }

  for ( ; i < 64; ++i) {
    s0 = key_sched[(i+1)&0x0f];
    s0 = sigma0 (s0);
    s1 = key_sched[(i+14)&0x0f];
    s1 = sigma1 (s1);

    t1 = key_sched[i&0xf] += s0 + s1 + key_sched[(i+9)&0xf];
    t1 += h + Sigma1(e) + Ch(e,f,g) + k256[i];
    t2 = Sigma0(a) + Maj(a,b,c);
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }

  iv[0] += a; iv[1] += b; iv[2] += c; iv[3] += d;
  iv[4] += e; iv[5] += f; iv[6] += g; iv[7] += h;
}
