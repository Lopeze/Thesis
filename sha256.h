
#ifndef __SHA256_H__
#define __SHA256_H__

/*
 *  sha256.h -- interface to a SHA-256 implementation
 *
 *  overview:   SHA256 is a NIST approved hashing algorithm defined in
 *              FIPS 180.
 *
 *  security:   SHA256 provides 128 bits of security against collision and
 *              second pre-image attacks. SHA256 provides 256 bits of
 *              security against pre-image attacks. SHA256 does NOT behave
 *              like a random oracle, but it can be used as one if the
 *              string being hashed is prefix-free encoded before hashing.
 *
 *  usage:      call sha256_init to initialize a struct sha256_state_struct
 *              before hashing a new string.
 *
 *              call sha256_update to hash the next string segment;
 *              sha256_update can be called as many times as necessary to hash
 *              all of the segments of a string; the order is important
 *
 *              call sha256_final to out put the digest from a hashing
 *              operation.
 *
 *              verify_sha256 is a built-in self-test, to verify whether
 *              the implementation is working properly
 */

#include <sys/types.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE (64)
#define SHA256_DIGEST_SIZE (32)
#define SHA256_STATE_BLOCKS (SHA256_DIGEST_SIZE/4)

struct sha256_state_struct {
  uint32_t iv[SHA256_STATE_BLOCKS];
  uint64_t bits_hashed;
  uint8_t leftover[SHA256_BLOCK_SIZE];
  size_t leftover_offset;
};

typedef struct sha256_state_struct *Sha256State_t;

int sha256_init (Sha256State_t s);
/*
 *  effects:  initializes s and returns 1
 *  exceptions:  returns 0 if s is null
 */

int sha256_update (Sha256State_t s, const void *data, size_t data_length);
/*
 *  assumes:  s has been initialized by sha256_init
 *  effects:  hashes data_length bytes addressed by data into state s and
 *            returns 1
 *  exceptions: returns 0 if s is null, if data is null when data_length > 0
 *            or if more than 2^64 bits are hashed
 */

int sha256_final (uint8_t *digest, Sha256State_t s);
/*
 *  assumes:  s has been initialized by sha256_init
 *            digest points to at least SHA256_DIGEST_SIZE bytes
 *  effects:  inserts the completed hash computation into digest and returns 1
 *  exceptions returns 0 if s or digest is null
 */

#endif
