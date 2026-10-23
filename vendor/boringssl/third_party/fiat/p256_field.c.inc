// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
#include <openssl/base.h>
#include "bedrock_unverified_platform.c.inc"

#include "p256_64.h"

// the Bedrock-generated point operations call Fiat-C or Fiat-x86 mul, sqr
static inline void p256_coord_mul(br_word_t out, br_word_t x, br_word_t y) {
  fiat_p256_mul((br_word_t*)out, (const br_word_t*)x, (const br_word_t*)y);
}
static inline void p256_coord_sqr(br_word_t out, br_word_t x) {
  fiat_p256_square((br_word_t*)out, (const br_word_t*)x);
}
