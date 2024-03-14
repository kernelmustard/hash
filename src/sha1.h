#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t K[4];
  uint32_t digest[5];                // Message Digest
  uint32_t length_low;                          // Message length in bits
  uint32_t length_high;                         // Message length in bits
  int_least16_t message_block_index;            // Index into message block array
  uint8_t message_block[64];                    // 512-bit message blocks
} sha1_context;

uint32_t sha1_circular_lshift(uint32_t bits, uint32_t word);

void sha1(FILE *stream, uint8_t *sha1_result);
void sha1_init(sha1_context *ctx);
void sha1_step(sha1_context *ctx);
void sha1_update(sha1_context *ctx, uint8_t *input_buffer);
void sha1_finalize(sha1_context *ctx, uint8_t *input_buffer, size_t input_len);
#endif