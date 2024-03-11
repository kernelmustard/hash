#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SHARED_STATIC_VARS
#define SHARED_STATIC_VARS
static uint32_t A, B, C, D; // digest buffers
static uint32_t *K; // K table
#endif
static uint32_t E;

#define sha1_hash_size 20

typedef struct sha1_context {
  uint32_t intermediate_hash[sha1_hash_size/4]; // Message Digest
  uint32_t length_low;                          // Message length in bits
  uint32_t length_high;                         // Message length in bits
  int_least16_t message_block_index;            // Index into message block array
  uint8_t message_block[64];                    // 512-bit message blocks
} sha1_context;

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result);
void sha1_init(sha1_context *ctx);
void sha1_step(sha1_context *ctx);
void sha1_update(sha1_context *ctx, uint8_t *input_buffer);
void sha1_finalize(sha1_context *ctx, uint8_t *input_buffer, size_t input_len);
#endif