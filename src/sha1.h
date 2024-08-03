#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct
{
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} sha1_ctx;

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result);
void sha1_init(sha1_ctx *ctx);
void sha1_step(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, uint8_t *input_buffer, unsigned input_length);
void sha1_finalize(sha1_ctx *ctx);

#endif