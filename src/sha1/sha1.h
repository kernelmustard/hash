#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  uint32_t state[5];
  uint8_t digest[20];
  uint32_t count[2];
  uint8_t buffer[64];
} sha1_ctx;

typedef union
{
  uint8_t c[64];
  uint32_t l[16];
} CHAR64LONG16;

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result);
void sha1_init(sha1_ctx *ctx);
void sha1_step(sha1_ctx *ctx, const unsigned char buffer[64]);
void sha1_update(sha1_ctx *ctx, const unsigned char *input_buffer, unsigned input_length);
void sha1_finalize(sha1_ctx *ctx);

#endif