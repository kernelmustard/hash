#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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

uint32_t rol(uint32_t value, unsigned bits);
uint32_t blk0(unsigned i, CHAR64LONG16 **block);
uint32_t blk(unsigned i, CHAR64LONG16 **block);
void R0(uint32_t v, uint32_t w, uint32_t x, uint32_t y, uint32_t z, unsigned i, CHAR64LONG16 *block);
void R1(uint32_t v, uint32_t w, uint32_t x, uint32_t y, uint32_t z, unsigned i, CHAR64LONG16 *block);
void R2(uint32_t v, uint32_t w, uint32_t x, uint32_t y, uint32_t z, unsigned i, CHAR64LONG16 *block);
void R3(uint32_t v, uint32_t w, uint32_t x, uint32_t y, uint32_t z, unsigned i, CHAR64LONG16 *block);
void R4(uint32_t v, uint32_t w, uint32_t x, uint32_t y, uint32_t z, unsigned i, CHAR64LONG16 *block);

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result);
void sha1_init(sha1_ctx *ctx);
void sha1_step(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, uint8_t *input_buffer, unsigned input_length);
void sha1_finalize(sha1_ctx *ctx);

#endif