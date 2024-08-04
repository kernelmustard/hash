#include "sha1.h"

/*
 * Thank you Steve Reid <steve@edmweb.com> for his implementation of SHA1 in C
 */

// define transformative functions

uint32_t rol(uint32_t value, unsigned bits)
{
  return (value << bits) | (value >> (32 - bits));
}

#if BYTE_ORDER == LITTLE_ENDIAN
uint32_t blk0(unsigned i, CHAR64LONG16 **block)
{
  return (rol((*block)->l[i],24)&0xFF00FF00) | (rol((*block)->l[i], 8) & 0x00FF00FFU);
}
#elif BYTE_ORDER == BIG_ENDIAN
uint32_t blk0(unsigned i, CHAR64LONG16 **block)
{
  return (*block)->l[i];
}
#else
#error "Endianness is not defined!"
#endif

uint32_t blk(unsigned i, CHAR64LONG16 **block)
{
  return (*block)->l[i&15] = rol((*block)->l[(i+13)&15] ^ (*block)->l[(i+8)&15] ^ (*block)->l[(i+2)&15] ^ (*block)->l[i&15], 1);
}

void R0(uint32_t v, uint32_t *w, uint32_t x, uint32_t y, uint32_t *z, unsigned i, CHAR64LONG16 *block)
{
  *z += ((*w & (x ^ y)) ^ y) + blk0(i, &block) + 0x5A827999U + rol(v, 5);
  *w = rol(*w, 30);
}

void R1(uint32_t v, uint32_t *w, uint32_t x, uint32_t y, uint32_t *z, unsigned i, CHAR64LONG16 *block)
{
  *z += ((*w & (x ^ y)) ^ y) + blk(i, &block) + 0x5A827999U + rol(v, 5);
  *w = rol(*w, 30);
}

void R2(uint32_t v, uint32_t *w, uint32_t x, uint32_t y, uint32_t *z, unsigned i, CHAR64LONG16 *block)
{
  *z += (*w ^ x ^ y) + blk(i, &block) + 0x6ED9EBA1U + rol(v, 5);
  *w = rol(*w, 30);
}

void R3(uint32_t v, uint32_t *w, uint32_t x, uint32_t y, uint32_t *z, unsigned i, CHAR64LONG16 *block)
{
  *z += (((*w | x) & y) | (*w & x)) + blk(i, &block) + 0x8F1BBCDCU + rol(v, 5);
  *w = rol(*w, 30);
}

void R4(uint32_t v, uint32_t *w, uint32_t x, uint32_t y, uint32_t *z, unsigned i, CHAR64LONG16 *block)
{
  *z += (*w ^ x ^ y) + blk(i, &block) + 0xCA62C1D6U + rol(v, 5);
  *w = rol(*w, 30);
}

void sha1_init(sha1_ctx *ctx)
{
  ctx->state[0] = 0x67452301U;
  ctx->state[1] = 0xefcdab89U;
  ctx->state[2] = 0x98badcfeU;
  ctx->state[3] = 0x10325476U;
  ctx->state[4] = 0xc3d2e1f0U;
  ctx->count[0] = ctx->count[1] = 0;

  return;
}

void sha1_step(sha1_ctx *ctx, const unsigned char buffer[64])
{
  uint32_t a, b, c, d, e;

  CHAR64LONG16 block[1];  // def in header
  memcpy(block, ctx->buffer, 64); // copy 64 bits of buffer into CHAR64LONG16 union

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  // 4 rounds of 20 operations (R0+R1)
  for (unsigned i = 0; i <= 79; i++)
  {
    if (i <= 15)
    {
      if      ((i+5) % 5 == 0) { R0(a, &b, c, d, &e, i, &(block[0])); } 
      else if ((i+5) % 5 == 1) { R0(e, &a, b, c, &d, i, &(block[0])); }
      else if ((i+5) % 5 == 2) { R0(d, &e, a, b, &c, i, &(block[0])); }
      else if ((i+5) % 5 == 3) { R0(c, &d, e, a, &b, i, &(block[0])); }
      else if ((i+5) % 5 == 4) { R0(b, &c, d, e, &a, i, &(block[0])); }
    }
    else if (i <= 19)
    {
      if      (i % 5 == 1) { R1(e, &a, b, c, &d, i, &(block[0])); }
      else if (i % 5 == 2) { R1(d, &e, a, b, &c, i, &(block[0])); }
      else if (i % 5 == 3) { R1(c, &d, e, a, &b, i, &(block[0])); }
      else if (i % 5 == 4) { R1(b, &c, d, e, &a, i, &(block[0])); }
    }
    else if (i <= 39)
    {
      if      (i % 5 == 0) { R2(a, &b, c, d, &e, i, &(block[0])); }
      else if (i % 5 == 1) { R2(e, &a, b, c, &d, i, &(block[0])); }
      else if (i % 5 == 2) { R2(d, &e, a, b, &c, i, &(block[0])); }
      else if (i % 5 == 3) { R2(c, &d, e, a, &b, i, &(block[0])); }
      else if (i % 5 == 4) { R2(b, &c, d, e, &a, i, &(block[0])); }
    }
    else if (i <= 59)
    {
      if      (i % 5 == 0) { R3(a, &b, c, d, &e, i, &(block[0])); }
      else if (i % 5 == 1) { R3(e, &a, b, c, &d, i, &(block[0])); }
      else if (i % 5 == 2) { R3(d, &e, a, b, &c, i, &(block[0])); }
      else if (i % 5 == 3) { R3(c, &d, e, a, &b, i, &(block[0])); }
      else if (i % 5 == 4) { R3(b, &c, d, e, &a, i, &(block[0])); }
    }
    else if (i <= 79)
    {
      if      (i % 5 == 0) { R4(a, &b, c, d, &e, i, &(block[0])); }
      else if (i % 5 == 1) { R4(e, &a, b, c, &d, i, &(block[0])); }
      else if (i % 5 == 2) { R4(d, &e, a, b, &c, i, &(block[0])); }
      else if (i % 5 == 3) { R4(c, &d, e, a, &b, i, &(block[0])); }
      else if (i % 5 == 4) { R4(b, &c, d, e, &a, i, &(block[0])); }
    }
  }

  // add working vars back into state
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;

  // wipe vars
  a = b = c = d = e = 0;
  memset(block, '\0', sizeof(block));

  return;
}

void sha1_update(sha1_ctx *ctx, const unsigned char *input_buffer, unsigned input_size)
{
  uint32_t i, j;

  j = ctx->count[0];
  if ( (ctx->count[0] += input_size << 3) < j) { ctx->count[1]++; }
  ctx->count[1] += (input_size >> 29);
  j = (j >> 3) & 63;
  if ((j + input_size) > 63)
  {
    memcpy(&ctx->buffer[j], input_buffer, (i = 64 - j));
    sha1_step(ctx, ctx->buffer);
    for (; i + 63 < input_size; i += 64)
    {
      sha1_step(ctx, &input_buffer[i]);
    }
    j = 0;
  }
  else 
  {
    i = 0;
  }
  memcpy(&ctx->buffer[j], &input_buffer[i], input_size - i);

  return;
}

void sha1_finalize(sha1_ctx *ctx)
{
  uint8_t finalcount[8];
  uint8_t c;

  for (unsigned i = 0; i < 8; i++)
  {
    finalcount[i] = (uint8_t) ((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);   // endian dependent
  }
  c = 0200;
  sha1_update(ctx, &c, 1);
  while ((ctx->count[0] & 504) != 448)
  {
    c = 0000;
    sha1_update(ctx, &c, 1);
  }
  sha1_update(ctx, finalcount, 8);
  for (unsigned i = 0; i < 20; i++)
  {
    ctx->digest[i] = (uint8_t) ((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }

  // wipe vars
  //memset(ctx, '\0', sizeof(*ctx));  // this undoes all progress lmao
  //memset(&finalcount, '\0', sizeof(finalcount));  // array is static, should be cleaned up automatically once we leave this function

  return;
}

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result)
{
  sha1_ctx ctx;
  sha1_init(&ctx);

  uint8_t *input_buffer = malloc(1024);
  unsigned input_size = 0;

  while ((input_size = fread(input_buffer, 1, 1024, stream)) > 0)
  {
    for (unsigned i = 0; i < 1024; i++)
    {
      sha1_update(&ctx, (const unsigned char *)input_buffer + i, 1);
    }
  }
  sha1_finalize(&ctx);

  // clean up
  free(input_buffer);
  rewind(stream);

  // pass result to main
  memcpy(sha1_result, ctx.digest, 20);
  return;

  return;
}