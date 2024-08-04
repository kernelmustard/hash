#include "sha1.h"

/*
 * Thank you Steve Reid <steve@edmweb.com> for his implementation of SHA1 in C
 */

// define transformative functions
#define sha1_rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

// sha1_blk0() and sha1_blk() perform the initial expand.
// I got the idea of expanding during the round function from SSLeay
#if BYTE_ORDER == LITTLE_ENDIAN
#define sha1_blk0(i) (block->l[i] = (sha1_rol(block->l[i],24)&0xFF00FF00) | (sha1_rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define sha1_blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define sha1_blk(i) (block->l[i&15] = sha1_rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))

#define SHA1_R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+sha1_blk0(i)+0x5A827999+sha1_rol(v,5);w=sha1_rol(w,30);
#define SHA1_R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+sha1_blk(i)+0x5A827999+sha1_rol(v,5);w=sha1_rol(w,30);
#define SHA1_R2(v,w,x,y,z,i) z+=(w^x^y)+sha1_blk(i)+0x6ED9EBA1+sha1_rol(v,5);w=sha1_rol(w,30);
#define SHA1_R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+sha1_blk(i)+0x8F1BBCDC+sha1_rol(v,5);w=sha1_rol(w,30);
#define SHA1_R4(v,w,x,y,z,i) z+=(w^x^y)+sha1_blk(i)+0xCA62C1D6+sha1_rol(v,5);w=sha1_rol(w,30);

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

  // 4 rounds of 20 operations (R0+R1 are sameish)
  for (unsigned i = 0; i <= 79; i++)
  {
    if (i <= 15)
    {
      if      ((i+5) % 5 == 0) { SHA1_R0(a, b, c, d, e, i); } 
      else if ((i+5) % 5 == 1) { SHA1_R0(e, a, b, c, d, i); }
      else if ((i+5) % 5 == 2) { SHA1_R0(d, e, a, b, c, i); }
      else if ((i+5) % 5 == 3) { SHA1_R0(c, d, e, a, b, i); }
      else if ((i+5) % 5 == 4) { SHA1_R0(b, c, d, e, a, i); }
    }
    else if (i <= 19)
    {
      if      (i % 5 == 1) { SHA1_R1(e, a, b, c, d, i); }
      else if (i % 5 == 2) { SHA1_R1(d, e, a, b, c, i); }
      else if (i % 5 == 3) { SHA1_R1(c, d, e, a, b, i); }
      else if (i % 5 == 4) { SHA1_R1(b, c, d, e, a, i); }
    }
    else if (i <= 39)
    {
      if      (i % 5 == 0) { SHA1_R2(a, b, c, d, e, i); }
      else if (i % 5 == 1) { SHA1_R2(e, a, b, c, d, i); }
      else if (i % 5 == 2) { SHA1_R2(d, e, a, b, c, i); }
      else if (i % 5 == 3) { SHA1_R2(c, d, e, a, b, i); }
      else if (i % 5 == 4) { SHA1_R2(b, c, d, e, a, i); }
    }
    else if (i <= 59)
    {
      if      (i % 5 == 0) { SHA1_R3(a, b, c, d, e, i); }
      else if (i % 5 == 1) { SHA1_R3(e, a, b, c, d, i); }
      else if (i % 5 == 2) { SHA1_R3(d, e, a, b, c, i); }
      else if (i % 5 == 3) { SHA1_R3(c, d, e, a, b, i); }
      else if (i % 5 == 4) { SHA1_R3(b, c, d, e, a, i); }
    }
    else if (i <= 79)
    {
      if      (i % 5 == 0) { SHA1_R4(a, b, c, d, e, i); }
      else if (i % 5 == 1) { SHA1_R4(e, a, b, c, d, i); }
      else if (i % 5 == 2) { SHA1_R4(d, e, a, b, c, i); }
      else if (i % 5 == 3) { SHA1_R4(c, d, e, a, b, i); }
      else if (i % 5 == 4) { SHA1_R4(b, c, d, e, a, i); }
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

  // will this crash if reading a large enough file?
  unsigned char *input_buffer = malloc(stream_len + 1);
  if (fread(input_buffer, 1, stream_len, stream) ) {};
  for (unsigned i = 0; i < stream_len; i++)
  {
    sha1_update(&ctx, (const unsigned char *)input_buffer + i, 1);
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