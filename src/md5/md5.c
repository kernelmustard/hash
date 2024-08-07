/**
 * @file md5.c
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief MD5 Implementation
 * @note Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into 
 * control structures
 * @note Derived further from Bryce Wilson's (https://github.com/Zunawe) which
 * can be found at https://github.com/Zunawe/md5-c/blob/main/md5.c
 */

#include "md5.h"

#define md5_rol(word, bits) ((word << bits) | (word >> (32 - bits)))

#define MD5_F(X, Y, Z) ((X & Y) | (~X & Z))
#define MD5_G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define MD5_H(X, Y, Z) (X ^ Y ^ Z)
#define MD5_I(X, Y, Z) (Y ^ (X | ~Z))

static const uint32_t MD5_S[64] = { 
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5,  9, 14, 20, 5,
  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
  16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 
  21 };

static const uint32_t MD5_K[64] = { 
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
  0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 
  0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 
  0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 
  0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
  0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391  };

static const uint8_t MD5_PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// initialize context used to track buffers and digest
void md5_init(md5_context *ctx)
{
  ctx->bitlen = 0;

  // MD5 Algorithm constants
  ctx->state[0] = 0x67452301U; // A, B, C, D
  ctx->state[1] = 0xefcdab89U;
  ctx->state[2] = 0x98badcfeU;
  ctx->state[3] = 0x10325476U;

  return;
}

void md5_step(md5_context *ctx, uint32_t *data)
{
  uint32_t AA = ctx->state[0];
  uint32_t BB = ctx->state[1];
  uint32_t CC = ctx->state[2];
  uint32_t DD = ctx->state[3];

  uint32_t E;

  unsigned j;

  for (unsigned i = 0; i < 64; ++i) 
  {
    switch (i / 16) 
    {
      case 0:
        E = MD5_F(BB, CC, DD);
        j = i;
        break;
      case 1:
        E = MD5_G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
        break;
      case 2:
        E = MD5_H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
        break;
      default:
        E = MD5_I(BB, CC, DD);
        j = (i * 7) % 16;
        break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + md5_rol((AA + E + MD5_K[i] + data[j]), MD5_S[i]);
    AA = temp;
  }

  ctx->state[0] += AA;
  ctx->state[1] += BB;
  ctx->state[2] += CC;
  ctx->state[3] += DD;

  return;
}

void md5_update(md5_context *ctx, const uint8_t *data, size_t len)
{
  uint32_t input[16];
  unsigned int offset = ctx->bitlen % 64;
  ctx->bitlen += (uint64_t)len;

  for (unsigned i = 0; i < len; ++i) {
    ctx->buffer[offset++] = (uint8_t)*(data + i);

    if (offset % 64 == 0) {
      for (unsigned j = 0; j < 16; ++j) {
        input[j] = (uint32_t)(ctx->buffer[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->buffer[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->buffer[(j * 4) + 1]) <<  8 |
                   (uint32_t)(ctx->buffer[(j * 4)]);
      }
      md5_step(ctx, input);
      offset = 0;
    }
  }
  return;
}

void md5_finalize(md5_context *ctx)
{
  uint32_t input[16];
  unsigned int offset = ctx->bitlen % 64;
  unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

  md5_update(ctx, MD5_PADDING, padding_length);
  ctx->bitlen -= (uint64_t)padding_length;

  for(unsigned int j = 0; j < 14; ++j){
    input[j] = (uint32_t)(ctx->buffer[(j * 4) + 3]) << 24 |
               (uint32_t)(ctx->buffer[(j * 4) + 2]) << 16 |
               (uint32_t)(ctx->buffer[(j * 4) + 1]) <<  8 |
               (uint32_t)(ctx->buffer[(j * 4)]);
  }
  input[14] = (uint32_t)(ctx->bitlen * 8);
  input[15] = (uint32_t)((ctx->bitlen * 8) >> 32);

  md5_step(ctx, input);

  for(unsigned int i = 0; i < 4; ++i){
    ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->state[i] & 0x000000ff));
    ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->state[i] & 0x0000ff00) >>  8);
    ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->state[i] & 0x00ff0000) >> 16);
    ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->state[i] & 0xff000000) >> 24);
  }
  return;
}

void md5(FILE *stream, uint8_t *md5_result)
{
  md5_context ctx; // instantiate context struct
  md5_init(&ctx);

  uint8_t *input_buffer = malloc(1024);
  size_t input_size = 0;

  while ((input_size = fread(input_buffer, 1, 1024, stream)) > 0) 
  {
    md5_update(&ctx, input_buffer, input_size);
  }
  md5_finalize(&ctx);

  // clean up
  rewind(stream);
  free(input_buffer);
  
  // pass result to main
  memcpy(md5_result, ctx.digest, 16);
  return;
}