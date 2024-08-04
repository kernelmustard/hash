#include "md5.h"

/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 * Thank you to GitHub user Zunawe for doing the difficult work of parsing the RFC1321 
 * implementation into more modern C.
 */

// MD5 Algorithm compression functions
uint32_t F(uint32_t X, uint32_t Y, uint32_t Z)
{
  return ((X & Y) | (~X & Z));
} 
uint32_t G(uint32_t X, uint32_t Y, uint32_t Z)
{
  return ((X & Z) | (Y & ~Z));
} 
uint32_t H(uint32_t X, uint32_t Y, uint32_t Z)
{
  return (X ^ Y ^ Z);
} 
uint32_t I(uint32_t X, uint32_t Y, uint32_t Z)
{
  return (Y ^ (X | ~Z));
}

// rotate 32-bit word left by n bits
uint32_t rotate_left(uint32_t word, uint32_t bits) 
{
  return (word << bits) | (word >> (32 - bits));
}

void md5_step(md5_context *ctx, uint32_t *input)
{
  uint32_t AA = ctx->buffer[0];
  uint32_t BB = ctx->buffer[1];
  uint32_t CC = ctx->buffer[2];
  uint32_t DD = ctx->buffer[3];

  uint32_t E;

  unsigned j;

  for (unsigned i = 0; i < 64; ++i) 
  {
    switch (i / 16) 
    {
      case 0:
        E = F(BB, CC, DD);
        j = i;
        break;
      case 1:
        E = G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
        break;
      case 2:
        E = H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
        break;
      default:
        E = I(BB, CC, DD);
        j = (i * 7) % 16;
        break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + rotate_left(AA + E + ctx->K[i] + input[j], ctx->S[i]);
    AA = temp;
  }

  ctx->buffer[0] += AA;
  ctx->buffer[1] += BB;
  ctx->buffer[2] += CC;
  ctx->buffer[3] += DD;

  return;
}

void md5_update(md5_context *ctx, uint8_t *input_buffer, size_t input_len)
{
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  ctx->size += (uint64_t)input_len;

  for (unsigned i = 0; i < input_len; ++i) {
    ctx->input[offset++] = (uint8_t)*(input_buffer + i);

    if (offset % 64 == 0) {
      for (unsigned j = 0; j < 16; ++j) {
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
                   (uint32_t)(ctx->input[(j * 4)]);
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
  unsigned int offset = ctx->size % 64;
  unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

  md5_update(ctx, ctx->PADDING, padding_length);
  ctx->size -= (uint64_t)padding_length;

  for(unsigned int j = 0; j < 14; ++j){
    input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
               (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
               (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
               (uint32_t)(ctx->input[(j * 4)]);
  }
  input[14] = (uint32_t)(ctx->size * 8);
  input[15] = (uint32_t)((ctx->size * 8) >> 32);

  md5_step(ctx, input);

  for(unsigned int i = 0; i < 4; ++i){
    ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000ff));
    ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000ff00) >>  8);
    ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00ff0000) >> 16);
    ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xff000000) >> 24);
  }
  return;
}

// initialize context used to track buffers and digest
void md5_init(md5_context *ctx)
{
  ctx->size = 0;

  // MD5 Algorithm constants
  ctx->buffer[0] = 0x67452301U; // A, B, C, D
  ctx->buffer[1] = 0xefcdab89U;
  ctx->buffer[2] = 0x98badcfeU;
  ctx->buffer[3] = 0x10325476U;

  uint32_t list_S[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                          5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21  };
  for (unsigned i = 0; i < 64; i++) { ctx->S[i] = list_S[i]; }

  uint32_t list_K[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                          0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                          0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                          0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                          0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                          0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                          0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                          0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                          0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                          0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                          0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                          0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                          0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                          0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                          0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                          0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391  };
  for (unsigned i = 0; i < 64; i++) { ctx->K[i] = list_K[i]; }

  // Padding used to make the bit length of the input congruent to 448 % 512
  uint8_t list_PADDING[64] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  };
  for (unsigned i = 0; i < 64; i++) { ctx->PADDING[i] = list_PADDING[i]; }

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