#include "sha1.h"

uint32_t sha1_circular_lshift(uint32_t bits, uint32_t word)
{
  return (((word) << (bits)) | ((word) >> (32-(bits))));
}

void sha1_step(sha1_context *ctx)
{

  int t;                            /* Loop counter                */
  uint32_t temp;                    /* Temporary word value        */
  uint32_t W[80];                   /* Word sequence               */
  uint32_t A, B, C, D, E;           /* Word buffers                */

  for (t = 0; t < 16; t++) {
    W[t]  = ctx->message_block[t * 4] << 24;
    W[t] |= ctx->message_block[t * 4 + 1] << 16;
    W[t] |= ctx->message_block[t * 4 + 2] << 8;
    W[t] |= ctx->message_block[t * 4 + 3];
  }

  for(t = 16; t < 80; t++) { W[t] = sha1_circular_lshift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]); }

  typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;
  CHAR64LlockONG16 block[1];     // use array to appear as a pointer
  memcpy(b, buffer, 64);

  A = ctx->digest[0];
  B = ctx->digest[1];
  C = ctx->digest[2];
  D = ctx->digest[3];
  E = ctx->digest[4];

  // 4 rounds of 20 operations each
  for (unsigned i = 0; i < 80; i++) {
        if (i <= 15)
        { 
          R0(A, B, C, D, E, i); 
          E += ((B & (C ^ D)) ^ D) + blk0(i) + ctx->K[0] + sha1_circular_lshift(A,5);
          B = sha1_circular_lshift(B,30);
        }
        else if (i <= 19)
        {
          R1(e, a, b, c, d, i); 
        }
        else if (i <= 39)
        { 
          R2(a, b, c, d, e, i); 
        }
        else if (i <= 59)
        {
          R3(a, b, c, d, e, i); 
        }
        else if (i <= 79)
        {
          R4(a, b, c, d, e, i); 
        }
    }
    // blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) | (rol(block->l[i],8) & 0x00ff00ff))
    // blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))

    /*

    R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
    R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
    R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
    R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
    R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);
    */

  ctx->digest[0] += A;
  ctx->digest[1] += B;
  ctx->digest[2] += C;
  ctx->digest[3] += D;
  ctx->digest[4] += E;

  // clear variables
  A = B = C = D = E = 0;
  ctx->message_block_index = 0;

  return;
}

// add padding on final block before calculations
void sha1_finalize(sha1_context *ctx, uint8_t *input_buffer, size_t input_len)
{
  // add padding
  input_buffer[input_len] = 0x80U;
  input_len++;
  while (input_len % 64 != 56) {
    //input_buffer[input_len] = 0x00;
    input_len++;
  }

  // divide longer buffer into 2 chunks
  if (input_len > 56) {
    sha1_update(ctx, input_buffer);
    for (ctx->message_block_index = 0; ctx->message_block_index < 56; ctx->message_block_index++) {
      ctx->message_block[ctx->message_block_index] = 0x00U;
    }
    // add length
    ctx->message_block_index+=8;
    ctx->message_block[56] = ctx->length_high >> 24;
    ctx->message_block[57] = ctx->length_high >> 16;
    ctx->message_block[58] = ctx->length_high >> 8;
    ctx->message_block[59] = ctx->length_high;
    ctx->message_block[60] = ctx->length_low >> 24;
    ctx->message_block[61] = ctx->length_low >> 16;
    ctx->message_block[62] = ctx->length_low >> 8;
    ctx->message_block[63] = ctx->length_low;
    sha1_step(ctx);
  }

  // sanitize context
  for (unsigned count = 0; count < 64; count++) { ctx->message_block[count] = 0; }
  ctx->length_low = 0;
  ctx->length_high = 0;

  return;
}

// process input buffer 64 bytes at a time
void sha1_update(sha1_context *ctx, uint8_t *input_buffer)
{
  unsigned input_index = 0;
  for (ctx->message_block_index = 0; ctx->message_block_index < 64; ctx->message_block_index++) {
    ctx->message_block[ctx->message_block_index] = input_buffer[input_index];
    input_index++;
  }
  if (ctx->message_block_index == 64) { sha1_step(ctx); }
  
  return;
}

void sha1_init(sha1_context *ctx)
{
  if (! ctx) { return; }

  ctx->length_low = 0;
  ctx->length_high = 0;
  ctx->message_block_index = 0;

  ctx->digest[0] = 0x67452301U;  // Constants defined in SHA-1
  ctx->digest[1] = 0xefcdab89U;
  ctx->digest[2] = 0x98badcfeU;
  ctx->digest[3] = 0x10325476U;
  ctx->digest[4] = 0xc3d2e1f0U;

  ctx->K[0] = 0x5a827999U;
  ctx->K[1] = 0x6ed9eba1U;
  ctx->K[2] = 0x8f1bbcdcU;
  ctx->K[3] = 0xca62c1d6U;

  return;
}

void sha1(FILE *stream, uint8_t *sha1_result)
{
  sha1_context ctx;
  sha1_init(&ctx);

  // read input 64 bytes at a time
  uint8_t *input_buffer = malloc(64 * 2);
  size_t input_len = 0;
    while ((input_len = fread(input_buffer, 1, 64, stream)) > 0) 
    {
      if (input_len == 64) 
      {
        sha1_update(&ctx, input_buffer);
      } 
      else 
      {
        sha1_finalize(&ctx, input_buffer, input_len);
      }
    }

  free(input_buffer);

  memcpy(sha1_result, ctx.digest, 20);
  return;
}