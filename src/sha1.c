#include "sha1.h"

#define sha1_circular_shift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

int sha1_init(sha1_context *ctx)
{
  if (! ctx) { return null; }

  ctx->length_low = 0;
  ctx->length_high = 0;
  ctx->message_block_index = 0;

  ctx->intermediate_hash[0] = 0x67452301U;
  ctx->intermediate_hash[1] = 0xefcdab89U;
  ctx->intermediate_hash[2] = 0x98badcfeU;
  ctx->intermediate_hash[3] = 0x10325476U;
  ctx->intermediate_hash[4] = 0xc3d2e1f0U;

  ctx->computed = 0;
  ctx->corrupted = 0;

  return success;
}

void sha1_step(sha1_context *ctx)
{
  const uint32_t K[] = {0x5a827999U,  /* Constants defined in SHA-1   */
                        0x6ed9eba1U,
                        0x8f1bbcdcU,
                        0xca62c1d6U };
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

    for(t = 16; t < 80; t++) { W[t] = sha1_circular_shift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]); }

    A = ctx->intermediate_hash[0];
    B = ctx->intermediate_hash[1];
    C = ctx->intermediate_hash[2];
    D = ctx->intermediate_hash[3];
    E = ctx->intermediate_hash[4];

    for(t = 0; t < 20; t++) {
        temp =  sha1_circular_shift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = sha1_circular_shift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++) {
        temp = sha1_circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = sha1_circular_shift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++) {
        temp = sha1_circular_shift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = sha1_circular_shift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++) {
        temp = sha1_circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = sha1_circular_shift(30,B);
        B = A;
        A = temp;
    }

    ctx->intermediate_hash[0] += A;
    ctx->intermediate_hash[1] += B;
    ctx->intermediate_hash[2] += C;
    ctx->intermediate_hash[3] += D;
    ctx->intermediate_hash[4] += E;

    ctx->message_block_index = 0;

  return;
}

int sha1_update(sha1_context *ctx, uint8_t *input_buffer, size_t input_len)
{
  if (!input_len) { return success; }         // if length is zero
  if (!ctx || !input_buffer) { return null; } // if context or buffer ptrs are null
  if (ctx->computed) {                        // if computed flag set before done
    ctx->corrupted = state_error;
    return state_error;
  }

  return success;
}

void sha1(FILE *stream, uint8_t *sha1_result)
{
  sha1_context ctx;
  int err;

  err = sha1_init(&ctx);
  if (err) {
    fprintf(stderr, "sha1_reset() error: %d\n", err);
    exit(1);
  }

  // read input 1024 bytes at a time
  uint8_t *input_buffer = malloc(1024);
  size_t input_size = 0;
  while((input_size = fread(input_buffer, 1, 64, stream)) > 0){
    sha1_update(&ctx, input_buffer, input_size);
  }

  free(input_buffer);

  memcpy(sha1_result, ctx.intermediate_hash, 20);
  return;
}