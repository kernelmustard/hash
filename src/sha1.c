#include "sha1.h"

#define sha1_circular_lshift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

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

int sha1_step(sha1_context *ctx)
{
  K = malloc(sizeof(*K) * 4);
  K[0] = 0x5a827999U;               // Constants defined in SHA-1
  K[1] = 0x6ed9eba1U;
  K[2] = 0x8f1bbcdcU;
  K[3] = 0xca62c1d6U;
  int t;                            // Loop counter
  uint32_t temp;                    // Temporary word value
  uint32_t W[80];                   // Word sequence
  uint32_t E;                       // Word buffers 

  for (t = 0; t < 16; t++) {
    W[t]  = ctx->message_block[t * 4] << 24;
    W[t] |= ctx->message_block[t * 4 + 1] << 16;
    W[t] |= ctx->message_block[t * 4 + 2] << 8;
    W[t] |= ctx->message_block[t * 4 + 3];
  }

  for(t = 16; t < 80; t++) { W[t] = sha1_circular_lshift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]); }

  A = ctx->intermediate_hash[0];
  B = ctx->intermediate_hash[1];
  C = ctx->intermediate_hash[2];
  D = ctx->intermediate_hash[3];
  E = ctx->intermediate_hash[4];

  for(t = 0; t < 20; t++) {
    temp =  sha1_circular_lshift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
    E = D;
    D = C;
    C = sha1_circular_lshift(30,B);
    B = A;
    A = temp;
  }

  for(t = 20; t < 40; t++) {
    temp = sha1_circular_lshift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = sha1_circular_lshift(30,B);
    B = A;
    A = temp;
  }

  for(t = 40; t < 60; t++) {
    temp = sha1_circular_lshift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
    E = D;
    D = C;
    C = sha1_circular_lshift(30,B);
    B = A;
    A = temp;
  }

  for(t = 60; t < 80; t++) {
    temp = sha1_circular_lshift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = sha1_circular_lshift(30,B);
    B = A;
    A = temp;
  }

  ctx->intermediate_hash[0] += A;
  ctx->intermediate_hash[1] += B;
  ctx->intermediate_hash[2] += C;
  ctx->intermediate_hash[3] += D;
  ctx->intermediate_hash[4] += E;

  ctx->message_block_index = 0;

  free(K);
  return success;
}

// process input buffer 64 bytes at a time
int sha1_update(sha1_context *ctx, uint8_t *input_buffer)
{
  unsigned input_index = 0;
  for (ctx->message_block_index = 0; ctx->message_block_index < 64; ctx->message_block_index++) {
    ctx->message_block[ctx->message_block_index] = input_buffer[input_index];
    input_index++;
  }
  if (ctx->message_block_index == 64) { sha1_step(ctx); }
  
  return success;
}

// add padding on final block before calculations
int sha1_finalize(sha1_context *ctx, uint8_t *input_buffer, size_t input_len)
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
  ctx->computed = 1;

  return success;
}

void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result)
{
  sha1_context ctx;
  int err;

  // set size
  ctx.length_high = stream_len & 0xFFFFFFFF00000000ULL;
  ctx.length_low = stream_len & 0x00000000FFFFFFFFULL;

  err = sha1_init(&ctx);
  if (err) {
    fprintf(stderr, "sha1_reset() error: %d\n", err);
    exit(1);
  }

  // read input 64 bytes at a time
  uint8_t *input_buffer = malloc(64);
  size_t input_len = 0;
    while ((input_len = fread(input_buffer, 1, 64, stream)) > 0) {
      if (input_len == 64) {
        err = sha1_update(&ctx, input_buffer);
        if (err) { fprintf(stderr, "sha1_update() error: %d\n", err); }
      } else {
        err = sha1_finalize(&ctx, input_buffer, input_len);
        if (err) { fprintf(stderr, "sha1_finalize() error: %d\n", err); }
      }
    }

  free(input_buffer);

  memcpy(sha1_result, ctx.intermediate_hash, 20);
  return;
}