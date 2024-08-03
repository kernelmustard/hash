#include "sha1.h"

/*
 * Thank you Steve Reid <steve@edmweb.com> for his implementation of SHA1 in C
 */

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

void sha1_step(sha1_ctx *ctx)
{
  return;
}

void sha1_update(sha1_ctx *ctx, uint8_t *input_buffer, unsigned input_length)
{
  return;
}

void sha1_finalize(sha1_ctx *ctx)
{
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
    sha1_update(&ctx, input_buffer, input_size);
  }
  sha1_finalize(&ctx);

  // clean up
  free(input_buffer);
  rewind(stream);

  // pass result to main
  memcpy(sha1_result, ctx.state, 20);
  return;

  return;
}