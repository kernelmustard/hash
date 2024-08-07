/**
 * @file sha256.c
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief Interface to SHA256 implementation
 * @note  Derived from Brad Conte (brad AT bradconte.com). His implementation 
 *        can be found at https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
 */

#include "sha256.h"

#define SHA256_ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))

static const uint32_t SHA256_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_step(sha256_context *ctx, const uint8_t buffer[])
{
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0;
  uint32_t t1 = 0, t2 = 0;
  uint32_t m[64] = { 0 };

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (buffer[j] << 24) | (buffer[j + 1] << 16) | (buffer[j + 2] << 8) | (buffer[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + SHA256_K[i] + m[i];
		t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(sha256_context *ctx)
{
	ctx->buffer_offset = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;

  return;
}

void sha256_update(sha256_context *ctx, const uint8_t buffer[], size_t len)
{
	uint32_t i;

	for (i = 0; i < len; ++i) {
		ctx->buffer[ctx->buffer_offset] = buffer[i];
		ctx->buffer_offset++;
		if (ctx->buffer_offset == 64) {
			sha256_step(ctx, ctx->buffer);
			ctx->bitlen += 512;
			ctx->buffer_offset = 0;
		}
	}
}

void sha256_final(sha256_context *ctx)
{
	uint32_t i;

	i = ctx->buffer_offset;

	// Pad whatever data is left in the buffer.
	if (ctx->buffer_offset < 56) 
  {
		ctx->buffer[i++] = 0x80;
		while (i < 56)
			ctx->buffer[i++] = 0x00;
	}
	else 
  {
		ctx->buffer[i++] = 0x80;
		while (i < 64)
			ctx->buffer[i++] = 0x00;
		sha256_step(ctx, ctx->buffer);
		memset(ctx->buffer, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->buffer_offset * 8;
	ctx->buffer[63] = ctx->bitlen;
	ctx->buffer[62] = ctx->bitlen >> 8;
	ctx->buffer[61] = ctx->bitlen >> 16;
	ctx->buffer[60] = ctx->bitlen >> 24;
	ctx->buffer[59] = ctx->bitlen >> 32;
	ctx->buffer[58] = ctx->bitlen >> 40;
	ctx->buffer[57] = ctx->bitlen >> 48;
	ctx->buffer[56] = ctx->bitlen >> 56;
	sha256_step(ctx, ctx->buffer);

	// Since this implementation uses LE uint8_t ordering and SHA uses big endian,
	// reverse all the uint8_ts when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) 
  {
		ctx->digest[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		ctx->digest[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void sha256(FILE *stream, uint64_t stream_len, uint8_t *sha256_result)
{
  sha256_context ctx;
  sha256_init(&ctx);

  uint8_t *input_buffer = malloc(1024);
  size_t input_size = 0;

  while ((input_size = fread(input_buffer, 1, 1024, stream)) > 0) 
  {
    sha256_update(&ctx, input_buffer, input_size);
    for (unsigned i = 0; i < 1024; i++) { input_buffer[i] = 0; }
  }
  sha256_final(&ctx);

  // pass result to main
  memcpy(sha256_result, ctx.digest, 32);

  // clean up
  free(input_buffer);
  rewind(stream);
  
  return;
}