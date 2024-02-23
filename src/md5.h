#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
  uint64_t size;      // Size of input in bytes
  uint32_t buffer[4]; // Current accumulation of hash
  uint8_t input[64];  // Input to be used in the next step
  uint8_t digest[16]; // Result of algorithm
} MD5Context;

uint32_t rotate_left(uint32_t x, uint32_t n);
void md5(FILE *stream, uint8_t *md5_result);
void md5_init(MD5Context *ctx);
void md5_step(uint32_t *buffer, uint32_t *input);
void md5_update(MD5Context *ctx, uint8_t *input_buffer, size_t input_len);
void md5_finalize(MD5Context *ctx);

#endif