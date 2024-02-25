#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum sha1_return_code {
  success,
  null,            // Null pointer parameter
  input_too_long,  // input data too long 
  state_error      // called Input after Result 
};

#define sha1_hash_size 20

typedef struct sha1_context {
  uint32_t intermediate_hash[sha1_hash_size/4]; // Message Digest                   
  uint32_t length_low;                          // Message length in bits           
  uint32_t length_high;                         // Message length in bits           
  int_least16_t message_block_index;            // Index into message block array   
  uint8_t message_block[64];                    // 512-bit message blocks           
  int computed;                                 // Is the digest computed?          
  int corrupted;                                // Is the message digest corrupted? 
} sha1_context;

void sha1(FILE *stream, uint8_t *sha1_result);
int sha1_init(sha1_context *ctx);
void sha1_step(sha1_context *ctx);
int sha1_update(sha1_context *ctx, uint8_t *input_buffer, size_t input_len);

#endif