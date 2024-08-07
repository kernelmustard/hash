/**
 * @file md5.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief MD5 implementation
 * 
 *  Overview:   MD5 is a cryptographic hashing algorithm specified in RFC 1321 
 *              that maps an arbitrary number of bytes to a 16 byte hash
 * 
 *  Usage:      1) call md5() with FILE stream, stream length, and ptr to 
 *              16-byte array to hold result
 * 
 *              2) md5() will call md5_init() to initialize the context struct 
 *              md5_context before hashing the FILE stream contents
 * 
 *              3) md5() will read FILE stream 1024 bytes at a time and call 
 *              md5_update() to hash each string segment
 * 
 *              4) md5() will call md5_finalize() to pad length, add length, 
 *              and perform final hash
 * 
 *              5) md5() will copy result to array passed by reference earlier
 */

#ifndef MD5_H_
#define MD5_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  uint8_t buffer[64]; // Input to be used in the next step
  uint64_t bitlen;    // length of input in bytes
  uint32_t state[4];  // Current accumulation of hash
  uint8_t digest[16]; // Result of algorithm
} md5_context;

/**
 * @brief main MD5 function that orchestrates the data from FILE stream to hash
 * @return void
 * @param stream pointer to FILE stream containing data to hash
 * @param md5_result pointer to 20-byte array in main function
 */
void md5(FILE *stream, uint8_t *md5_result);

/**
 * @brief MD5 initialization function. Initialize ctx values
 * @return void
 * @param ctx pointer the md5_context struct
 */
void md5_init(md5_context *ctx);

/**
 * @brief MD5 compression functions. Process string segments in 64-byte blocks 
 * and pass to md5_step()
 * @return void
 * @param ctx pointer to md5_context struct
 * @param data array of bytes to process
 */
void md5_step(md5_context *ctx, uint32_t *data);

/**
 * @brief MD5 update function. Process string segments in 64-byte blocks and 
 * pass to md5_step()
 * @return void
 * @param ctx pointer to md5_context struct
 * @param data pointer to array of bytes to process
 * @param len number of bytes in array to process
 */
void md5_update(md5_context *ctx, const uint8_t *data, size_t len);

/**
 * @brief MD5 finalization function. Pad, rehash, and append total length 
 * before copying ctx->state to ctx->digest
 * @return void
 * @param ctx pointer to md5_context struct 
 */
void md5_finalize(md5_context *ctx);

#endif // MD5_H_