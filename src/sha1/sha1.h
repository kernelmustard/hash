/**
 * @file sha1.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief SHA1 implementation
 * 
 *  Overview:   SHA1 is a cryptographic hashing algorithm specified in RFC 1321 
 *              that maps and arbitrary number of bytes to a 20-byte hash
 * 
 * Usage:       1) call sha1() with a FILE stream, stream length, and ptr to a 
 *              20-byte array to hold result
 * 
 *              2) sha1() will call sha1_init() to initialize the sha1_context 
 *              struct before hashing the FILE stream contents
 * 
 *              3) sha1() will malloc a buffer and read entire FILE stream 
 *              contents, and call sha1_update() to hash the string a byte at a
 *              time
 * 
 *              4) sha1() will call sha1_finalize() to pad length and perform 
 *              final hash
 * 
 *              5) sha1() will copy result to array passed by reference earlier
 * 
 * @note derived from Steve Reid's (steve@edmweb.com) implementation, which can
 * be found at https://github.com/clibs/sha1/blob/master/sha1.c
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  uint8_t buffer[64];
  uint32_t count[2];
  uint32_t state[5];
  uint8_t digest[20]; // Result of algorithm
} sha1_ctx;

typedef union
{
  uint8_t c[64];
  uint32_t l[16];
} CHAR64LONG16;

/**
 * @brief main SHA1 function that orchestrates the data from file stream to hash
 * @return void
 * @param stream pointer to FILE stream containing data to hash
 * @param stream_len length of data in stream
 * @param sha1_result ptr to 20-byte array in main function
 */
void sha1(FILE *stream, uint64_t stream_len, uint8_t *sha1_result);

/**
 * @brief SHA1 initialization function. Initializes ctx vars
 * @return void
 * @param ctx pointer to sha1_context struct
 */
void sha1_init(sha1_ctx *ctx);

/**
 * @brief SHA1 compression functions. Hashes data in ctx->buffer and passed 
 * results to ctx->state[] array
 * @return void
 * @param ctx pointer to sha1_context struct
 */
void sha1_step(sha1_ctx *ctx);

/**
 * @brief SHA1 update function. Process string segments into 64-byte blocks and
 * pass to sha1_step()
 * @return void
 * @param ctx pointer to sha1_context struct
 * @param data array of bytes to process
 * @param len number of bytes in array to process
 */
void sha1_update(sha1_ctx *ctx, const uint8_t *data, unsigned len);

/**
 * @brief SHA1 finalization function. Pad, rehash, and append total length 
 * before copying ctx->state[] to ctx->digest[]
 * @return void
 * @param ctx pointer to sha1_context struct
 */
void sha1_finalize(sha1_ctx *ctx);

#endif  // SHA1_H