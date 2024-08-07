/**
 * @file sha256.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief Interface to SHA256 implementation
 * 
 *  Overview:   SHA256 is a cryptographic hashing algorithm specifified in RFC 6234
 *              that maps an arbitrary number of bytes to a 64-byte hash.
 * 
 *  Usage:      1) call sha256 with a FILE stream, stream length, and ptr to a 
 *              64 byte array to hold result
 * 
 *              2) sha256 will call sha256_init to initialize the context 
 *              struct sha256_context before hashing the FILE stream 
 *              contents
 *              
 *              3) sha256 will read FILE stream 1024 bytes at a time and call 
 *              sha256_update to hash each string segment
 * 
 *              4) sha256 will call sha256_finalize to pad length and perform 
 *              final hash
 * 
 *              5) sha256 will copy result to array passed by reference earlier
 * @note  Derived from Brad Conte (brad AT bradconte.com). His implementation 
 *        can be found at https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdio.h>  // FILE, fread(), rewind()
#include <stdint.h> // uint8_t, uint32_t, uint64_t
#include <stdlib.h> // malloc(), free()
#include <memory.h> // memset(), memcpy()

typedef struct {
	uint8_t buffer[64];
	uint32_t buffer_offset;
	uint64_t bitlen;
	uint32_t state[8];
  uint8_t digest[64];
} sha256_context;

/**
 * @brief main SHA256 function that orchestrates the data from FILE 
 * stream to hash
 * @return void
 * @param stream pointer to FILE stream containing data to hash
 * @param stream_len length of data in stream
 * @param sha256_result ptr to 64-byte array in main function
 */
void sha256(FILE *stream, uint64_t stream_len, uint8_t *sha256_result);

/**
 * @brief SHA256 initialization function. Initializes ctx
 * @return void
 * @param ctx pointer to sha256_context struct
 */
void sha256_init(sha256_context *ctx);

/**
 * @brief SHA256 compression functions. Hashes data and passes results 
 * to ctx->state[] array
 * @return void
 * @param ctx pointer to sha256_context struct
 * @param data 64-byte array 
 */
void sha256_step(sha256_context *ctx, const uint8_t data[]);

/**
 * @brief SHA256 update function. Process string segments in 64-byte 
 * blocks
 * @return void
 * @param ctx pointer to sha256_context struct 
 * @param data array of bytes to process
 * @param len number of bytes in array to process
 */
void sha256_update(sha256_context *ctx, const uint8_t data[], size_t len);

/**
 * @brief SHA256 finalization function. Pad, rehash, and append total 
 * length before copying state to digest 
 * @return void
 * @param ctx pointer to sha256_context struct
 */
void sha256_final(sha256_context *ctx);

#endif   // SHA256_H
