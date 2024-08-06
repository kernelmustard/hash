/*********************************************************************
* Filename:   sha256.h
* Author:     kernelmustard (GitHub)
* Copyright:  GPL3
* Details:    Defines the API for the corresponding SHA1 implementation
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	unsigned long long bitlen;
	uint32_t state[8];
} sha256_context;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_context *ctx);
void sha256_step(sha256_context *ctx, const uint8_t data[]);
void sha256_update(sha256_context *ctx, const uint8_t data[], size_t len);
void sha256_final(sha256_context *ctx, uint8_t hash[]);

#endif   // SHA256_H
