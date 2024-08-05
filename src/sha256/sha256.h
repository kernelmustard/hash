#ifndef SHA256_H
#define SHA256_H

#include <stdio.h>
#include <stdint.h>

void sha256(FILE *stream, uint64_t stream_len, uint8_t *sha256_result);

#endif