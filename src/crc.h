#ifndef CRC_H
#define CRC_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void crc(FILE *stream, uint64_t stream_len, uint8_t *crc32_result);

#endif