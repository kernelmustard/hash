#ifndef CRC_H
#define CRC_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void crc32(FILE *stream, uint64_t stream_len, uint32_t *crc32_result);
void crc32_table(void);

#endif