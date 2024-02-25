#include "crc.h"

void crc32(FILE *stream, uint64_t stream_len, uint32_t *crc32_result) 
{
  // parse stream
  uint8_t *message = malloc(stream_len);
  size_t ret = fread(message, 1, stream_len, stream);

  // Table of CRCs of all 8-bit messages.
  uint32_t crc_table[256];
  for (unsigned index = 0; index < 256; index++) {
    uint32_t crc_table_val = (uint32_t)index;
    for (unsigned nibble = 0; nibble < 8; nibble++) { // iterate of 8 parts of 32-bit int
      if (crc_table_val & 1) {
        crc_table_val = (uint32_t)0xedb88320 ^ (crc_table_val >> 1);
      } else {
        crc_table_val >>= 1;
      }
    }
    crc_table[index] = crc_table_val;
  }

  uint32_t crc32_string = 0xffffffff;

  for (unsigned count = 0; count < stream_len; count++) {
    crc32_string = crc_table[(crc32_string ^ message[count]) & 0xff] ^ (crc32_string >> 8);
  }

  *crc32_result = crc32_string ^ (uint32_t)0xffffffff; // return 1s complement of crc32_string (used message[0..stream_len-1])
}
