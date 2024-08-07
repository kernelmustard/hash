/**
 * @file crc32.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief CRC32 implementation 
 * @note Reworked version of W3C's algo published in their PNG specification 
 * (https://www.w3.org/TR/png/#D-CRCAppendix). Many thanks to all the folks 
 * that worked on it
 */

#include "crc32.h"

void crc32(FILE *stream, uint64_t stream_len, uint32_t *crc32_result) 
{
  // parse stream
  uint8_t *message = malloc(stream_len);
  size_t ret = fread(message, 1, stream_len, stream);
  if (ret <= 0) {}  // do nothing to quiet error message

  // Table of CRCs of all 8-bit messages.
  uint32_t crc32_table[256];
  for (unsigned index = 0; index < 256; index++) 
  {
    uint32_t crc_table_val = (uint32_t)index;
    for (unsigned nibble = 0; nibble < 8; nibble++) // iterate of 8 parts of 32-bit int
    { 
      if (crc_table_val & 1) 
      { 
        crc_table_val = 0xedb88320U ^ (crc_table_val >> 1); 
      } 
      else 
      { 
        crc_table_val >>= 1; 
      }
    }
    crc32_table[index] = crc_table_val;
  }

  uint32_t crc32_string = 0xffffffffU;

  for (unsigned count = 0; count < stream_len; count++) 
  {
    crc32_string = crc32_table[(crc32_string ^ message[count]) & 0xff] ^ (crc32_string >> 8);
  }

  // clean up
  rewind(stream);

  *crc32_result = crc32_string ^ 0xffffffffU; // return 1s complement of crc32_string (used message[0..stream_len-1])
}
