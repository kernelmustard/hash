#include <string.h> // memset

// Implementation heavily influenced by/ stolen from w3's PNG
uint32_t crc32(FILE *stream, uint64_t stream_len) 
{
    // parse stream
    char message[stream_len];
    memset(message, '\0', stream_len);
    fread(message, sizeof(message[0]), stream_len, stream);

    // Table of CRCs of all 8-bit messages.
    uint32_t crc_table[256];
    for (unsigned index=0; index<256; index++) {
        uint32_t crc_table_val = (uint32_t)index;
        for (unsigned unk=0; unk<8; unk++) {   // What value is this representing??
            if (crc_table_val & 1) {
                crc_table_val = (uint32_t)0xedb88320 ^ (crc_table_val >> 1);
            } else {
                crc_table_val = crc_table_val >> 1;
            }
        }
        crc_table[index] = crc_table_val;
    }

    uint32_t crc32_string = 0xffffffff;

    for (unsigned count=0; count<stream_len; count++) {
        crc32_string = crc_table[(crc32_string ^ message[count]) & 0xff] ^ (crc32_string >> 8);
    }

    return crc32_string ^ (uint32_t)0xffffffff;  // return crc32_string of message[0..stream_len-1]
}
