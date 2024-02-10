#include "crc.h"

// Implementation heavily influenced by/ stolen from w3's PNG
uint32_t crc32(FILE *stream, uint64_t stream_len) 
{
    if (stream == NULL) { printf("WACK!\n"); }  // DEBUG

    // parse stream
    printf("parse stream\n");   // DEBUG
    char message[stream_len];
    memset(message, '\0', stream_len);
    size_t ret = fread(message, sizeof(message[0]), stream_len, stream);
    if (ret != stream_len) {
        printf("Failed to parse file!\n");
        return -1;
    }

    // print message DEBUG
    for (unsigned i=0; i<stream_len; i++) {
        printf("%c", message[i]);
    }
    printf("\n");

    // Table of CRCs of all 8-bit messages.
    printf("make crc table\n"); // DEBUG
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
    printf("crc32_string = %d (before 1s complement)\n", crc32_string);

    return crc32_string ^ (uint32_t)0xffffffff;  // return crc32_string of message[0..stream_len-1]
}
