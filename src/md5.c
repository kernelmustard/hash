#include <stdio.h>  // FILE

typedef struct{
    uint64_t size;        // Size of input in bytes
    uint32_t buffer[4];   // Current accumulation of hash
    uint8_t input[64];    // Input to be used in the next step
    uint8_t digest[16];   // Result of algorithm
} MD5Context;

void md5_init(MD5Context *ctx);

void md5(FILE *stream, uint64_t stream_len, uint8_t *result[16])
{
    //MD5Context ctx; // instantiate context struct
    

    return;
}