#include "sha1.h"

#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

int SHA1Reset(SHA1Context *ctx)
{
    if (!ctx) { return shaNull; }

    ctx->Length_Low = 0;
    ctx->Length_High = 0;
    ctx->Message_Block_Index = 0;

    ctx->Intermediate_Hash[0]   = 0x67452301;
    ctx->Intermediate_Hash[1]   = 0xEFCDAB89;
    ctx->Intermediate_Hash[2]   = 0x98BADCFE;
    ctx->Intermediate_Hash[3]   = 0x10325476;
    ctx->Intermediate_Hash[4]   = 0xC3D2E1F0;

    ctx->Computed   = 0;
    ctx->Corrupted  = 0;
    return shaSuccess;
}

int SHA1Result( SHA1Context *ctx, uint8_t Message_Digest[SHA1HashSize]) 
{
    int i;

    if (!ctx || !Message_Digest) { return shaNull; }

    if (ctx->Corrupted) { return ctx->Corrupted; }

    if (!ctx->Computed) {
        SHA1PadMessage(ctx);
        for (i=0; i<64; ++i) { ctx->Message_Block[i] = 0; }  /* message may be sensitive, clear it out */
        ctx->Length_Low = 0;                                /* and clear length */
        ctx->Length_High = 0;
        ctx->Computed = 1;
    }

    for(i = 0; i < SHA1HashSize; ++i) { Message_Digest[i] = ctx->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ); }

    return shaSuccess;
}

int SHA1Input(SHA1Context *ctx, const uint8_t *message_array, unsigned length)
{
    if (!length) { return shaSuccess; }

    if (!ctx || !message_array) { return shaNull; }

    if (ctx->Computed) {
        ctx->Corrupted = shaStateError;
        return shaStateError;
    }

    if (ctx->Corrupted) { return ctx->Corrupted; }

    while(length-- && !ctx->Corrupted) {
        ctx->Message_Block[ctx->Message_Block_Index++] = (*message_array & 0xFF);

        ctx->Length_Low += 8;
        if (ctx->Length_Low == 0) {
            ctx->Length_High++;
            if (ctx->Length_High == 0) { ctx->Corrupted = 1; } /* Message is too long */
        }

        if (ctx->Message_Block_Index == 64) { SHA1ProcessMessageBlock(ctx); }

        message_array++;
    }

    return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *ctx)
{
    const uint32_t K[] = { 0x5A827999,  /* Constants defined in SHA-1   */
                           0x6ED9EBA1,
                           0x8F1BBCDC,
                           0xCA62C1D6   };
    int t;                              /* Loop counter                */
    uint32_t temp;                      /* Temporary word value        */
    uint32_t W[80];                     /* Word sequence               */
    uint32_t A, B, C, D, E;             /* Word buffers                */

    for (t = 0; t < 16; t++) {
        W[t] = ctx->Message_Block[t * 4] << 24;
        W[t] |= ctx->Message_Block[t * 4 + 1] << 16;
        W[t] |= ctx->Message_Block[t * 4 + 2] << 8;
        W[t] |= ctx->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++) { W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]); }

    A = ctx->Intermediate_Hash[0];
    B = ctx->Intermediate_Hash[1];
    C = ctx->Intermediate_Hash[2];
    D = ctx->Intermediate_Hash[3];
    E = ctx->Intermediate_Hash[4];

    for(t = 0; t < 20; t++) {
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++) {
        temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    ctx->Intermediate_Hash[0] += A;
    ctx->Intermediate_Hash[1] += B;
    ctx->Intermediate_Hash[2] += C;
    ctx->Intermediate_Hash[3] += D;
    ctx->Intermediate_Hash[4] += E;

    ctx->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *ctx)
{
    if (ctx->Message_Block_Index > 55) {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < 64) { ctx->Message_Block[ctx->Message_Block_Index++] = 0; }

        SHA1ProcessMessageBlock(ctx);

        while(ctx->Message_Block_Index < 56) { ctx->Message_Block[ctx->Message_Block_Index++] = 0; }
    } else {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < 56) { ctx->Message_Block[ctx->Message_Block_Index++] = 0; }
    }

    // append 64 bits of length
    ctx->Message_Block[56] = ctx->Length_High >> 24;
    ctx->Message_Block[57] = ctx->Length_High >> 16;
    ctx->Message_Block[58] = ctx->Length_High >> 8;
    ctx->Message_Block[59] = ctx->Length_High;
    ctx->Message_Block[60] = ctx->Length_Low >> 24;
    ctx->Message_Block[61] = ctx->Length_Low >> 16;
    ctx->Message_Block[62] = ctx->Length_Low >> 8;
    ctx->Message_Block[63] = ctx->Length_Low;

    SHA1ProcessMessageBlock(ctx);
}
