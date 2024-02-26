#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};
#define SHA1HashSize 20

typedef struct SHA1Context {
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest           */
    uint32_t Length_Low;                /* Message length in bits           */
    uint32_t Length_High;               /* Message length in bits           */
    int_least16_t Message_Block_Index;  /* Index into message block array   */
    uint8_t Message_Block[64];          /* 512-bit message blocks           */
    int Computed;                       /* Is the digest computed?          */
    int Corrupted;                      /* Is the message digest corrupted? */
} SHA1Context;

int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result(SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);

#endif