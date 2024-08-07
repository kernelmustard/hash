/**
 * @file crc32.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief CRC32 implementation
 * 
 *  Overview: CRC32 is a checksumming algorithm specified in "Cyclic Codes For 
 *            Error Detection" by W. W. Peterson and D. T. Brown used to detect
 *            changes (errors) during data transmission
 * 
 *  Usage:    1) call crc32() with a FILE stream, stream length, and ptr to a 
 *            uint32_t  to hold result
 * 
 *            2) crc32() will malloc a buffer and read entire stream into it
 * 
 *            3) crc32() will construct crc_table[] of all possible CRC32 
 *            strings and calculate proper CRC32 using the data in the FILE 
 *            stream
 * 
 *            4) crc32() will assign the value (in 1s complement) to the 
 *            uint32_t passed by reference earlier 
 * 
 * @note Reworked version of W3C's algo published in their PNG specification 
 * (https://www.w3.org/TR/png/#D-CRCAppendix). Many thanks to all the folks 
 * that worked on it
 */

#ifndef CRC_H
#define CRC_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * @brief main CRC32 function that handles mapping FILE stream data to crc32 string
 * @return void
 * @param stream pointer to FILE stream containing data to checksum
 * @param stream_len length of data in stream
 * @param crc32_result pointer to uint32_t in main function
 */
void crc32(FILE *stream, uint64_t stream_len, uint32_t *crc32_result);

#endif  // CRC_H