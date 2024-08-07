/**
 * @file main.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief Main function for hash program
 * 
 *  Overview:   Hash a file or string up to 2^64 in length 
 * 
 */

#ifndef MAIN_H
#define MAIN_H

#include <getopt.h> // struct option, getopt_long(), optarg
#include <stdint.h> // uint8_t, uint32_t, uint64_t
#include <math.h>   // pow()
#include <stdio.h>  // printf(), perror(), FILE, fopen(), fseek(), ftell(), 
                    // fprintf(), tmpfile(), fclose()
#include <stdlib.h> // exit(), malloc(), free()
#include <string.h> // strlen(), strcpy()

/**
 * @brief small helper function to print help message
 * @return void
 * @param void
 */
void print_help(void);

#endif