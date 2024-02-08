#include <stdio.h>      // printf fileno fopen fseek ftell fread
#include <getopt.h>     // getopt_long
#include <stdlib.h>     // abort abs
//#include <inttypes.h> // Uncomment in case you need portable printf for larger types like uint64_t
#include <stdint.h>     // uintX_t
#include <math.h>       // sin floor

#include "crc.c"
#include "md5.c"

typedef unsigned __int128 uint128_t;

static int verbose_flag = 0; 
static int all_algo_flag = 0;

void print_help(void);

int main(int argc, char **argv) 
{
    unsigned gol_ret;
    FILE *stream = NULL;    // store input message
    uint64_t stream_len = 0;


    while (1) {
        static struct option long_options[] =
        {
            {"verbose", no_argument,        &verbose_flag,  1},     // set verbosity flag
            {"all",     no_argument,        &all_algo_flag, 1},
            {"help",    no_argument,        0,              'h'},
            {"file",    required_argument,  0,              'f'},
            {"stdin",   required_argument,  0,              's'},   // TODO: CHECK IF FILE SET AND REJECT
            {"crc32",   no_argument,        0,              'c'},
            {"md5",     no_argument,        0,              'm'},
            {0, 0, 0, 0}                                            // "The last element of the array has to be filled with zeros."
        };

        int option_index = 0;   // getopt_long stores the option index here 
        gol_ret = getopt_long(argc, argv, "vahf:s:c", long_options, &option_index);

        // Detect the end of the options
        if (gol_ret == -1) {
            break;
        }

        char *message = NULL;       // file contents buffer
        uint64_t stream_len = 0;   // file length, 64 bits can hold the length of a 16 EiB file
        switch (gol_ret)
            {
            case 1:
                // If this option set a flag, do nothing else now.
                if (long_options[option_index].flag != 0)
                    break;
                printf("option %s", long_options[option_index].name);
                if (optarg) {
                    printf(" with arg %s", optarg);
                }
                printf("\n");
                break;
            case 'v':   // support -v and -a 
                verbose_flag = 1;
                break;

            case 'h':
                print_help();
                break;

            case 'f':
                stream = fopen(optarg, "rb");
                fseek(stream, 0, SEEK_END);  // move fp to EOF, and ftell the num of bytes from beginning to fp
                stream_len = ftell(stream);
                fseek(stream, 0, SEEK_SET);  // same as rewind(f)

                if (stream_len >= (2^32)) {  // retrict size to ~4GiB
                    printf("[ERROR] File too large! The max size is %d.\n", 2^32);  // possible to hash larger files with memory-mapping, but for now no large files
                    abort();
                }
                break;
            case 's':
                // read from stdin
                message = optarg;
                
            case 'a':
                all_algo_flag = 1;
            case 'c':
                uint32_t crc32_result = crc32(stream, stream_len);
                printf("CRC32\t%d", crc32_result);
                stream_len = sizeof(message);
                if (all_algo_flag != 0) { // if not all algo's, break
                    fclose(stream);
                    break; 
                }
            case 'm':
                uint8_t md5_result[16] = { 0 };
                md5(stream, stream_len, md5_result);
                printf("MD5\t");
                if (all_algo_flag != 0) { // if not all algo's, break
                    fclose(stream);
                    break; 
                }
                fclose(stream); // fall through to last algo
                break;
            
            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
            }
        }

    /* Ignore any remaining command line arguments (not options). */
    if (verbose_flag && optind < argc)
        {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
            printf ("%s ", argv[optind++]);
        putchar ('\n');
        }
    
    return 0;
}

void print_help(void)
{
    printf("\n\
./hash [ [--verbose|-v] | [--help|-h] | [--all|-a] ] [ [--crc32|-c] ] [--file|-f] <file>\n\
--help      | -h\t\tPrint help message\n\
--verbose   | -v\t\tPrint verbose output.\n\
--file      | -f\t\tSpecify a file to hash\n\
--all       | -a\t\tGenerate all hashes.\n\
--crc32     | -c\t\tGenerate CRC-32 hash\n\
--md5       | -m\t\tGenerate MD5 hash\n\
    ");
    return;
}