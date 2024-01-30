#include <stdio.h>      /* printf fileno fopen fseek ftell fread */    
#include <getopt.h>     /* getopt_long */ 
#include <stdlib.h>     /* abort */
//#include <inttypes.h> /* Uncomment in case you need portable printf for larger types like uint64_t */
#include <stdint.h>     /* uint32_t */

typedef unsigned __int128 uint128_t;

static int verbose_flag = 0; 
static int all_algo_flag = 0;

void print_help(void);
uint32_t crc32(char *bitstring_buf, size_t bitstring_len);
uint128_t md5(char *bitstring_buf, size_t bitstring_len);

int main(int argc, char **argv) 
{
    unsigned gol_ret;
    int ret = 0;

    while (1) {
        static struct option long_options[] =
        {
            {"verbose", no_argument,        &verbose_flag,  1},     /* set verbosity flag */
            {"all",     no_argument,        &all_algo_flag, 1},
            {"help",    no_argument,        0,              'h'},
            {"file",    required_argument,  0,              'f'},
            {"stdin",   required_argument,  0,              's'},   /* TODO: CHECK IF FILE SET AND REJECT */
            {"crc32",   no_argument,        0,              'c'},
            {"md5",     no_argument,        0               'm'},
            {0, 0, 0, 0}                                            /* "The last element of the array has to be filled with zeros." */
        };

        int option_index = 0;   /* getopt_long stores the option index here. */
        gol_ret = getopt_long(argc, argv, "vahf:s:c", long_options, &option_index);

        /* Detect the end of the options. */
        if (gol_ret == -1) {
            break;
        }

        char *bitstring_buf;     // file contents buffer
        size_t bitstring_len;    // file length
        switch (gol_ret)
            {
            case 1:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
                printf("option %s", long_options[option_index].name);
                if (optarg) {
                    printf(" with arg %s", optarg);
                }
                printf("\n");
                break;
            case 'v':   /* support -v and -a  */
                verbose_flag = 1;
                break;
            case 'a':
                all_algo_flag = 1;
                break;

            case 'h':
                print_help();
                break;

            case 'f':
                FILE *f = fopen(optarg, "rb");
                fseek(f, 0, SEEK_END);  /* move fp to EOF, and ftell the num of bytes from beginning to fp*/
                //long fsize = ftell(f);  
                bitstring_len = ftell(f);
                fseek(f, 0, SEEK_SET);  /* same as rewind(f) */

                bitstring_buf = malloc(bitstring_len + 1);
                fread(bitstring_buf, bitstring_len, 1, f);

                // DEBUG
                if (verbose_flag) {
                    printf("[VERBOSE] File Contents:\n%s\n", bitstring_buf);
                }

                fclose(f);
                bitstring_buf[bitstring_len] = 0;
                break;
            
            case 's':
                // read from stdin
                printf("Reading from stdin is uninplemented!\n");
                break;
            
            case 'c':   /* CRC-32 */
                uint32_t crc32_string = crc32(bitstring_buf, bitstring_len);
                printf("[OUTPUT] CRC32: %x\n", crc32_string);
                if (! all_algo_flag) { break; }
                break;  /* fall through to the last hashing algo */
            
            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
            }
        }

    /* Instead of reporting ‘--verbose’
        and ‘--brief’ as they are encountered,
        we report the final status resulting from them. */
    if (verbose_flag) {
        puts ("verbose flag is set\n");
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
        {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
            printf ("%s ", argv[optind++]);
        putchar ('\n');
        }
    return ret;
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

/* Implementation heavily influenced by/ stolen from w3's PNG */
uint32_t crc32(char *bitstring_buf, size_t bitstring_len) 
{
    /* Table of CRCs of all 8-bit messages. */
    uint32_t crc_table[256];
    for (unsigned index=0; index<256; index++) {
        uint32_t crc_table_val = (uint32_t)index;
        for (unsigned unk=0; unk<8; unk++) {   /* What value is this representing?? */
            if (crc_table_val & 1) {
                crc_table_val = 0xedb88320L ^ (crc_table_val >> 1);
            } else {
                crc_table_val = crc_table_val >> 1;
            }
        }
        crc_table[index] = crc_table_val;
    }

    uint32_t crc32_string = 0xffffffffL;

    for (unsigned count=0; count<bitstring_len; count++) {
        crc32_string = crc_table[(crc32_string ^ bitstring_buf[count]) & 0xff] ^ (crc32_string >> 8);
    }

    return crc32_string ^ 0xffffffffL;  /* return crc_string of bitstring_buf[0..bitstring_len-1] */
}

uint128_t md5(char *bitstring_buf, size_t bitstring_len)
{
    uint128_t md5_string = 0x0;
    static unsigned desired_r = 448;   /* 512 - 64 */
    int padding_len = 0;
    
    // pad input string until 64 bits less than a multiple of 512
    padding_len = desired_r - (bitstring_len % 512);
    if (padding_len < 0) {
        padding_len = (padding_len * -1) + 448;
    }

    return md5_string;
}