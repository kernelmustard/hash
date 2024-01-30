#include <stdio.h>      /* printf fileno fopen fseek ftell fread */    
#include <getopt.h>     /* getopt_long */ 
#include <stdlib.h>     /* abort abs */
//#include <inttypes.h> /* Uncomment in case you need portable printf for larger types like uint64_t */
#include <stdint.h>     /* uint32_t */
#include <math.h>       /* sin floor */

typedef unsigned __int128 uint128_t;

static int verbose_flag = 0; 
static int all_algo_flag = 0;

void print_help(void);
uint32_t crc32(char *message, uint64_t message_len);
void md5(char *message, uint64_t message_len, uint8_t result[16]);

int main(int argc, char **argv) 
{
    unsigned gol_ret;

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

        char *message = NULL;       /* file contents buffer */
        uint64_t message_len = 0;   /* file length, 64 bits can hold the length of a 16 EiB file */ 
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
                message_len = ftell(f);
                fseek(f, 0, SEEK_SET);  /* same as rewind(f) */

                if (message_len >= sizeof(uint32_t)) {  /* let message_len store large file lengths, but retrict file size to 4GiB */
                    printf("[ERROR] File too large! The max size is %d.\n", sizeof(uint32_t));  /* possible to hash larger files with memory-mapping, but for now no large files */
                    abort();
                }

                message = malloc(message_len + 1);
                fread(message, message_len, 1, f);

                // DEBUG
                if (verbose_flag) {
                    printf("[VERBOSE] File Contents:\n%s\n", message);
                }

                fclose(f);
                message[message_len] = 0;
                break;
            
            case 's':
                // read from stdin
                message = optarg;
                message_len = sizeof(message);
                break;
            
            case 'c':   /* CRC-32 */
                uint32_t crc32_string = crc32(message, message_len);
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

/* Implementation heavily influenced by/ stolen from w3's PNG */
uint32_t crc32(char *message, uint64_t message_len) 
{
    /* Table of CRCs of all 8-bit messages. */
    uint32_t crc_table[256];
    for (unsigned index=0; index<256; index++) {
        uint32_t crc_table_val = (uint32_t)index;
        for (unsigned unk=0; unk<8; unk++) {   /* What value is this representing?? */
            if (crc_table_val & 1) {
                crc_table_val = (uint32_t)0xedb88320 ^ (crc_table_val >> 1);
            } else {
                crc_table_val = crc_table_val >> 1;
            }
        }
        crc_table[index] = crc_table_val;
    }

    uint32_t crc32_string = 0xffffffff;

    for (unsigned count=0; count<message_len; count++) {
        crc32_string = crc_table[(crc32_string ^ message[count]) & 0xff] ^ (crc32_string >> 8);
    }

    return crc32_string ^ (uint32_t)0xffffffff;  /* return crc32_string of message[0..message_len-1] */
}

/* written with great assistance from RFC1321 */
void md5(char *message, uint64_t message_len, uint8_t result[16])
{

    uint8_t message_array[message_len+64+8] = { 0 };    /* init byte array with (actual message length) + (max padding length of 512 bits/64 bytes) + (64 bits/8 bytes of number indicating message length) */ 
    uint32_t message_index = 0;
    for (unsigned count=0; count<message_len; count++) {   /* read message into array */ 
        message_array[message_index] = message[message_index];
        message_index++;    /* either this, or increment before next write to array */
    }

    /* pad input string until 64 bits less than a multiple of 512 (begin with 1) */
    uint64_t padding_len = 0;
    int scratch_len = 448 - (message_len % 512);
    if (scratch_len < 0) {
        padding_len = (scratch_len * -1) + 448;
    } else if (scratch_len == 0) {
        padding_len = 512;  /* if already 448, pad 512 ("Padding is always performed, even if the length of the message is already congruent to 448, modulo 512.") */ 
    }

    message_array[message_index] = 0x80;    /* 1000 0000 */
    message_index++;
    for (unsigned count=0; count<(padding_len-1); count++) {
        message_index++;    /* array initialized to 0, just increment counter */
    }

    /* Append 64 bits of message length, low-order first */
    uint32_t message_len_low = message_len & (uint64_t)0x00000000FFFFFFFF;  /* append lower end first */
    uint32_t message_len_high = message_len & (uint64_t)0xFFFFFFFF00000000;
    message_array[message_index] = message_len_low;
    message_index+=32;
    message_array[message_index] = message_len_high;
    message_index+=32;

    /* Initialize Message Digest buffer, low-order first */
    uint32_t 
    uint32_t a = 0x67452301;
    uint32_t b = 0xefcdab89;
    uint32_t c = 0x98badcfe;
    uint32_t d = 0x10325476;

    /* Calculate the table */
    uint32_t table[64], shift_table[64];
    for (unsigned count=0; count<sizeof(table); count++) {
        table[count] = floor(4294967296 * abs(sin(count)));
    }

    return result;
}