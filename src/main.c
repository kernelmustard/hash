#include <stdio.h>      /* printf fileno fopen fseek ftell fread */    
#include <getopt.h>     /* getopt_long */ 
#include <stdlib.h>     /* abort */
#include <inttypes.h>   /* uint32_t uint8_t */

static int verbose_flag;

void print_help(void);
uint32_t crc32(void *bitstring);

int main(int argc, char **argv) 
{
    unsigned gol_ret;
    int ret = 0;

    while (1)
    {
        static struct option long_options[] =
        {
            {"verbose", no_argument,        &verbose_flag,  1},     /* set verbosity flag */
            {"brief",   no_argument,        &verbose_flag,  0},     /* default brief */
            {"help",    no_argument,        0,              'h'},
            {"file",    required_argument,  0,              'f'},
            {"stdin",   required_argument,  0,              's'},
            {"all",     no_argument,        0,              'a'},
            {"crc32",    no_argument,       0,             'e'},
            {0, 0, 0, 0}                                            /* "The last element of the array has to be filled with zeros." */
        };

        int option_index = 0;   /* getopt_long stores the option index here. */
        gol_ret = getopt_long(argc, argv, "h", long_options, &option_index);

        /* Detect the end of the options. */
        if (gol_ret == -1) {
            break;
        }

        char *file_buf;     // file contents buffer
        size_t file_len;    // file length
        switch (gol_ret)
            {
            case 0:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
                printf("option %s", long_options[option_index].name);
                if (optarg) {
                    printf(" with arg %s", optarg);
                }
                printf("\n");
                break;

            case 'h':
                print_help();
                break;

            case 'f':
                FILE *f = fopen(optarg, "rb");
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

                file = malloc(fsize + 1);
                fread(file, fsize, 1, f);

                // DEBUG
                //printf("%s", file);

                fclose(f);
                file[fsize] = 0;
                break;
            
            case 's':
                // read from stdin
                printf("Reading from stdin is uninplemented!\n");
                break;
            
            case 'a':
                // run all hashes (check if other already applied)
                break;
            
            case 'c':   /* CRC-8 */
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
--help  | -h\t\tPrint help message\n\
--file  | -f\t\tSpecify a file to hash\n\
--crc8  | -c\t\tGenerate CRC-8 hash\n\
--crc16 | -d\t\tGenerate CRC-16 hash\n\
--crc32 | -e\t\tGenerate CRC-32 hash\n\
--crc64 | -f\t\tGenerate CRC-64 hash\n\
--all   | -a\t\tGenerate all hashes.\n\
");
    return;
}

uint32_t crc32(const uint8_t data[], size_t data_length) {
	uint32_t crc32 = 0xFFFFFFFFu;
	
	for (size_t i = 0; i < data_length; i++) {
		const uint32_t lookupIndex = (crc32 ^ data[i]) & 0xff;
		crc32 = (crc32 >> 8) ^ CRCTable[lookupIndex];  // CRCTable is an array of 256 32-bit constants
	}
	
	// Finalize the CRC-32 value by inverting all the bits
	crc32 ^= 0xFFFFFFFFu;
	return crc32;
}
