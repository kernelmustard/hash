#include <stdio.h>  /* printf fileno */    
#include <getopt.h> /* getopt_long */ 
#include <stdlib.h> /* abort */

static int verbose_flag;

void print_help(void);
void crc8(void *bitstring);

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
            {"crc8",    no_argument,        0,              'c'},
            {0, 0, 0, 0}                                            /* "The last element of the array has to be filled with zeros." */
        };

        int option_index = 0;   /* getopt_long stores the option index here. */
        gol_ret = getopt_long(argc, argv, "h", long_options, &option_index);

        /* Detect the end of the options. */
        if (gol_ret == -1) {
            break;
        }

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
                FILE *fp;
                char buf[4096]; /* 4MiB limit */
                fp = fopen(optarg, "r");
                if (fp == NULL) {
                    perror("Error opening file");
                    ret = -1;
                }
                if (fgets(buf, sizeof(buf), fp)!=NULL) {
                    /* writing content to stdout */
                    for (unsigned i=0; i<sizeof(buf) ;i++) {
                        putc(buf[i], stdout);
                    }
                }
                fclose(fp);
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



/*  Calculate n-Bit CRC

function crc(bit array bitString[1..len], int len) {
    remainderPolynomial := polynomialForm(bitString[1..n])   // First n bits of the message
    // A popular variant complements remainderPolynomial here; see § Preset to −1 below
    for i from 1 to len {
        remainderPolynomial := remainderPolynomial * x + bitString[i+n] * x0   // Define bitString[k]=0 for k>len
        if coefficient of xn of remainderPolynomial = 1 {
            remainderPolynomial := remainderPolynomial xor generatorPolynomial
        }
    }
    // A popular variant complements remainderPolynomial here; see § Post-invert below
    return remainderPolynomial
}

function crc(bit array bitString[1..len], int len) {
    remainderPolynomial := 0
    // A popular variant complements remainderPolynomial here; see § Preset to −1 below
    for i from 1 to len {
        remainderPolynomial := remainderPolynomial xor (bitstring[i] * xn−1)
        if (coefficient of xn−1 of remainderPolynomial) = 1 {
            remainderPolynomial := (remainderPolynomial * x) xor generatorPolynomial
        } else {
            remainderPolynomial := (remainderPolynomial * x)
        }
    }
    // A popular variant complements remainderPolynomial here; see § Post-invert below
    return remainderPolynomial
}

*/

/* Calculate n-bit CRC with Polynomial division with bytewise message XORing

function crc(byte array string[1..len], int len) {
    remainderPolynomial := 0
    // A popular variant complements remainderPolynomial here; see § Preset to −1 below
    for i from 1 to len {
        remainderPolynomial := remainderPolynomial xor polynomialForm(string[i]) * xn−8
        for j from 1 to 8 {    // Assuming 8 bits per byte
            if coefficient of xn−1 of remainderPolynomial = 1 {
                remainderPolynomial := (remainderPolynomial * x) xor generatorPolynomial
            } else {
                remainderPolynomial := (remainderPolynomial * x)
            }
        }
    }
    // A popular variant complements remainderPolynomial here; see § Post-invert below
    return remainderPolynomial
}

*/