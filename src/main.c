#include <stdio.h>  /* printf */    
#include <getopt.h> /* getopt_long */ 
#include <stdlib.h> /* abort */

static int verbose_flag;

void print_help(void);

int main(int argc, char **argv) 
{
    unsigned gol_ret;
    while (1)
    {
      static struct option long_options[] =
        {
            {"verbose", no_argument,    &verbose_flag,  1},   /* set verbosity flag */
            {"brief",   no_argument,    &verbose_flag,  0},   /* default brief */
            {"help",    no_argument,    0,              'h'},
            {0, 0, 0,  0}                                     /* "The last element of the array has to be filled with zeros." */
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
        puts ("verbose flag is set");
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
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
--help | -h\tPrint help message.\n\
");
    return;
}