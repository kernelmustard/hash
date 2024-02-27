#include "main.h"
#include "crc.c"
#include "md5.c"
#include "sha1.c"

static int verbose_flag = 0;
static int all_algo_flag = 0;

int main(int argc, char **argv) {
  int gol_ret;
  FILE *stream = NULL; // ptf to input message stream
  uint64_t stream_len = 0; // stream length, 64 bits can hold the length of a 16 EiB file

  if (argc < 2) {
    printf("Not enough arguments!\n");
    print_help();
    exit(1);
  }

  while (1) {
    static struct option long_options[] = {
      {"verbose", no_argument,        &verbose_flag, 1}, // set verbosity flag
      {"all",     no_argument,        &all_algo_flag, 1},
      {"help",    no_argument,        0, 'h'},
      {"file",    required_argument,  0, 'f'},
      {"string",  required_argument,  0, 's'}, // TODO: CHECK IF FILE SET AND REJECT
      {"crc32",   no_argument,        0, 'c'},
      {"md5",     no_argument,        0, 'm'},
      {"sha1",    no_argument,        0, 'o'},
      {0, 0, 0, 0} // "The last element of the array has to be filled with zeros."
    };

    int option_index = 0; // getopt_long stores the option index here
    gol_ret = getopt_long(argc, argv, "vhf:s:acm", long_options, &option_index);

    // Detect the end of the options
    if (gol_ret == -1) {
      break;
    }

    switch (gol_ret) {
      case 1:
        // If this option set a flag, do nothing else now.
        break;
      case 'v': // support -v
        verbose_flag = 1;
        break;

      case 'h':
        print_help();
        break;

      case 'f':
        stream = fopen(optarg, "rb");

        fseek(stream, 0, SEEK_END); // move fp to EOF, and ftell the num of bytes from beginning to fp
        stream_len = ftell(stream);
        fseek(stream, 0, SEEK_SET); // same as rewind(f)

        if (stream_len >= pow(2, 32)) { // retrict size to ~4GiB
          printf("[ERROR] File too large! The max size is %f.\n", pow(2, 32)); // possible to hash larger files with memory-mapping, but for now no large files
          exit(-1);
        }
        break;
      case 's':
        stream_len = strlen(optarg) + 1;
        stream = tmpfile();
        if (stream == NULL) {
          perror("Unable to create tmpfile!\n");
          exit(-1);
        }
        // crc32 showing error reading string from stdin, (md5 not having issues, no issue crc32ing a file either)

        for (unsigned i = 0; optarg[i] != '\0'; i++) {
          fputc(optarg[i], stream);
        }
        rewind(stream);
        break;

      case 'a':
        all_algo_flag = 1;
        // fall through
      case 'c': {
        uint32_t crc32_result = 0;
        crc32(stream, stream_len, &crc32_result);
        printf("CRC32\t%x\n", crc32_result);
        if (!all_algo_flag) { // if not all algo's, break
          if (stream != NULL) { fclose(stream); }
          break;
        }
      }
        // fall through
      case 'm': { 
        uint8_t md5_result[16] = { 0 };
        md5(stream, &(md5_result[0]));
        printf("MD5\t");
        for (unsigned i = 0; i < 16; i++) { printf("%02x", md5_result[i]); }
        printf("\n");
        if (!all_algo_flag) { // if not all algo's, break
          if (stream != NULL) { fclose(stream); }
          break;
        }
      }
        // fall through
      case 'o': {
        uint8_t sha1_result[20] = { 0 };
        sha1(stream, stream_len, &(sha1_result[0]));
        printf("SHA1\t");
        for (unsigned i = 0; i < 20; i++) { printf("%02x", sha1_result[i]); }
        printf("\n");
        if (stream != NULL) { fclose(stream); }
        break;
      }

      case '?':
        // getopt_long already printed an error message.
        break;

      default:
        exit(-1);
    }
  }
  return 0;
}

void print_help(void) {
  printf("\n\
./hash [[--help|-h | [--verbose|-v]]] [[--file|-f] <file> | [--string|-s] \"string\" ] [[--all|-a] | [--crc32|-c] | [--md5|-m] | [--sha1|-o]]\n\
--help      | -h\t\tPrint help message\n\
--verbose   | -v\t\tPrint verbose output\n\
--file      | -f\t\tSpecify a file to hash\n\
--all       | -a\t\tGenerate all hashes\n\
--crc32     | -c\t\tGenerate CRC-32 hash\n\
--md5       | -m\t\tGenerate MD5 hash\n\
--sha1      | -o\t\tGenerate SHA1 hash\n");
  return;
}