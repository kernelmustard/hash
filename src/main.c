#include "main.h"
#include "crc.c"
#include "md5.c"
#include "sha1.c"


uint8_t arg_flags = 0;
/* first
 * 0 verbose  (0x01)
 * 0 file     (0x02)
 * 0 string   (0x04)
 * 0 all      (0x08)
 * 
 * 0 crc32    (0x10)
 * 0 md5      (0x20)
 * 0 sha1     (0x40)
 * 0 
 */

int main(int argc, char **argv) {  

  if (argc < 2) {
    printf("Not enough arguments!\n");
    print_help();
    exit(1);
  }

  int gol_ret = 0;
  char *filename = NULL;
  char *string = NULL;

  while (1) 
  {
    static struct option long_options[] = {
      {"verbose", no_argument,        0, 'v'},
      {"help",    no_argument,        0, 'h'},
      {"file",    required_argument,  0, 'f'},
      {"string",  required_argument,  0, 's'},
      {"all",     no_argument,        0, 'a'},
      {"crc32",   no_argument,        0, 'c'},
      {"md5",     no_argument,        0, 'm'},
      {"sha1",    no_argument,        0, 'o'},
      {0, 0, 0, 0} // "The last element of the array has to be filled with zeros."
    };

    int option_index = 0; // getopt_long stores the option index here
    gol_ret = getopt_long(argc, argv, "vhf:s:acm", long_options, &option_index);

    // Detect the end of the options
    if (gol_ret == -1) { break; }

    switch (gol_ret) 
    {
      case 'v': // support -v
        arg_flags |= 0x01;
        printf("Verbose flag set!\n");
        break;

      case 'h':
        if (arg_flags & 0x01) { printf("Printing help!\n"); }
        print_help();
        return 0;

      case 'f':
        if (arg_flags & 0x04) 
        { 
          perror("Unable to read file: string already set!\n"); 
          break;
        }
        if (arg_flags & 0x01) { printf("Reading file!\n"); }
        arg_flags |= 0x02;
        filename = malloc(strlen(optarg) + 1);
        strcpy(filename, optarg);
        break;

      case 's':
        if (arg_flags & 0x02) 
        {
          perror("Unable to read string: file already set!\n");
          break;
        }
        arg_flags |= 0x04;
        string = malloc(strlen(optarg) + 1);  // does not validate length of user-controlled input string
        strcpy(string, optarg);               // merely allows user to shoot their own dick off
        break;

      case 'a':
        if (arg_flags & 0x01) { printf("All hashing algorithms selected\n"); }
        arg_flags |= 0x08;
        // fall through
      case 'c':
        arg_flags |= 0x10;
        if (arg_flags & 0x01) { printf("CRC32 flag set\n"); }
        if (!(arg_flags & 0x08)) { break; }
        // fall through
      case 'm':
        arg_flags |= 0x20;
        if (arg_flags & 0x01) { printf("MD5 flag set\n"); }
        if (!(arg_flags & 0x08)) { break; }
        // fall through  
      case 'o':
        arg_flags |= 0x40;
        if (arg_flags & 0x01) { printf("SHA1 flag set\n"); }
        if (!(arg_flags & 0x08)) { break; }
        // fall through

      case '?':
        // getopt_long already printed an error message.
        break;

      default:
        return -1;
    }
  }

  FILE *stream = NULL; // ptr to input message stream
  uint64_t stream_len = 0; // stream length, 64 bits can hold the length of a 16 EiB file

  if (arg_flags & 0x02) {
    if (arg_flags & 0x01) { printf("Reading file %s\n", filename); };
    stream = fopen(filename, "rb");


    fseek(stream, 0, SEEK_END); // move fp to EOF, and ftell the num of bytes from beginning to fp
    stream_len = ftell(stream);
    fseek(stream, 0, SEEK_SET); // same as rewind(f)

    if (arg_flags & 0x01) { printf("File length is %ld\n", stream_len); }
    if (stream_len >= pow(2, 64))   // retrict size to length held by uint64_t  (some amount of exabytes)
    { 
      fprintf(stderr, "File too large! The max size is %f.\n", pow(2, 64));
       return -1;
    }
  } 
  else if (arg_flags & 0x04) 
  {
    stream_len = strlen(string);
    stream = tmpfile();
    if (stream == NULL) 
    {
      perror("Unable to create tmpfile!\n");
      return -1;
    }

    for (unsigned i = 0; string[i] != '\0'; i++) { fputc(string[i], stream); }
    rewind(stream);
    free(string);
  } 
  else 
  {
    perror("You must either select a file or string to hash!\n");
    return -1;
  }

  // CRC32
  if (arg_flags & 0x10) 
  {
    uint32_t crc32_result = 0;
    crc32(stream, stream_len, &crc32_result);
    printf("CRC32\t%x\n", crc32_result);
  }

  // MD5
  if (arg_flags & 0x20) 
  {
    uint8_t md5_result[16] = { 0 };
    md5(stream, &(md5_result[0]));
    printf("MD5\t");
    for (unsigned i = 0; i < 16; i++) { printf("%02x", md5_result[i]); }
    printf("\n");
  }

  // SHA1
  if (arg_flags & 0x40)
  {
    uint8_t sha1_result[20] = { 0 };
    sha1(stream, stream_len, &(sha1_result[0]));
    printf("SHA1\t");
    for (unsigned i = 0; i < 20; i++) { printf("%02x", sha1_result[i]); }
    printf("\n");
  }

  if (filename != NULL) { free(filename); }
  fclose(stream);
  return 0;
}

void print_help(void) 
{
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
