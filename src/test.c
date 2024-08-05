#include "sha1/sha1.c"
#include "CUnit/Basic.h"
#include <stdio.h>
#include <stdint.h>

#define SUCCESS 0

int init_suite(void) 
{
  return 0;
}

int clean_suite(void) 
{
  return 0;
}

void string_to_file(char const *string, FILE **stream, uint64_t len)
{
  *stream = tmpfile();

  fprintf(*stream, "%s", string);
  rewind(*stream);
  
  return;
}

void sha1_vec1(void)
{
  char const string[] = "";
  char const expect[] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  char result[41] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[20] = { 0 };
  sha1(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 40) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void sha1_vec2(void)
{
  char const string[] = "a";
  char const expect[] = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8";
  char result[41] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[20] = { 0 };
  sha1(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 40) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}

int main(void)
{
  // declare test suites
  //CU_pSuite crc32_pSuite = NULL;
  CU_pSuite sha1_pSuite = NULL;

  // initalize CUnit registry
  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }
  
  // initialize test suites
  //crc32_pSuite = CU_add_suite("CRC32", init_suite, clean_suite); // source: https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/crc32.testvec
  //if (crc32_pSuite == NULL) 
  //{
  //  CU_cleanup_registry();
  //  return CU_get_error();
  //}

  sha1_pSuite = CU_add_suite("SHA1", init_suite, clean_suite);  // source: https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/sha1.testvec
  
  // add tests to suites
  //if (NULL == CU_add_test(crc32_pSuite, "Test of Test Vector 1", crc32_vec1))
  //{
  //  CU_cleanup_registry();
  //  return CU_get_error();
  //}

  if (NULL == CU_add_test(sha1_pSuite, "Test of SHA1 Vector 1", sha1_vec1))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (NULL == CU_add_test(sha1_pSuite, "Test of SHA1 Vector 2", sha1_vec2))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }


  // Run all tests using the CUnit Basic interface
  CU_basic_set_mode(CU_BRM_VERBOSE);  // set the run mode for the basic interface
  CU_basic_run_tests();               // run all registered CUnit tests using the basic interface
  CU_cleanup_registry();              // clear test registry
  return CU_get_error();              // return current error condition code
}