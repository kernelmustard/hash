#include "crc32/crc32.c"
#include "md5/md5.c"
#include "sha1/sha1.c"
#include "sha256/sha256.c"

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

void crc32_vec1(void)
{
  char const string[] = "";
  char const expect[] = "00000000";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec2(void)
{
  char const string[] = "a";
  char const expect[] = "e8b7be43";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec3(void)
{
  char const string[] = "abc";
  char const expect[] = "352441c2";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec4(void)
{
  char const string[] = "message digest";
  char const expect[] = "20159d7f";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec5(void)
{
  char const string[] = "abcdefghijklmnopqrstuvwxyz";
  char const expect[] = "4c2750bd";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec6(void)
{
  char const string[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char const expect[] = "1fc2e6d2";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void crc32_vec7(void)
{
  char const string[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  char const expect[] = "7ca94a72";
  char result[9] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint32_t hash = 0;
  crc32(stream, len, &hash);

  // convert result to string
  sprintf(&result[0], "%x", hash & 0xf0000000);
  sprintf(&result[1], "%x", hash & 0x0f000000);
  sprintf(&result[2], "%x", hash & 0x00f00000);
  sprintf(&result[3], "%x", hash & 0x000f0000);
  sprintf(&result[4], "%x", hash & 0x0000f000);
  sprintf(&result[5], "%x", hash & 0x00000f00);
  sprintf(&result[6], "%x", hash & 0x000000f0);
  sprintf(&result[7], "%x", hash & 0x0000000f);

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 8) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}

void md5_vec1(void) 
{
  char const string[] = "";
  char const expect[] = "d41d8cd98f00b204e9800998ecf8427e";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec2(void) 
{
  char const string[] = "a";
  char const expect[] = "0cc175b9c0f1b6a831c399e269772661";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec3(void) 
{
  char const string[] = "abc";
  char const expect[] = "900150983cd24fb0d6963f7d28e17f72";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec4(void) 
{
  char const string[] = "message digest";
  char const expect[] = "f96b697d7cb7938d525a2f31aaf161d0";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec5(void) 
{
  char const string[] = "abcdefghijklmnopqrstuvwxyz";
  char const expect[] = "c3fcd3d76192e4007dfb496cca67e13b";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec6(void) 
{
  char const string[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char const expect[] = "d174ab98d277d9f5a5611c2c9f419d9f";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
  return;
}
void md5_vec7(void) 
{
  char const string[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  char const expect[] = "57edf4a22be3c955ac49da2e2107b67a";
  char result[33] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[16] = { 0 };
  md5(stream, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 16) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }
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
void sha1_vec3(void)
{
  char const string[] = "abc";
  char const expect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
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
void sha1_vec4(void)
{
  char const string[] = "message digest";
  char const expect[] = "c12252ceda8be8994d5fa0290a47231c1d16aae3";
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
void sha1_vec5(void)
{
  char const string[] = "abcdefghijklmnopqrstuvwxyz";
  char const expect[] = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89";
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
void sha1_vec6(void)
{
  char const string[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  char const expect[] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
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
void sha1_vec7(void)
{
  char const string[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char const expect[] = "761c457bf73b14d27e9e9265c46f4b4dda11f940";
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
void sha1_vec8(void)
{
  char const string[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  char const expect[] = "50abf5706a150990a08b2c5ea40fa0e585554732";
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

void sha256_vec1(void)
{
  char const string[] = "";
  char const expect[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec2(void)
{
  char const string[] = "a";
  char const expect[] = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec3(void)
{
  char const string[] = "abc";
  char const expect[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec4(void)
{
  char const string[] = "message digest";
  char const expect[] = "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec5(void)
{
  char const string[] = "abcdefghijklmnopqrstuvwxyz";
  char const expect[] = "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec6(void)
{
  char const string[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  char const expect[] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec7(void)
{
  char const string[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char const expect[] = "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}
void sha256_vec8(void)
{
  char const string[] = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  char const expect[] = "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e";
  char result[65] = { '\0' };

  // convert string to FILE
  FILE *stream = NULL;
  uint64_t len = sizeof(string)/sizeof(string[0])-1;
  string_to_file(string, &stream, len);

  // calculate hash
  uint8_t hash[32] = { 0 };
  sha256(stream, len, &(hash[0]));

  // convert result to string
  unsigned res_ctr = 0;
  for (unsigned i = 0; i < (sizeof(hash) / sizeof(hash[0])); i++)
  {
    sprintf(&result[res_ctr], "%x", hash[i] & 0xf0);
    sprintf(&result[res_ctr+1], "%x", hash[i] & 0x0f);
    res_ctr += 2;
  }

  // compare result to known good
  CU_ASSERT( strncmp(result, expect, 64) == SUCCESS );

  if (fclose(stream) != 0)
  {
    fprintf(stderr, "Failed to close file with %d\n", errno);
  }

  return;
}

int main(void)
{
  // declare test suites
  CU_pSuite crc32_pSuite = NULL;
  CU_pSuite md5_pSuite = NULL;
  CU_pSuite sha1_pSuite = NULL;
  CU_pSuite sha256_pSuite = NULL;

  // initalize CUnit registry
  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }
  
  // initialize test suites
  crc32_pSuite = CU_add_suite("CRC32", init_suite, clean_suite); // https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/crc32.testvec
  if (crc32_pSuite == NULL) 
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  md5_pSuite = CU_add_suite("MD5", init_suite, clean_suite);    // https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/md5.testvec
  if (md5_pSuite == NULL)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  
  sha1_pSuite = CU_add_suite("SHA1", init_suite, clean_suite);  // https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/sha1.testvec
  if (sha1_pSuite == NULL)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  sha256_pSuite = CU_add_suite("SHA256", init_suite, clean_suite);  // https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/sha256.testvec
  if (sha256_pSuite == NULL)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  
  // add tests to suites
  if (NULL == CU_add_test(crc32_pSuite, "Vector 1", crc32_vec1) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 2", crc32_vec2) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 3", crc32_vec3) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 4", crc32_vec4) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 5", crc32_vec5) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 6", crc32_vec6) ||
      NULL == CU_add_test(crc32_pSuite, "Vector 7", crc32_vec7) )
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(md5_pSuite, "Vector 1", md5_vec1) ||
      NULL == CU_add_test(md5_pSuite, "Vector 2", md5_vec2) ||
      NULL == CU_add_test(md5_pSuite, "Vector 3", md5_vec3) ||
      NULL == CU_add_test(md5_pSuite, "Vector 4", md5_vec4) ||
      NULL == CU_add_test(md5_pSuite, "Vector 5", md5_vec5) ||
      NULL == CU_add_test(md5_pSuite, "Vector 6", md5_vec6) ||
      NULL == CU_add_test(md5_pSuite, "Vector 7", md5_vec7) )
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(sha1_pSuite, "Vector 1", sha1_vec1) || 
      NULL == CU_add_test(sha1_pSuite, "Vector 2", sha1_vec2) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 3", sha1_vec3) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 4", sha1_vec4) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 5", sha1_vec5) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 6", sha1_vec6) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 7", sha1_vec7) ||
      NULL == CU_add_test(sha1_pSuite, "Vector 8", sha1_vec8) )
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (NULL == CU_add_test(sha256_pSuite, "Vector 1", sha256_vec1) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 2", sha256_vec2) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 3", sha256_vec3) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 4", sha256_vec4) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 5", sha256_vec5) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 6", sha256_vec6) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 7", sha256_vec7) ||
      NULL == CU_add_test(sha256_pSuite, "Vector 8", sha256_vec8) )
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