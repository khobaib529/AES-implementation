// AES encryption and decryption tests

#include <assert.h>
#include <algorithm>
#include <iostream>

#include "AES.h"

void ASSERT_EQ(unsigned char cipher_text[4][4],
               unsigned char expected_cipher_text[4][4]) {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      assert(cipher_text[row][col] == expected_cipher_text[row][col]);
    }
  }
}

void test_aes_128_encryption() {
  std::cout << "Testing AES128 encryption" << std::endl;
  unsigned char key[4][4] = {{0x2B, 0x7E, 0x15, 0x16},
                             {0x28, 0xAE, 0xD2, 0xA6},
                             {0xAB, 0xF7, 0x15, 0x88},
                             {0x09, 0xCF, 0x4F, 0x3C}};
  unsigned char plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                    {0x2E, 0x40, 0x9F, 0x96},
                                    {0xE9, 0x3D, 0x7E, 0x11},
                                    {0x73, 0x93, 0x17, 0x2A}};
  unsigned char cipher_text[4][4];
  unsigned char expected_cipher_text[4][4] = {{0x3A, 0xD7, 0x7B, 0xB4},
                                              {0x0D, 0x7A, 0x36, 0x60},
                                              {0xA8, 0x9E, 0xCA, 0xF3},
                                              {0x24, 0x66, 0xEF, 0x97}};
  AES128 aes128(key);
  aes128.encrypt(plain_text, cipher_text);
  ASSERT_EQ(cipher_text, expected_cipher_text);
  std::cout << "Test cases passed for AES128 encryption." << std::endl;
}

void test_aes_128_decryption() {
  std::cout << "Testing AES128 decryption." << std::endl;
  unsigned char key[4][4] = {{0x2B, 0x7E, 0x15, 0x16},
                             {0x28, 0xAE, 0xD2, 0xA6},
                             {0xAB, 0xF7, 0x15, 0x88},
                             {0x09, 0xCF, 0x4F, 0x3C}};
  unsigned char cipher_text[4][4] = {{0x3A, 0xD7, 0x7B, 0xB4},
                                     {0x0D, 0x7A, 0x36, 0x60},
                                     {0xA8, 0x9E, 0xCA, 0xF3},
                                     {0x24, 0x66, 0xEF, 0x97}};
  unsigned char expected_plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                             {0x2E, 0x40, 0x9F, 0x96},
                                             {0xE9, 0x3D, 0x7E, 0x11},
                                             {0x73, 0x93, 0x17, 0x2A}};
  unsigned char plain_text[4][4];
  AES128 aes128(key);
  aes128.decrypt(cipher_text, plain_text);
  ASSERT_EQ(plain_text, expected_plain_text);
  std::cout << "Test cases passed for AES128 decryption." << std::endl;
}

void test_aes_192_encrypion() {
  std::cout << "Testing AES192 encryption." << std::endl;
  unsigned char key[6][4] = {
      {0x8E, 0x73, 0xB0, 0xF7}, {0xDA, 0x0E, 0x64, 0x52},
      {0xC8, 0x10, 0xF3, 0x2B}, {0x80, 0x90, 0x79, 0xE5},
      {0x62, 0xF8, 0xEA, 0xD2}, {0x52, 0x2C, 0x6B, 0x7B}};
  unsigned char plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                    {0x2E, 0x40, 0x9F, 0x96},
                                    {0xE9, 0x3D, 0x7E, 0x11},
                                    {0x73, 0x93, 0x17, 0x2A}};
  unsigned char expected_cipher_text[4][4] = {{0xBD, 0x33, 0x4F, 0x1D},
                                              {0x6E, 0x45, 0xF2, 0x5F},
                                              {0xF7, 0x12, 0xA2, 0x14},
                                              {0x57, 0x1F, 0xA5, 0xCC}};
  unsigned char cipher_text[4][4];
  AES192 aes192(key);
  aes192.encrypt(plain_text, cipher_text);
  ASSERT_EQ(cipher_text, expected_cipher_text);
  std::cout << "Test cases passed for AES192 encryption." << std::endl;
}

void test_aes_192_decrypion() {
  std::cout << "Testing AES192 decryption." << std::endl;
  unsigned char key[6][4] = {
      {0x8E, 0x73, 0xB0, 0xF7}, {0xDA, 0x0E, 0x64, 0x52},
      {0xC8, 0x10, 0xF3, 0x2B}, {0x80, 0x90, 0x79, 0xE5},
      {0x62, 0xF8, 0xEA, 0xD2}, {0x52, 0x2C, 0x6B, 0x7B}};
  unsigned char cipher_text[4][4] = {{0xBD, 0x33, 0x4F, 0x1D},
                                     {0x6E, 0x45, 0xF2, 0x5F},
                                     {0xF7, 0x12, 0xA2, 0x14},
                                     {0x57, 0x1F, 0xA5, 0xCC}};
  unsigned char expected_plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                             {0x2E, 0x40, 0x9F, 0x96},
                                             {0xE9, 0x3D, 0x7E, 0x11},
                                             {0x73, 0x93, 0x17, 0x2A}};
  unsigned char plain_text[4][4];
  AES192 aes192(key);
  aes192.decrypt(cipher_text, plain_text);
  ASSERT_EQ(plain_text, expected_plain_text);
  std::cout << "Test cases passed for AES192 decryption." << std::endl;
}

void test_aes_256_encryption() {
  std::cout << "Testing AES256 encryption" << std::endl;
  unsigned char key[8][4] = {
      {0x60, 0x3D, 0xEB, 0x10}, {0x15, 0xCA, 0x71, 0xBE},
      {0x2B, 0x73, 0xAE, 0xF0}, {0x85, 0x7D, 0x77, 0x81},
      {0x1F, 0x35, 0x2C, 0x07}, {0x3B, 0x61, 0x08, 0xD7},
      {0x2D, 0x98, 0x10, 0xA3}, {0x09, 0x14, 0xDF, 0xF4}};
  unsigned char plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                    {0x2E, 0x40, 0x9F, 0x96},
                                    {0xE9, 0x3D, 0x7E, 0x11},
                                    {0x73, 0x93, 0x17, 0x2A}};
  unsigned char expected_cipher_text[4][4] = {{0xF3, 0xEE, 0xD1, 0xBD},
                                              {0xB5, 0xD2, 0xA0, 0x3C},
                                              {0x06, 0x4B, 0x5A, 0x7E},
                                              {0x3D, 0xB1, 0x81, 0xF8}};
  unsigned char cipher_text[4][4];
  AES256 aes256(key);
  aes256.encrypt(plain_text, cipher_text);
  ASSERT_EQ(cipher_text, expected_cipher_text);
  std::cout << "Test cases passed for AES256 encryption." << std::endl;
}

void test_aes_256_decryption() {
  std::cout << "Testing AES256 decryption" << std::endl;
  unsigned char key[8][4] = {
      {0x60, 0x3D, 0xEB, 0x10}, {0x15, 0xCA, 0x71, 0xBE},
      {0x2B, 0x73, 0xAE, 0xF0}, {0x85, 0x7D, 0x77, 0x81},
      {0x1F, 0x35, 0x2C, 0x07}, {0x3B, 0x61, 0x08, 0xD7},
      {0x2D, 0x98, 0x10, 0xA3}, {0x09, 0x14, 0xDF, 0xF4}};
  unsigned char cipher_text[4][4] = {{0xF3, 0xEE, 0xD1, 0xBD},
                                     {0xB5, 0xD2, 0xA0, 0x3C},
                                     {0x06, 0x4B, 0x5A, 0x7E},
                                     {0x3D, 0xB1, 0x81, 0xF8}};
  unsigned char expected_plain_text[4][4] = {{0x6B, 0xC1, 0xBE, 0xE2},
                                             {0x2E, 0x40, 0x9F, 0x96},
                                             {0xE9, 0x3D, 0x7E, 0x11},
                                             {0x73, 0x93, 0x17, 0x2A}};
  unsigned char plain_text[4][4];
  AES256 aes256(key);
  aes256.decrypt(cipher_text, plain_text);
  ASSERT_EQ(plain_text, expected_plain_text);
  std::cout << "Test cases passed for AES256 decryption." << std::endl;
}

int main() {
  test_aes_128_encryption();
  test_aes_128_decryption();
  test_aes_192_encrypion();
  test_aes_192_decrypion();
  test_aes_256_encryption();
  test_aes_256_decryption();
  return 0;
}
