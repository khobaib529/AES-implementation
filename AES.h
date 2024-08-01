/*
 * AES Implementation
 *
 * This code implements the Advanced Encryption Standard (AES) algorithm for
 * different key sizes (128-bit, 192-bit, and 256-bit). It includes both
 * encryption and decryption functionalities.
 *
 * Testing:
 * This implementation has been tested using NIST (National Institute of
 * Standards and Technology) AES test vectors to ensure correctness and
 * compliance with the AES standard.
 */

#ifndef AES_H_
#define AES_H_

#include <cstring>

// AES S-Box for byte substitution in encryption and decryption
const unsigned char S_BOX[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
     0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
     0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
     0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
     0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
     0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
     0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
     0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
     0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
     0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
     0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
     0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
     0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
     0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
     0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
     0xb0, 0x54, 0xbb, 0x16}};

// AES Inverse S-Box for byte substitution in decryption
const unsigned char INV_S_BOX[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
     0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
     0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
     0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
     0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
     0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57,
     0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
     0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03,
     0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
     0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
     0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e,
     0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
     0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
     0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
     0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c,
     0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
     0x55, 0x21, 0x0c, 0x7d}};

const unsigned char ROUND_CONSTANT[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                          0x20, 0x40, 0x80, 0x1B, 0x36};

const unsigned char CONSTANT_MATRIX[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                             {0x01, 0x02, 0x03, 0x01},
                                             {0x01, 0x01, 0x02, 0x03},
                                             {0x03, 0x01, 0x01, 0x02}};

const unsigned char INVERSE_CONSTANT_MATRIX[4][4] = {{0x0E, 0x0B, 0x0D, 0x09},
                                                     {0x09, 0x0E, 0x0B, 0x0D},
                                                     {0x0D, 0x09, 0x0E, 0x0B},
                                                     {0x0B, 0x0D, 0x09, 0x0E}};

// AES Base class defining the core operations for AES encryption and decryption
class AESBase {
 public:
  virtual void encrypt(const unsigned char plain_text[4][4],
                       unsigned char cipher_text[4][4]) = 0;
  virtual void decrypt(const unsigned char cipher_text[4][4],
                       unsigned char plain_text[4][4]) = 0;
  void xor_words(const unsigned char word1[4], const unsigned char word2[4],
                 unsigned char result[4]) {
    for (int i = 0; i < 4; i++) {
      result[i] = word1[i] ^ word2[i];
    }
  }

  void xor_blocks(const unsigned char block1[4][4],
                  const unsigned char block2[4][4],
                  unsigned char result[4][4]) {
    for (int word = 0; word < 4; word++) {
      xor_words(block1[word], block2[word], result[word]);
    }
  }

  void substitute_bytes_for_block(unsigned char block[4][4]) {
    for (int word = 0; word < 4; word++) {
      substitute_bytes_for_word(block[word]);
    }
  }

  void inverse_substitute_bytes_for_block(unsigned char block[4][4]) {
    for (int word = 0; word < 4; word++) {
      inverse_substitute_bytes_for_word(block[word]);
    }
  }

  void substitute_bytes_for_word(unsigned char word[4]) {
    for (int i = 0; i < 4; i++) {
      int column = word[i] % 16;
      int row = word[i] / 16;
      word[i] = S_BOX[row][column];
    }
  }

  void inverse_substitute_bytes_for_word(unsigned char word[4]) {
    for (int i = 0; i < 4; i++) {
      int column = word[i] % 16;
      int row = word[i] / 16;
      word[i] = INV_S_BOX[row][column];
    }
  }

  void shift_rows(unsigned char block[4][4]) {
    unsigned char temp_word[4][4];
    for (int col = 0; col < 4; col++) {
      int k = 0;
      for (int row = col; row < 4; row++) {
        temp_word[k++][col] = block[row][col];
      }
      for (int row = 0; row < col; row++) {
        temp_word[k++][col] = block[row][col];
      }
    }
    memcpy(block, temp_word, 16);
  }

  void inverse_shift_rows(unsigned char block[4][4]) {
    unsigned char new_block[4][4];
    for (int col = 0; col < 4; col++) {
      int k = 0;
      for (int row = 4 - col; row < 4; row++) {
        new_block[k][col] = block[row][col];
        k++;
      }
      for (int row = 0; row < 4 - col; row++) {
        new_block[k][col] = block[row][col];
        k++;
      }
    }
    memcpy(block, new_block, 16);
  }

  unsigned char multiply_using_gf(unsigned char a, unsigned char b) {
    unsigned char product = 0;
    while (b) {
      if (b & 1) product ^= a;
      unsigned char hi_bit_set = a & 0x80;
      a <<= 1;
      if (hi_bit_set)
        a ^= 0x1B;  // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x +
                    // 1
      b >>= 1;
    }
    return product;
  }

  void mix_column(unsigned char block[4][4]) {
    unsigned char new_word[4];
    for (int word = 0; word < 4; word++) {
      for (int byte = 0; byte < 4; byte++) {
        unsigned char result = 0;
        for (int i = 0; i < 4; i++) {
          result ^= multiply_using_gf(block[word][i], CONSTANT_MATRIX[byte][i]);
        }
        new_word[byte] = result;
      }
      memcpy(block[word], new_word, 4);
    }
  }

  void inverse_mix_column(unsigned char block[4][4]) {
    unsigned char new_word[4];
    for (int word = 0; word < 4; word++) {
      for (int byte = 0; byte < 4; byte++) {
        unsigned char result = 0;
        for (int i = 0; i < 4; i++) {
          result ^= multiply_using_gf(block[word][i],
                                      INVERSE_CONSTANT_MATRIX[byte][i]);
        }
        new_word[byte] = result;
      }
      memcpy(block[word], new_word, 4);
    }
  }

  void g(const unsigned char word[4], int round, unsigned char result[4]) {
    const unsigned char first_byte = word[0];
    for (int i = 1; i < 4; i++) {
      result[i - 1] = word[i];
    }
    result[3] = first_byte;

    substitute_bytes_for_word(result);

    result[0] ^= ROUND_CONSTANT[round - 1];
  }

  virtual ~AESBase() = default;
};

// AES implementation for 128-bit keys
class AES128 : public AESBase {
 private:
  void gen_key_schedule_128() {
    for (int round = 1; round <= 10; round++) {
      for (int word = 0; word < 4; word++) {
        if (word == 0) {
          unsigned char g_of_last_word[4];
          g(m_round_keys[round - 1][3], round, g_of_last_word);
          xor_words(g_of_last_word, m_round_keys[round - 1][0],
                    m_round_keys[round][word]);
        } else {
          xor_words(m_round_keys[round - 1][word],
                    m_round_keys[round][word - 1], m_round_keys[round][word]);
        }
      }
    }
  }

 public:
  AES128(const unsigned char key[4][4]) {
    memcpy(m_round_keys[0], key, 16);
    gen_key_schedule_128();
  }

  void encrypt(const unsigned char plain_text[4][4],
               unsigned char cipher_text[4][4]) override {
    xor_blocks(plain_text, m_round_keys[0], cipher_text);

    for (int round = 1; round <= 9; round++) {
      substitute_bytes_for_block(cipher_text);
      shift_rows(cipher_text);
      mix_column(cipher_text);
      xor_blocks(cipher_text, m_round_keys[round], cipher_text);
    }

    substitute_bytes_for_block(cipher_text);
    shift_rows(cipher_text);
    xor_blocks(cipher_text, m_round_keys[10], cipher_text);
  }

  void decrypt(const unsigned char cipher_text[4][4],
               unsigned char plain_text[4][4]) override {
    xor_blocks(cipher_text, m_round_keys[10], plain_text);
    inverse_substitute_bytes_for_block(plain_text);
    inverse_shift_rows(plain_text);

    for (int round = 9; round >= 1; round--) {
      xor_blocks(plain_text, m_round_keys[round], plain_text);
      inverse_mix_column(plain_text);
      inverse_substitute_bytes_for_block(plain_text);
      inverse_shift_rows(plain_text);
    }
    xor_blocks(plain_text, m_round_keys[0], plain_text);
  }

 public:
  unsigned char m_round_keys[11][4][4];
};

// AES implementation for 192-bit keys
class AES192 : public AESBase {
 private:
  void gen_key_schedule_192() {
    int round = 1;
    for (int word = 6; word < 52; word++) {
      if (word % 6 == 0) {
        g(*(*m_round_keys + word - 1), round, *(*m_round_keys + word));
        xor_words(*(*m_round_keys + word), *(*m_round_keys + word - 6),
                  *(*m_round_keys + word));
        round++;
      } else {
        xor_words(*(*m_round_keys + word - 1), *(*m_round_keys + word - 6),
                  *(*m_round_keys + word));
      }
    }
  }

 public:
  AES192(const unsigned char key[6][4]) {
    memcpy(m_round_keys[0], key, 24);
    gen_key_schedule_192();
  }

  void encrypt(const unsigned char plain_text[4][4],
               unsigned char cipher_text[4][4]) override {
    xor_blocks(m_round_keys[0], plain_text, cipher_text);
    for (int round = 1; round < 12; round++) {
      substitute_bytes_for_block(cipher_text);
      shift_rows(cipher_text);
      mix_column(cipher_text);
      xor_blocks(m_round_keys[round], cipher_text, cipher_text);
    }
    substitute_bytes_for_block(cipher_text);
    shift_rows(cipher_text);
    xor_blocks(cipher_text, m_round_keys[12], cipher_text);
  }

  void decrypt(const unsigned char cipher_text[4][4],
               unsigned char plain_text[4][4]) override {
    xor_blocks(cipher_text, m_round_keys[12], plain_text);
    inverse_substitute_bytes_for_block(plain_text);
    inverse_shift_rows(plain_text);
    for (int round = 11; round >= 1; round--) {
      xor_blocks(plain_text, m_round_keys[round], plain_text);
      inverse_mix_column(plain_text);
      inverse_substitute_bytes_for_block(plain_text);
      inverse_shift_rows(plain_text);
    }
    xor_blocks(plain_text, m_round_keys[0], plain_text);
  }

 private:
  unsigned char m_round_keys[13][4][4];
};

// AES implementation for 256-bit keys
class AES256 : public AESBase {
 private:
  void gen_key_schedule_256() {
    bool flag = true;
    int round = 1;
    for (int block = 2; block < 15; block++) {
      for (int word = 0; word < 4; word++) {
        if (word == 0) {
          if (flag == true) {
            unsigned char g_of_last_word[4];
            g(m_round_keys[block - 1][3], round, g_of_last_word);
            xor_words(g_of_last_word, m_round_keys[block - 2][0],
                      m_round_keys[block][word]);
            flag = false;
            round++;
          } else {
            memcpy(m_round_keys[block][word], m_round_keys[block - 1][3], 4);
            substitute_bytes_for_word(m_round_keys[block][word]);
            xor_words(m_round_keys[block][word], m_round_keys[block - 2][0],
                      m_round_keys[block][word]);
            flag = true;
          }
        } else {
          xor_words(m_round_keys[block - 2][word],
                    m_round_keys[block][word - 1], m_round_keys[block][word]);
        }
      }
    }
  }

 public:
  AES256(const unsigned char key[8][4]) {
    memcpy(m_round_keys[0], key, 32);
    gen_key_schedule_256();
  }

  void encrypt(const unsigned char plain_text[4][4],
               unsigned char cipher_text[4][4]) override {
    xor_blocks(plain_text, m_round_keys[0], cipher_text);

    for (int round = 1; round <= 13; round++) {
      substitute_bytes_for_block(cipher_text);
      shift_rows(cipher_text);
      mix_column(cipher_text);
      xor_blocks(cipher_text, m_round_keys[round], cipher_text);
    }

    substitute_bytes_for_block(cipher_text);
    shift_rows(cipher_text);
    xor_blocks(cipher_text, m_round_keys[14], cipher_text);
  }

  void decrypt(const unsigned char cipher_text[4][4],
               unsigned char plain_text[4][4]) override {
    xor_blocks(cipher_text, m_round_keys[14], plain_text);
    inverse_substitute_bytes_for_block(plain_text);
    inverse_shift_rows(plain_text);

    for (int round = 13; round >= 1; round--) {
      xor_blocks(plain_text, m_round_keys[round], plain_text);
      inverse_mix_column(plain_text);
      inverse_substitute_bytes_for_block(plain_text);
      inverse_shift_rows(plain_text);
    }
    xor_blocks(plain_text, m_round_keys[0], plain_text);
  }

 public:
  unsigned char m_round_keys[15][4][4];
};

#endif
