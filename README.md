# AES Encryption and Decryption Implementation

## Overview

This repository provides an implementation of the Advanced Encryption Standard (AES) algorithm in C++. The implementation supports AES-128, AES-192, and AES-256 key sizes.

## Classes

### AESBase

- **Purpose**: Defines core AES operations and serves as a base class for AES encryption and decryption implementations.
- **Key Methods**:
  - `encrypt(const unsigned char plain_text[4][4], unsigned char cipher_text[4][4])`: Pure virtual function for encryption.
  - `decrypt(const unsigned char cipher_text[4][4], unsigned char plain_text[4][4])`: Pure virtual function for decryption.
  - Various helper functions for XOR operations, byte substitution, shifting rows, mixing columns, and key scheduling.

### AES128

- **Purpose**: Implements AES encryption and decryption for 128-bit keys.
- **Constructor**: `AES128(const unsigned char key[4][4])`
- **Key Methods**:
  - `encrypt(const unsigned char plain_text[4][4], unsigned char cipher_text[4][4])`: Encrypts 128-bit data.
  - `decrypt(const unsigned char cipher_text[4][4], unsigned char plain_text[4][4])`: Decrypts 128-bit data.

### AES192

- **Purpose**: Implements AES encryption and decryption for 192-bit keys.
- **Constructor**: `AES192(const unsigned char key[6][4])`
- **Key Methods**:
  - `encrypt(const unsigned char plain_text[4][4], unsigned char cipher_text[4][4])`: Encrypts 192-bit data.
  - `decrypt(const unsigned char cipher_text[4][4], unsigned char plain_text[4][4])`: Decrypts 192-bit data.

### AES256

- **Purpose**: Implements AES encryption and decryption for 256-bit keys.
- **Constructor**: `AES256(const unsigned char key[8][4])`
- **Key Methods**:
  - `encrypt(const unsigned char plain_text[4][4], unsigned char cipher_text[4][4])`: Encrypts 256-bit data.
  - `decrypt(const unsigned char cipher_text[4][4], unsigned char plain_text[4][4])`: Decrypts 256-bit data.

### Example Usage

Here is an example of how to use the `AES128` class for encryption and decryption:

```cpp
#include <iostream>

#include "AES.h"

int main() {
    std::cout << "Testing AES128 encryption" << std::endl;
    
    // Key and plaintext for AES-128 encryption
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

    // Initialize AES-128 encryption with the provided key
    AES128 aes128(key);

    // Encrypt the plaintext
    aes128.encrypt(plain_text, cipher_text);

    // Output the ciphertext for verification
    std::cout << "Cipher Text:" << std::endl;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            std::cout << std::hex << (int)cipher_text[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // Check if the resulting ciphertext matches the expected value
    bool match = true;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            if (cipher_text[i][j] != expected_cipher_text[i][j]) {
                match = false;
                break;
            }
        }
    }

    if (match) {
        std::cout << "Encryption successful. The output matches the expected ciphertext." << std::endl;
    } else {
        std::cout << "Encryption failed. The output does not match the expected ciphertext." << std::endl;
    }

    return 0;
}
