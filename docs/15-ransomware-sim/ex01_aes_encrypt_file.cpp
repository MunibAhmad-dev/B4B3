/*
  Exercise 01 — AES-256-CBC File Encryption/Decryption
  -------------------------------------------------------
  Build the core encryption primitive used in ransomware and other secure tools.

  Tasks:
  1. Write: std::vector<BYTE> aesEncrypt(data, key[32], iv[16])
     Uses Windows CNG (BCryptEncrypt) with AES-256-CBC + PKCS7 padding.

  2. Write: std::vector<BYTE> aesDecrypt(ciphertext, key[32], iv[16])
     Inverse of aesEncrypt.

  3. Write: bool encryptFile(const std::string& srcPath, const std::string& dstPath,
                              const BYTE key[32], const BYTE iv[16])
     - Reads srcPath into memory
     - Encrypts with aesEncrypt
     - Writes to dstPath with a 16-byte IV prepended
       (IV stored in file so decryption is self-contained)

  4. Write: bool decryptFile(const std::string& srcPath, const std::string& dstPath,
                              const BYTE key[32])
     - Reads first 16 bytes as IV
     - Decrypts the rest with aesDecrypt using stored IV
     - Writes plaintext to dstPath

  5. In main():
     - Generate a random 32-byte key with BCryptGenRandom
     - Generate a random 16-byte IV
     - Print key and IV as hex
     - Encrypt "test.txt" → "test.txt.enc"
     - Decrypt "test.txt.enc" → "test.txt.dec"
     - Verify: SHA-256(test.txt) == SHA-256(test.txt.dec)
     - Delete test.txt.enc and test.txt.dec

  Create "test.txt" beforehand with some content.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_aes_encrypt_file.cpp -lbcrypt -lkernel32
*/

#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

// YOUR CODE HERE

int main() {
    // Generate key + IV
    BYTE key[32] = {}, iv[16] = {};
    BCRYPT_ALG_HANDLE hRng;
    BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    BCryptGenRandom(hRng, key, 32, 0);
    BCryptGenRandom(hRng, iv, 16, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);

    std::cout << "Key: ";
    for (int i = 0; i < 32; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    std::cout << "\nIV:  ";
    for (int i = 0; i < 16; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
    std::cout << "\n\n";

    // YOUR CODE HERE

    return 0;
}
