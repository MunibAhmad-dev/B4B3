/*
  Solution 01 — AES-256-CBC File Encryption/Decryption (complete)
*/
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

std::vector<BYTE> aesEncrypt(const std::vector<BYTE>& plaintext,
                              const BYTE key[32], const BYTE iv[16]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);

    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    ULONG cipherLen = 0;
    BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                  nullptr, ivCopy, 16, nullptr, 0, &cipherLen, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> cipher(cipherLen);
    memcpy(ivCopy, iv, 16);
    BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                  nullptr, ivCopy, 16, cipher.data(), cipherLen, &cipherLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return cipher;
}

std::vector<BYTE> aesDecrypt(const std::vector<BYTE>& ciphertext,
                              const BYTE key[32], const BYTE iv[16]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);

    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    ULONG plainLen = 0;
    BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                  nullptr, ivCopy, 16, nullptr, 0, &plainLen, BCRYPT_BLOCK_PADDING);

    std::vector<BYTE> plain(plainLen);
    memcpy(ivCopy, iv, 16);
    BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                  nullptr, ivCopy, 16, plain.data(), plainLen, &plainLen, BCRYPT_BLOCK_PADDING);
    plain.resize(plainLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return plain;
}

bool encryptFile(const std::string& src, const std::string& dst,
                 const BYTE key[32], const BYTE iv[16]) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    in.close();

    auto cipher = aesEncrypt(data, key, iv);

    std::ofstream out(dst, std::ios::binary);
    if (!out) return false;
    out.write((char*)iv, 16);          // prepend IV
    out.write((char*)cipher.data(), cipher.size());
    return true;
}

bool decryptFile(const std::string& src, const std::string& dst,
                 const BYTE key[32]) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    BYTE iv[16] = {};
    in.read((char*)iv, 16);
    std::vector<BYTE> cipher((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    in.close();

    auto plain = aesDecrypt(cipher, key, iv);

    std::ofstream out(dst, std::ios::binary);
    if (!out) return false;
    out.write((char*)plain.data(), plain.size());
    return true;
}

// SHA-256 via CNG for verification
std::string sha256File(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::vector<BYTE> data((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hHash, data.data(), (ULONG)data.size(), 0);

    BYTE digest[32] = {};
    BCryptFinishHash(hHash, digest, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream ss;
    for (int i = 0; i < 32; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return ss.str();
}

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

    // Create test file
    { std::ofstream t("test.txt"); t << "Hello from AES-256-CBC encryption test!\nLine 2.\n"; }

    std::string h1 = sha256File("test.txt");
    std::cout << "SHA-256(test.txt):     " << h1 << "\n";

    if (!encryptFile("test.txt", "test.txt.enc", key, iv)) {
        std::cerr << "Encryption failed\n"; return 1;
    }
    std::cout << "Encrypted → test.txt.enc\n";

    if (!decryptFile("test.txt.enc", "test.txt.dec", key)) {
        std::cerr << "Decryption failed\n"; return 1;
    }

    std::string h2 = sha256File("test.txt.dec");
    std::cout << "SHA-256(test.txt.dec): " << h2 << "\n";

    if (h1 == h2) std::cout << "\n[OK] Hashes match — round-trip successful!\n";
    else          std::cerr << "\n[FAIL] Hash mismatch!\n";

    DeleteFileA("test.txt.enc");
    DeleteFileA("test.txt.dec");
    DeleteFileA("test.txt");
    return (h1 == h2) ? 0 : 1;
}
