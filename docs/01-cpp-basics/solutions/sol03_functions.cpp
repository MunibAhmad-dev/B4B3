// Solution 03 — Functions

#include <iostream>
#include <iomanip>

int xorEncrypt(int value, int key) {
    return value ^ key;
}

void xorBuffer(char* buf, int len, char key) {
    for (int i = 0; i < len; i++)
        buf[i] ^= key;
}

bool isPowerOfTwo(unsigned int n) {
    if (n == 0) return false;
    return (n & (n - 1)) == 0;
    // Explanation: a power of two in binary has exactly one 1-bit.
    // n-1 flips that bit and sets all lower bits.
    // n & (n-1) therefore == 0 only when n has exactly one 1-bit.
}

int countBitsSet(unsigned int n) {
    int count = 0;
    while (n) {
        count += n & 1;  // add lowest bit (0 or 1)
        n >>= 1;         // shift right, discard lowest bit
    }
    return count;
    // Alternative one-liner: return __builtin_popcount(n);
}

int main() {
    // Task 1
    int enc = xorEncrypt(0x41, 0xFF);
    std::cout << "encrypted: 0x" << std::hex << enc << "\n";
    int dec = xorEncrypt(enc, 0xFF);
    std::cout << "decrypted: 0x" << std::hex << dec << "\n\n";

    // Task 2
    char buf[] = "Hello";
    std::cout << "original:  Hello\nencrypted: ";
    xorBuffer(buf, 5, 0x5A);
    for (int i = 0; i < 5; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buf[i] << " ";
    std::cout << "\n";
    xorBuffer(buf, 5, 0x5A);
    std::cout << "decrypted: " << buf << "\n\n";

    // Task 3
    unsigned int tests[] = {0, 1, 2, 3, 4, 7, 8, 255, 256};
    for (auto n : tests)
        std::cout << std::dec << n << " isPowerOfTwo: " << (isPowerOfTwo(n) ? "yes" : "no") << "\n";
    std::cout << "\n";

    // Task 4
    unsigned int tests2[] = {0, 1, 7, 255, 0xDEADBEEF};
    for (auto n : tests2)
        std::cout << "0x" << std::hex << n << " bits set: " << std::dec << countBitsSet(n) << "\n";

    return 0;
}
