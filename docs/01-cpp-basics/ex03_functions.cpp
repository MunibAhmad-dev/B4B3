/*
  Exercise 03 — Functions
  ------------------------
  Tasks:
  1. Write a function: int xorEncrypt(int value, int key)
     Returns value XOR'd with key.
     Call it with value=0x41, key=0xFF and print the result in hex.
     Call xorEncrypt again on the result with the same key — you should get 0x41 back.
     This demonstrates that XOR encryption is its own inverse.

  2. Write a function: void xorBuffer(char* buf, int len, char key)
     XOR-encrypts every byte in buf with key (modifies buf in-place via pointer).
     In main: create char buf[] = "Hello", call xorBuffer(buf, 5, 0x5A),
     print the encrypted bytes as hex, then call xorBuffer again to decrypt,
     print the decrypted string.

  3. Write a function: bool isPowerOfTwo(unsigned int n)
     Returns true if n is a power of two (1, 2, 4, 8, 16, ...).
     Hint: use the bit trick (n & (n-1)) == 0.
     Test with: 0, 1, 2, 3, 4, 7, 8, 255, 256.

  4. Write a function: int countBitsSet(unsigned int n)
     Returns the number of 1-bits in n.
     (This is called a "popcount".)
     Test with: 0, 1, 7, 255, 0xDEADBEEF.

  Compile: g++ -std=c++17 -Wall -o ex03.exe ex03_functions.cpp
*/

#include <iostream>
#include <iomanip>   // std::hex, std::setw, std::setfill

// YOUR FUNCTION DECLARATIONS AND DEFINITIONS HERE

int main() {
    // Task 1
    // YOUR CODE HERE

    // Task 2
    // YOUR CODE HERE

    // Task 3
    // YOUR CODE HERE

    // Task 4
    // YOUR CODE HERE

    return 0;
}
