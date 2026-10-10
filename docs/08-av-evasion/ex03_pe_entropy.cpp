/*
  Exercise 03 — PE Section Entropy
  ----------------------------------
  AV engines flag PE sections with entropy > 7.0 as potentially packed/encrypted.
  This exercise teaches you to calculate it and understand why it matters.

  Shannon entropy formula:
    H = -sum(p_i * log2(p_i))   for each unique byte value i
    where p_i = count(byte i) / total_bytes

  Maximum entropy = 8.0 (perfectly random data, e.g. encrypted/compressed)
  Normal code/data ~ 5.0-6.5
  Encrypted config/payload ~ 7.5-8.0

  Tasks:
  1. Write: double entropy(const std::vector<uint8_t>& data)
     Calculates Shannon entropy of a byte buffer.

  2. Parse a PE file (argv[1]) — reuse your PE parser from Module 04 ex03.
     For each section: calculate and print its entropy.
     Flag sections with entropy > 7.0 as suspicious.

  3. Hardcode a buffer of 256 bytes:
       a) All zeros                 → entropy = 0.0
       b) 0x00-0xFF repeating       → entropy ≈ 8.0
       c) ASCII text "hello world"  → entropy ≈ 2.8
     Calculate and print entropy for each.

  4. XOR-encrypt a 4096-byte buffer of ASCII letters with key 0x5A.
     Calculate entropy before and after encryption.
     Observe: entropy increases after XOR with a fixed key, but not to 8.0
     because the distribution is still non-uniform.

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_pe_entropy.cpp
  Run:
    ex03.exe Stub.exe
*/

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <string>
#include <cstdint>

// YOUR CODE HERE

int main(int argc, char* argv[]) {
    // Task 3
    // YOUR CODE HERE

    // Task 4
    // YOUR CODE HERE

    // Task 2
    if (argc >= 2) {
        // YOUR CODE HERE
    }
    return 0;
}
