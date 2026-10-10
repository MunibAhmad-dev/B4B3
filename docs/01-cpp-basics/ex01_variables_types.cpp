/*
  Exercise 01 — Variables, types, sizeof
  ----------------------------------------
  Tasks:
  1. Declare one variable of each type: int, long long, double, char, bool.
     Assign them any values you like, then print each one with std::cout.

  2. Print the SIZE (in bytes) of each type using sizeof().
     Expected output should be:
       sizeof(int)       = 4
       sizeof(long long) = 8
       sizeof(double)    = 8
       sizeof(char)      = 1
       sizeof(bool)      = 1

  3. Declare an unsigned int and assign it the value 4294967295 (max for uint32).
     Then add 1 to it and print the result. Explain in a comment what happens.

  4. Declare two integers. Use bitwise OR to combine them and print the result.
     Declare a BYTE (use: typedef unsigned char BYTE;) and set bit 3 using |=.
     Then test if bit 3 is set using & and print "bit 3 is set" or "bit 3 is clear".

  Compile: g++ -std=c++17 -Wall -o ex01.exe ex01_variables_types.cpp
*/

#include <iostream>

int main() {
    // --- Task 1: declare and print ---
    // YOUR CODE HERE

    // --- Task 2: sizeof ---
    // YOUR CODE HERE

    // --- Task 3: unsigned overflow ---
    // YOUR CODE HERE

    // --- Task 4: bitwise ---
    // YOUR CODE HERE

    return 0;
}
