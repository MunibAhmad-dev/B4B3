/*
  Exercise 01 — Templates
  ------------------------
  Tasks:
  1. Write a template function: T clamp(T val, T lo, T hi)
     Returns val clamped to the range [lo, hi].
     Test with int, double, char.

  2. Write a template function: void xorCrypt(T* data, size_t count, T key)
     XOR-encrypts an array of any type in-place.
     Test with: char array ("Hello"), int array {1,2,3,4}, unsigned char array.

  3. Write a template class RingBuffer<T, N> where N is the capacity (non-type
     template parameter).
       - push(T val) — adds to the ring, overwrites oldest if full
       - T pop()     — removes and returns oldest value
       - bool empty()
       - size_t size()
     Test: RingBuffer<char, 8> used as a keystroke accumulator — push 10 chars,
     pop and print all available.

  4. Write a template function: string toHex(T val)
     Returns the hex representation of any integer type as a string, e.g.
     toHex((uint32_t)0xDEADBEEF) → "DEADBEEF"
     toHex((uint8_t)0x41) → "41"

  Compile: g++ -std=c++17 -Wall -o ex01.exe ex01_templates.cpp
*/

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// YOUR CODE HERE

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
