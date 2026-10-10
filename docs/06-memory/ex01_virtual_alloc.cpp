/*
  Exercise 01 — VirtualAlloc
  ---------------------------
  Tasks:
  1. Allocate a 4096-byte (PAGE_SIZE) block with PAGE_READWRITE.
     Fill it with the pattern 0xAB repeated.
     Read back and verify: print first 16 bytes as hex.
     Free it.

  2. Allocate a 4096-byte block as PAGE_READWRITE.
     Write the string "Hello from heap page" into it.
     Then call VirtualProtect to change it to PAGE_READONLY.
     Try to write to it — catch the access violation using __try / __except.
     Print whether the write was blocked.

  3. Use VirtualQuery to inspect the allocation you made in task 1 (before
     freeing it). Print:
       - BaseAddress
       - RegionSize
       - State (MEM_COMMIT / MEM_RESERVE / MEM_FREE)
       - Protect flags

  4. Enumerate ALL memory regions in your own process using VirtualQuery in a loop.
     Count: how many committed regions, how many are executable, total committed bytes.
     Print a summary.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_virtual_alloc.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>

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
