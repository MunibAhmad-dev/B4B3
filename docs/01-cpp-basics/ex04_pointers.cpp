/*
  Exercise 04 — Pointers
  -----------------------
  Tasks:
  1. Declare int x = 100.
     Declare int* p pointing to x.
     Through the pointer, change x to 999.
     Print both x and *p — they should both show 999.
     Print the memory address stored in p using std::cout << p.

  2. Declare int arr[5] = {10, 20, 30, 40, 50}.
     Using ONLY pointer arithmetic (no arr[i] indexing), print all 5 values.
     Then write a loop that sums all values using a pointer walking the array.

  3. Write a function: void swap(int* a, int* b)
     Swaps the values at addresses a and b WITHOUT a temporary variable.
     Hint: use XOR swap: *a ^= *b; *b ^= *a; *a ^= *b;
     Call it with two integers and verify they are swapped.

  4. Heap allocation:
     - Allocate an array of 8 ints on the heap with new.
     - Fill them with values 0..7 multiplied by 0x10 (so 0, 16, 32, ...).
     - Print all 8 values.
     - Free the memory with delete[].
     - Set the pointer to nullptr immediately after.

  5. (Pointer to pointer)
     Declare int x = 7.
     Declare int* p = &x.
     Declare int** pp = &p.
     Change x's value to 42 using ONLY pp (two dereferences).
     Print x. It should print 42.

  Compile: g++ -std=c++17 -Wall -o ex04.exe ex04_pointers.cpp
*/

#include <iostream>

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

    // Task 5
    // YOUR CODE HERE

    return 0;
}
