/*
  Exercise 02 — Control flow
  ---------------------------
  Tasks:
  1. Write a for loop that prints numbers 1 to 20.
     On multiples of 3 print "Fizz" instead of the number.
     On multiples of 5 print "Buzz" instead of the number.
     On multiples of both print "FizzBuzz".
     (Classic FizzBuzz — memorise the pattern, it appears in interviews.)

  2. Write a while loop that:
     - Starts with x = 256
     - Each iteration: right-shift x by 1 (x >>= 1)
     - Prints x each iteration
     - Stops when x == 0
     Count how many iterations it took and print it.
     (This teaches you how bits shift — critical for flag parsing.)

  3. Write a switch statement that takes an integer "cmd" (hardcode cmd = 3).
     Cases:
       1 → print "LIST_PROCESSES"
       2 → print "SCREENSHOT"
       3 → print "KEYLOG_START"
       4 → print "SHELL_EXEC"
       default → print "UNKNOWN_COMMAND"
     (This is literally how a RAT command dispatcher works.)

  Compile: g++ -std=c++17 -Wall -o ex02.exe ex02_control_flow.cpp
*/

#include <iostream>

int main() {
    // --- Task 1: FizzBuzz ---
    // YOUR CODE HERE

    // --- Task 2: bit shift loop ---
    // YOUR CODE HERE

    // --- Task 3: command dispatcher ---
    int cmd = 3;
    // YOUR CODE HERE

    return 0;
}
