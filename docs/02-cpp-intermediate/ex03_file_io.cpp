/*
  Exercise 03 — File I/O
  -----------------------
  Build a simple keystroke logger that writes to a file and reads it back.

  Tasks:
  1. Write a function: void logKey(const string& logPath, char key)
     Opens logPath in append mode, writes the character,
     writes a newline every 20 characters (track count with a static variable).

  2. Simulate 60 keystrokes (use a loop, alternate between 'A'-'Z' and '0'-'9').
     Call logKey() for each. The file should be named "keylog.txt".

  3. Write a function: string readLog(const string& logPath)
     Reads the entire file and returns its contents as a string.
     Print the contents.

  4. Write a function: vector<string> readLines(const string& logPath)
     Returns the file contents as a vector of lines.
     Print how many lines are in the log.

  5. Binary file: write the 4-byte magic number { 0xB4, 0x4B, 0xD4, 0x3E }
     to a file "magic.bin", then read it back and verify each byte.

  Compile: g++ -std=c++17 -Wall -o ex03.exe ex03_file_io.cpp
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// YOUR CODE HERE

int main() {
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
