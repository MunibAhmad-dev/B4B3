/*
  Exercise 02 — Compile-time String Obfuscation
  -----------------------------------------------
  This exercise teaches you exactly how the S() macro in Protector.cpp works.

  Tasks:
  1. Write a constexpr function: constexpr char xorChar(char c, char key)
     Returns c XOR'd with key.

  2. Write a constexpr struct ObfStr<N> that:
       - Takes a string literal in its constexpr constructor
       - Stores each char XOR'd with key 0x5A at compile time
       - Has a decode() method that returns the decrypted std::string at runtime

  3. Declare five obfuscated strings using ObfStr:
       "cmd.exe"
       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
       "hal9th"
       "explorer.exe"
       "powershell.exe"
     Decode and print each one.

  4. After compiling, use a strings utility or grep to verify NONE of the
     plaintext strings appear in the binary:
       strings ex02.exe | grep -i "cmd"
       strings ex02.exe | grep -i "run"
     They should NOT appear. The only thing in the binary should be XOR'd bytes.

  5. (Harder) Modify ObfStr to use a key derived from the XOR of all bytes
     of the string itself. This makes each string use a different key, making
     pattern matching harder.

  Compile: g++ -std=c++17 -Wall -O2 -o ex02.exe ex02_constexpr_obfuscation.cpp
  (Need -O2 or -O1 for constexpr to be evaluated fully at compile time)
*/

#include <iostream>
#include <string>

// YOUR CODE HERE

int main() {
    // Task 3
    // YOUR CODE HERE

    return 0;
}
