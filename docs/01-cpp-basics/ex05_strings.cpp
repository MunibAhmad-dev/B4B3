/*
  Exercise 05 — Strings
  ----------------------
  Tasks:
  1. C-string operations:
     Declare: char buf[64] = "OneDriveHelper"
     Print its length using strlen().
     Copy it to a second char array using strncpy() — use the safe version with size limit.
     Append ".exe" using strncat().
     Print the final string.

  2. std::string operations:
     Declare: std::string s = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
     Print s.length().
     Find the position of "Run" using s.find().
     Extract just "Run" using s.substr().
     Replace "HKEY_CURRENT_USER" with "HKCU" using s.replace() or s.find()+s.substr().
     Print the modified string.

  3. String ↔ number conversions:
     Convert int 4444 to std::string using std::to_string().
     Prepend "Port: " and print.
     Convert std::string "192" to int using std::stoi().
     Multiply by 256 and print.

  4. XOR a std::string:
     Write a function: std::string xorStr(const std::string& s, char key)
     Returns a new string with every character XOR'd with key.
     Call it on "cmd.exe" with key 0x42.
     Print the encrypted bytes as hex.
     Call it again on the result to decrypt and print the original.

  Compile: g++ -std=c++17 -Wall -o ex05.exe ex05_strings.cpp
*/

#include <iostream>
#include <string>
#include <cstring>
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
