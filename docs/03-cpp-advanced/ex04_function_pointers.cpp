/*
  Exercise 04 — Function Pointers as a Dispatch Table
  -----------------------------------------------------
  A RAT receives command IDs over the network (e.g. 0x01, 0x02, 0x03).
  A dispatch table maps each command ID to a handler function.
  This is faster than a switch statement and harder to reverse-engineer.

  Tasks:
  1. Define a function pointer type: typedef void (*CmdHandler)(const char* args)

  2. Write 5 handler functions:
       handleListProc(const char* args)    — prints "listing processes"
       handleScreenshot(const char* args)  — prints "taking screenshot"
       handleShell(const char* args)       — prints "running: <args>"
       handleKeylog(const char* args)      — prints "starting keylogger"
       handleUninstall(const char* args)   — prints "uninstalling"

  3. Build a dispatch table:
       CmdHandler table[256] = {};   // 256-entry table, all nullptr
       table[0x01] = handleListProc;
       table[0x02] = handleScreenshot;
       // etc.

  4. Write a function: void dispatch(uint8_t cmdId, const char* args)
     Looks up cmdId in the table. If the entry is non-null, calls it.
     Otherwise prints "unknown command: 0xXX".

  5. Simulate receiving 6 command packets:
       {0x01, ""}, {0x02, ""}, {0x03, "whoami"}, {0x04, ""},
       {0x05, ""}, {0xFF, ""}  ← unknown
     Call dispatch() for each.

  Bonus: rewrite the table using std::array<std::function<void(const char*)>, 256>
  so you can store lambdas too.

  Compile: g++ -std=c++17 -Wall -o ex04.exe ex04_function_pointers.cpp
*/

#include <iostream>
#include <cstdint>
#include <iomanip>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
