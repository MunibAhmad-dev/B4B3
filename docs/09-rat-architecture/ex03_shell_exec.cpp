/*
  Exercise 03 — Shell Execution with Output Capture
  ---------------------------------------------------
  This is the function every RAT uses to run commands on the victim.

  Tasks:
  1. Write: std::string ExecShell(const std::string& cmd)
     Same as Module 05 ex01 but this time handle edge cases:
     - Command timeout: kill the process if it doesn't finish in 30 seconds
     - Max output: stop reading if output exceeds 1 MB
     - Trim trailing whitespace/newlines from the output

  2. Write: std::string GetSystemInfo()
     Returns a formatted string with:
       Computer name, username, OS version, architecture, IP addresses,
       process list (PID | name, one per line)
     Reuse your process enumeration code from Module 05 ex02.

  3. Write: std::string GetCurrentDirectory_()
     Returns the current working directory.

  4. In main() test all three:
     Run "whoami /all"
     Run "netstat -ano | findstr ESTABLISHED"
     Print GetSystemInfo()
     Print GetCurrentDirectory_()

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_shell_exec.cpp -lkernel32 -liphlpapi
*/

#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
