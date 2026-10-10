/*
  Exercise 01 — CreateProcess and Output Capture
  -------------------------------------------------
  Spawn a process silently and capture its stdout output.
  This is exactly how the RAT's shell execution works.

  Tasks:
  1. Write a function:
       std::string RunCommand(const char* cmd)
     - Creates an anonymous pipe with CreatePipe()
     - Spawns the command via CreateProcessA with:
         CREATE_NO_WINDOW flag
         STARTUPINFOA.hStdOutput and hStdError = write end of pipe
         STARTUPINFOA.dwFlags = STARTF_USESTDHANDLES
     - Closes the write end of the pipe in the parent
     - Reads all output from the read end into a std::string
     - Waits for the process to finish (WaitForSingleObject)
     - Returns the captured output

  2. In main(), run the following commands and print their output:
       "whoami"
       "ipconfig"
       "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""

  3. Write the output of "whoami" to a file "result.txt" using WriteFile (Win32).

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_create_process.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <string>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
