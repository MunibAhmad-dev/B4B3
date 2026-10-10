/*
  Exercise 02 — Process Enumeration
  ------------------------------------
  Tasks:
  1. Write a struct: struct ProcInfo { DWORD pid; std::string name; std::string path; }

  2. Write: std::vector<ProcInfo> GetProcessList()
     Uses CreateToolhelp32Snapshot + Process32First/Next.
     For each process, also get its full path:
       Open it with OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)
       Call QueryFullProcessImageNameA()
       Close handle.
     If path can't be read (access denied), store empty string.

  3. Write: DWORD FindProcessByName(const std::string& name)
     Returns the PID of the first process whose name matches (case-insensitive).
     Returns 0 if not found.

  4. Write: bool IsProcessRunning(const std::string& name)
     Returns true if any process with that name is running.

  5. In main():
     - Print all processes as: PID | NAME | PATH
     - Count total processes and print
     - Check if "explorer.exe" is running and print result
     - Check if "wireshark.exe" is running (sandbox/analyst check)
     - Find the PID of "explorer.exe" and print it

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe ex02_enumerate_processes.cpp -lkernel32
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
