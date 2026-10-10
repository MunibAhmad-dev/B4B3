/*
  Exercise 01 — Handles and Win32 File I/O
  ------------------------------------------
  Use Win32 API (NOT std::fstream) for all file operations.

  Tasks:
  1. Write a function: bool WriteFileFull(const char* path, const char* data, DWORD len)
     Creates or overwrites the file at path with data.
     Uses: CreateFileA, WriteFile, CloseHandle.
     Returns true on success.

  2. Write a function: std::string ReadFileFull(const char* path)
     Reads the entire file and returns its contents as a string.
     Uses: CreateFileA, GetFileSize (or GetFileSizeEx), ReadFile, CloseHandle.
     Returns empty string on error.

  3. Write a function: bool AppendFile(const char* path, const char* data, DWORD len)
     Opens an existing file and appends data.
     Uses: CreateFileA with OPEN_ALWAYS and FILE_APPEND_DATA access.

  4. In main():
     - Write "Hello, Win32!\n" to "test.txt"
     - Append "Second line\n" to "test.txt"
     - Read the whole file back and print it
     - Print the file size in bytes
     - Delete the file with DeleteFileA()

  5. Error handling:
     Write a helper: void printLastError(const char* context)
     That calls GetLastError() + FormatMessageA and prints both.
     Call it after every failed Win32 call.

  Compile (requires Windows):
    g++ -std=c++17 -Wall -o ex01.exe ex01_handles_winapi.cpp -lkernel32
*/

#include <windows.h>
#include <iostream>
#include <string>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
