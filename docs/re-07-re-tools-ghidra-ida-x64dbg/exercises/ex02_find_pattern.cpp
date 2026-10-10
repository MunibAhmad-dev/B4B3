// ex02_find_pattern.cpp — search process memory for a byte pattern
// TODO: Accept pid + hex pattern on CLI.
//       Walk VirtualQueryEx, ReadProcessMemory each committed region,
//       search for the pattern, print all matches: 0x<addr>.
// Compile: g++ -std=c++17 -o ex02.exe ex02_find_pattern.cpp
// Usage: ex02.exe <pid> <hex_pattern>  e.g. ex02.exe 1234 4D5A
#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if(argc<3){printf("Usage: ex02.exe <pid> <hex>\n");return 1;}
    printf("Pattern search exercise — implement TODOs\n");
    return 0;
}
