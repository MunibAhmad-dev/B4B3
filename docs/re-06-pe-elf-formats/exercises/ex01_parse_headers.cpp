// ex01_parse_headers.cpp — PE header parser
// TODO: Open any .exe, map it, and print:
//   Machine, TimeDateStamp, NumberOfSections, Characteristics
//   ImageBase, EntryPoint, SectionAlignment, FileAlignment
//   All 16 DataDirectory entries (name + RVA + size)
//   All section names + VA + RawSize + Characteristics flags
// Compile: g++ -std=c++17 -o ex01.exe ex01_parse_headers.cpp
// Usage: ex01.exe <file.exe>
#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: ex01.exe <file>\n"); return 1; }
    printf("PE header parser — implement TODOs for: %s\n", argv[1]);
    return 0;
}
