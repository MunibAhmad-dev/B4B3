/*
  Exercise 03 — PE Parser
  ------------------------
  Parse a PE (Portable Executable) file and print its structure.
  This is what an AV engine does before scanning for signatures.

  Tasks:
  1. Read a PE file into a vector<char> from disk.
     Accept the filename as argv[1].

  2. Validate the DOS header:
     - First 2 bytes should be 'M','Z' (0x4D, 0x5A)
     - e_lfanew field gives the offset to the PE header

  3. Validate the PE signature:
     - 4 bytes at e_lfanew should be 'P','E',0,0

  4. Print from IMAGE_FILE_HEADER:
     - Machine type (0x8664 = AMD64, 0x14C = i386)
     - Number of sections
     - TimeDateStamp (convert to human-readable with ctime())
     - Characteristics flags

  5. Print from IMAGE_OPTIONAL_HEADER:
     - Magic (0x10B = PE32, 0x20B = PE32+/64-bit)
     - AddressOfEntryPoint
     - ImageBase
     - Subsystem (2 = GUI / no window, 3 = Console)
     - SizeOfImage

  6. Print the section table:
     For each section: Name, VirtualAddress, SizeOfRawData, Characteristics
     The Characteristics field has flags like:
       IMAGE_SCN_MEM_EXECUTE (0x20000000) — code section
       IMAGE_SCN_MEM_READ    (0x40000000) — readable
       IMAGE_SCN_MEM_WRITE   (0x80000000) — writable

  7. Count imports:
     Navigate to the import directory (from OptionalHeader.DataDirectory[1]).
     Print each imported DLL name.
     This shows you exactly what an AV sees when it checks your binary.

  Example output:
    === PE Analysis: Stub.exe ===
    Architecture : AMD64
    Sections     : 6
    Subsystem    : 2 (GUI — no console)
    Entry point  : 0x1234
    Sections:
      .text   VA=0x1000  size=45678  flags=RX
      .rdata  VA=0xC000  size=12345  flags=R
      .data   VA=0xF000  size=1234   flags=RW
    Imports:
      kernel32.dll
      advapi32.dll
      wininet.dll

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_pe_parser.cpp
  Run:
    ex03.exe Stub.exe
*/

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>

// YOUR CODE HERE

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ex03.exe <pe_file>\n";
        return 1;
    }
    // YOUR CODE HERE
    return 0;
}
