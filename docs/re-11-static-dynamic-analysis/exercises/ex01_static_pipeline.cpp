// ex01_static_pipeline.cpp — automated static analysis pipeline exercise
// Compile: g++ -std=c++17 -o ex01.exe ex01_static_pipeline.cpp
// Usage: ex01.exe <binary>
//
// TODO 1: Compute MD5 of the entire file (implement without external crypto lib —
//         use BCrypt CNG or implement the 64-step MD5 algorithm manually).
//         Print as hex string.
//
// TODO 2: Extract all printable ASCII strings (len >= 6) and wide strings (len >= 4).
//         Categorize each: URL, IP, registry, file path, or generic.
//
// TODO 3: Walk the import table and build a capability summary:
//         - Network: WinINet/WinHTTP/Winsock
//         - Injection: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
//         - Persistence: RegSetValueEx, CreateService
//         - Crypto: Crypt*, BCrypt*
//         Print a capability bitmask.
//
// TODO 4: Print a "threat score" 0-100 based on entropy (>7.0=+30), suspicious
//         imports (+10 each), URL/IP strings (+5 each), capped at 100.

#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: ex01.exe <binary>\n"); return 1; }
    printf("Static pipeline stub — implement TODOs for: %s\n", argv[1]);
    return 0;
}
