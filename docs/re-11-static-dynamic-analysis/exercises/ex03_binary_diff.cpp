// ex03_binary_diff.cpp — binary diff exercise
// Compile: g++ -std=c++17 -o ex03.exe ex03_binary_diff.cpp
// Usage: ex03.exe <old_pe> <new_pe>
//
// TODO 1: Parse both PEs. Build a map<string, uint32_t> of export_name -> DJB2 hash
//         of the first 64 bytes of each exported function.
//
// TODO 2: Diff the maps:
//         - "CHANGED": export exists in both but hash differs (likely patched)
//         - "ADDED":   export only in new binary
//         - "REMOVED": export only in old binary
//
// TODO 3: For each CHANGED function, print old bytes vs new bytes side-by-side (hex),
//         annotate common patch patterns:
//         - E9 xx xx xx xx  → JMP (hook / inline patch)
//         - 0F 1F ...       → NOP sled
//         - B8 xx xx xx xx  → MOV EAX, imm (forced return value)
//
// TODO 4: Report a "patch summary" — which DLL component was likely patched and why.

#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc < 3) { printf("Usage: ex03.exe <old_pe> <new_pe>\n"); return 1; }
    printf("Binary diff stub — implement TODOs for: %s vs %s\n", argv[1], argv[2]);
    return 0;
}
