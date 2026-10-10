// ex01_full_analysis.cpp — full analysis pipeline exercise
// Compile: g++ -std=c++17 -o ex01.exe ex01_full_analysis.cpp -lbcrypt
// Usage: ex01.exe <binary> [--report <out.txt>]
//
// TODO 1: Phase 1 (Triage) — compute MD5/SHA256, check magic bytes, detect packer
//         signatures (UPX: "UPX0"/"UPX1" section names; NsPack: ".nsp0"; MPRESS: ".MPRESS1")
//
// TODO 2: Phase 2 (Static) — entropy, suspicious imports, strings, section table
//         Build a capability bitmask: NETWORK|INJECTION|PERSISTENCE|CRYPTO|KEYLOG
//
// TODO 3: Phase 3 (Behavioral hints) — any embedded IP/domain strings, registry
//         run keys, mutex names, hardcoded file paths
//
// TODO 4: Phase 4 (YARA generation) — from strings found, write a basic YARA rule
//         with the top 3 most unique strings found and the MZ condition
//
// TODO 5: Phase 5 (Report output) — write a structured text report:
//         HASH / VERDICT / CAPABILITY_FLAGS / IOC_TABLE / YARA_RULE

#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: ex01.exe <binary> [--report <out.txt>]\n"); return 1; }
    printf("Full analysis pipeline — implement TODOs for: %s\n", argv[1]);
    return 0;
}
