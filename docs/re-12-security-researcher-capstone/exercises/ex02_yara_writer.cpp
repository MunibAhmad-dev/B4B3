// ex02_yara_writer.cpp — automatic YARA rule generator exercise
// Compile: g++ -std=c++17 -o ex02.exe ex02_yara_writer.cpp
// Usage: ex02.exe <binary> [--name <rule_name>]
//
// TODO 1: Extract all interesting strings (URLs, IPs, suspicious API names, mutex-like names)
//         Sort by uniqueness heuristic: shorter strings that appear in fewer common DLLs rank higher.
//
// TODO 2: Pick the top 5 strings, sanitize them for YARA (escape backslashes, quotes).
//         If any are hex sequences (e.g., XOR key bytes), emit as hex strings { AA BB CC }.
//
// TODO 3: Collect import hashes for suspicious APIs. Not directly YARA-expressible without
//         imphash plugin, but comment them in the meta section.
//
// TODO 4: Output a valid .yar file:
//   rule <name> {
//     meta:
//       description = "Auto-generated from binary analysis"
//       sample_md5  = "<md5>"
//     strings:
//       $s1 = "..."  ascii
//       $h1 = { HH HH HH }
//     condition:
//       uint16(0) == 0x5A4D and filesize < 10MB and 3 of them
//   }

#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: ex02.exe <binary> [--name <rule_name>]\n"); return 1; }
    printf("YARA rule generator — implement TODOs for: %s\n", argv[1]);
    return 0;
}
