/*
  Exercise 03 — Function-Level Diff (Hash Matching)
  ---------------------------------------------------
  Rather than diffing raw bytes, match functions by their "shape"
  (mnemonic sequence hash) so relocation and recompilation noise
  doesn't create false positives.

  Algorithm:
    1. Parse both PEs, find the .text section.
    2. Locate function boundaries using a heuristic:
       - Any address in the export table → function start.
       - Pattern: a sequence starting after a series of NOPs/RETs → new function.
    3. Hash each function using its mnemonic sequence.
    4. Match functions between old and new by hash:
         hash_old → func_A, hash_new → func_A  → UNCHANGED
         hash differs                           → CHANGED
         present only in new export table       → ADDED
         present only in old export table       → REMOVED

  Tasks:
  1. Implement parseFunctions(pe_bytes, sections) — use export table RVAs
     as function start points; estimate each function's end by scanning
     forward until a RET or another function start.
  2. Implement mnemonicHash(code, size) — hash the mnemonic IDs
     (ignoring operands so relocations don't affect the hash).
  3. Implement matchFunctions(funcsA, funcsB) — return {name, status, %-match}.
  4. Print a table of: name | old_hash | new_hash | status

  Uses Zydis for disassembly — see Module 22, ex03.
  If Zydis is not available, use a simple NOP-count hash as a fallback.

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_function_matcher.cpp
    # Add Zydis if available: -DZYDIS_AVAILABLE -I<zydis>/include -lZydis
  Usage:
    ex03.exe old.dll new.dll
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef ZYDIS_AVAILABLE
#include <Zydis/Zydis.h>
#endif

struct FuncInfo {
    std::string name;
    DWORD       rva;
    uint32_t    hash;
    size_t      size;
};

// ---------- Simple mnemonic hash (no Zydis) ----------
uint32_t simpleHash(const BYTE* code, size_t size) {
    uint32_t h = 5381;
    // Just use bytes — imprecise but works without Zydis
    for (size_t i = 0; i < size; i++) h = h * 33 + code[i];
    return h;
}

#ifdef ZYDIS_AVAILABLE
uint32_t mnemonicHash(const BYTE* code, size_t size) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    uint32_t h = 5381; size_t off = 0;
    while (off < size &&
           ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code+off, size-off, &instr, operands))) {
        h = h * 33 + instr.mnemonic;
        off += instr.length;
    }
    return h;
}
#else
uint32_t mnemonicHash(const BYTE* code, size_t size) { return simpleHash(code, size); }
#endif

// ---------- TODO 1: parseFunctions ----------
std::vector<FuncInfo> parseFunctions(const std::vector<BYTE>& peBuf) {
    std::vector<FuncInfo> funcs;
    // YOUR CODE HERE:
    // 1. Parse IMAGE_NT_HEADERS64 to find export directory RVA
    // 2. Find .text section VirtualAddress + raw data offset
    // 3. Parse export table: for each export name + RVA:
    //    - rvaToFile = rva - textSection.VirtualAddress + textSection.PointerToRawData
    //    - code = peBuf.data() + rvaToFile
    //    - estimate function size: scan forward until RET (0xC3/0xC2) or next function
    //    - hash = mnemonicHash(code, size)
    //    - funcs.push_back({ name, rva, hash, size })
    (void)peBuf;
    return funcs;
}

enum MatchStatus { UNCHANGED, CHANGED, ADDED, REMOVED };

struct MatchResult {
    std::string name;
    DWORD       rvaOld, rvaNew;
    uint32_t    hashOld, hashNew;
    MatchStatus status;
};

// ---------- TODO 2+3: matchFunctions ----------
std::vector<MatchResult> matchFunctions(
    const std::vector<FuncInfo>& funcsA,
    const std::vector<FuncInfo>& funcsB)
{
    std::vector<MatchResult> results;
    // YOUR CODE HERE:
    // Build map name→FuncInfo for both
    // For each name in A:
    //   if in B: compare hashes → UNCHANGED or CHANGED
    //   else: REMOVED
    // For each name only in B: ADDED
    (void)funcsA; (void)funcsB;
    return results;
}

std::vector<BYTE> readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return { std::istreambuf_iterator<char>(f), {} };
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe/dll> <new.exe/dll>\n", argv[0]);
        return 1;
    }
    auto bufA = readFile(argv[1]);
    auto bufB = readFile(argv[2]);
    if (bufA.empty() || bufB.empty()) { printf("[-] File read error\n"); return 1; }

    auto funcsA = parseFunctions(bufA);
    auto funcsB = parseFunctions(bufB);

    if (funcsA.empty()) {
        printf("[-] parseFunctions not implemented\n"); return 1;
    }

    printf("[*] Old: %zu exports  New: %zu exports\n",
           funcsA.size(), funcsB.size());

    auto matches = matchFunctions(funcsA, funcsB);
    if (matches.empty()) {
        printf("[-] matchFunctions not implemented\n"); return 1;
    }

    int same=0, changed=0, added=0, removed=0;
    printf("\n%-40s  %10s  %10s  %s\n", "Function", "OldHash", "NewHash", "Status");
    printf("%s\n", std::string(80, '-').c_str());
    for (auto& m : matches) {
        const char* statusStr = m.status==UNCHANGED ? "same"
                              : m.status==CHANGED   ? "CHANGED"
                              : m.status==ADDED     ? "ADDED"
                                                    : "REMOVED";
        printf("%-40s  %08X    %08X    %s\n",
               m.name.c_str(), m.hashOld, m.hashNew, statusStr);
        switch (m.status) {
            case UNCHANGED: same++;    break;
            case CHANGED:   changed++; break;
            case ADDED:     added++;   break;
            case REMOVED:   removed++; break;
        }
    }
    printf("\n[*] Summary: %d same  %d changed  %d added  %d removed\n",
           same, changed, added, removed);
    return 0;
}
