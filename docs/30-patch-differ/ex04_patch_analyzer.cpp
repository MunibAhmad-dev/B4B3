/*
  Exercise 04 — Patch Analyzer (Side-by-Side Disassembly)
  ---------------------------------------------------------
  After finding changed functions (ex03), drill into each one and
  display the old and new disassembly side by side — the way BinDiff
  and Diaphora show patch diffs to vulnerability researchers.

  For each changed function:
    Address | Old instruction  |  New instruction
    --------|------------------|------------------
    .+0x00  | push rbp         |  push rbp
    .+0x03  | mov rbp, rsp     |  mov rbp, rsp
    .+0x06  | mov eax, [rcx]   |  cmp rcx, 0x1000   ← CHANGED
    .+0x0B  | ...              |  jg .error
    .+0x0D  | ...              |  mov eax, [rcx]

  The side-by-side shows what was inserted (new bounds check, NULL check, etc.)

  Tasks:
  1. Implement sideBySide(codeA, sizeA, baseAddrA, codeB, sizeB, baseAddrB):
     - Disassemble both buffers in parallel
     - Pair instructions that appear at the "same position" by iterating both
       until both reach a common instruction (uses a simple LCS-based alignment)
     - Print changed instructions highlighted
  2. Load changed functions from ex03 and display them one by one.
  3. Flag pattern changes that suggest specific bug types:
       - Added bounds check: new code has CMP + Jcc before a memory access
       - Removed assert: old code had INT3 or CALL __assert that's now gone
       - NULL check added: new code has TEST reg, reg + JE/JNZ before deref
       - Constant changed: immediate operand value is different

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_patch_analyzer.cpp
    # With Zydis: -DZYDIS_AVAILABLE -I<zydis>/include -lZydis
  Usage:
    ex04.exe old.dll new.dll [function_name]
*/

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>

#ifdef ZYDIS_AVAILABLE
#include <Zydis/Zydis.h>
#endif

struct Instruction {
    size_t      offset;
    BYTE        bytes[15];
    int         length;
    std::string text;
    int         mnemonic; // opcode ID for comparison
};

#ifdef ZYDIS_AVAILABLE
std::vector<Instruction> disassemble(const BYTE* code, size_t size, ULONGLONG base) {
    std::vector<Instruction> instrs;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    size_t off = 0;
    while (off < size) {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code+off, size-off, &instr, operands))) {
            off++; continue;
        }
        Instruction i;
        i.offset  = off;
        i.length  = instr.length;
        i.mnemonic = instr.mnemonic;
        memcpy(i.bytes, code+off, instr.length);
        char buf[256] = {};
        ZydisFormatterFormatInstruction(&formatter, &instr, operands,
                                         instr.operand_count, buf, sizeof(buf),
                                         base + off, nullptr);
        i.text = buf;
        instrs.push_back(i);
        off += instr.length;
    }
    return instrs;
}
#else
std::vector<Instruction> disassemble(const BYTE* code, size_t size, ULONGLONG base) {
    // Fallback: one byte per "instruction"
    std::vector<Instruction> instrs;
    for (size_t i = 0; i < size; i++) {
        Instruction ins;
        ins.offset = i; ins.bytes[0] = code[i]; ins.length = 1;
        char buf[32]; sprintf_s(buf, "db 0x%02X", code[i]);
        ins.text = buf; ins.mnemonic = code[i];
        instrs.push_back(ins);
    }
    (void)base;
    return instrs;
}
#endif

// ---------- TODO 1: sideBySide ----------
void sideBySide(const BYTE* codeA, size_t sizeA, ULONGLONG baseA,
                 const BYTE* codeB, size_t sizeB, ULONGLONG baseB,
                 const std::string& funcName) {
    auto instrA = disassemble(codeA, sizeA, baseA);
    auto instrB = disassemble(codeB, sizeB, baseB);

    printf("\n[FUNCTION] %s\n", funcName.c_str());
    printf("%-45s  |  %-45s\n", "OLD", "NEW");
    printf("%s\n", std::string(95, '-').c_str());

    // YOUR CODE HERE:
    // Simple parallel walk (same count of instructions — works for minor patches)
    // More accurate: implement LCS alignment
    size_t n = std::max(instrA.size(), instrB.size());
    int changes = 0;
    for (size_t i = 0; i < n; i++) {
        bool hasA = i < instrA.size();
        bool hasB = i < instrB.size();
        bool same = hasA && hasB && instrA[i].text == instrB[i].text;

        char aText[48] = {}, bText[48] = {};
        if (hasA) snprintf(aText, sizeof(aText), ".+%04zX  %s", instrA[i].offset, instrA[i].text.c_str());
        if (hasB) snprintf(bText, sizeof(bText), ".+%04zX  %s", instrB[i].offset, instrB[i].text.c_str());

        const char* marker = same ? " " : (hasA && !hasB ? "-" : (!hasA && hasB ? "+" : "~"));
        printf("%s %-45s  |  %-45s\n", marker, aText, bText);
        if (!same) changes++;
    }
    printf("[*] %d instruction differences\n", changes);

    // TODO: detect patterns
    // YOUR CODE HERE: scan instrB for CMP+Jcc before MEM_ACCESS → bounds check added
    // Scan instrA for INT3 that's gone → assert removed
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe> <new.exe> [function_offset_hex]\n", argv[0]);
        return 1;
    }

    // For demo: compare the first 256 bytes of each file's .text section
    // (In full implementation, load from ex03 changed function list)
    std::ifstream fA(argv[1], std::ios::binary), fB(argv[2], std::ios::binary);
    if (!fA || !fB) { printf("[-] File open error\n"); return 1; }

    std::vector<BYTE> bufA(std::istreambuf_iterator<char>(fA), {});
    std::vector<BYTE> bufB(std::istreambuf_iterator<char>(fB), {});

    size_t szA = std::min(bufA.size(), (size_t)256);
    size_t szB = std::min(bufB.size(), (size_t)256);

    printf("[*] Comparing first 256 bytes (demo mode)\n");
    printf("[*] For full analysis: run ex03 first to find changed functions\n");

    sideBySide(bufA.data(), szA, 0x140001000ULL,
               bufB.data(), szB, 0x140001000ULL,
               "demo_function@0x1000");
    return 0;
}
