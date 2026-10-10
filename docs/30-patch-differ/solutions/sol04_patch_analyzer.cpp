/*
  Solution 04 — Patch Analyzer: Side-by-Side Disassembly + Pattern Detection (complete)

  Pattern detection added after the parallel-walk printout:
    - BOUNDS CHECK ADDED:  CMP + Jcc before a memory read/write in instrB
    - ASSERT REMOVED:      INT3 (0xCC) in instrA not present in instrB at same index
    - NULL CHECK ADDED:    TEST reg,reg + JE/JNZ before memory dereference in instrB
    - CONSTANT CHANGED:    immediate value differs between instrA[i] and instrB[i]
                           (detected by comparing hex tokens in the text representation)

  Compile without Zydis (byte-level fallback):
    g++ -std=c++17 -Wall -o sol04.exe sol04_patch_analyzer.cpp
  With Zydis:
    g++ -std=c++17 -Wall -DZYDIS_AVAILABLE -I<zydis>/include \
        -o sol04.exe sol04_patch_analyzer.cpp -L<zydis>/lib -lZydis
  Usage:
    sol04.exe old.exe new.exe
    sol04.exe old.dll new.dll SomeExportName
*/

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <sstream>

#ifdef ZYDIS_AVAILABLE
#include <Zydis/Zydis.h>
#endif

struct Instruction {
    size_t      offset;
    BYTE        bytes[15];
    int         length;
    std::string text;
    int         mnemonic;   // opcode ID (Zydis mnemonic enum or raw byte)
};

// ---------- disassemble ----------
#ifdef ZYDIS_AVAILABLE
std::vector<Instruction> disassemble(const BYTE* code, size_t size, ULONGLONG base) {
    std::vector<Instruction> instrs;
    ZydisDecoder   decoder;
    ZydisFormatter formatter;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    size_t off = 0;
    while (off < size) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code+off, size-off, &ins, ops))) {
            off++; continue;
        }
        Instruction i;
        i.offset   = off;
        i.length   = (int)ins.length;
        i.mnemonic = (int)ins.mnemonic;
        memcpy(i.bytes, code+off, ins.length);
        char buf[256] = {};
        ZydisFormatterFormatInstruction(
            &formatter, &ins, ops, ins.operand_count,
            buf, sizeof(buf), base+off, nullptr);
        i.text = buf;
        instrs.push_back(i);
        off += ins.length;
    }
    return instrs;
}
#else
// Fallback: one byte per "instruction" — limited analysis
std::vector<Instruction> disassemble(const BYTE* code, size_t size, ULONGLONG base) {
    std::vector<Instruction> instrs;
    for (size_t i = 0; i < size; i++) {
        Instruction ins = {};
        ins.offset   = i;
        ins.bytes[0] = code[i];
        ins.length   = 1;
        ins.mnemonic = code[i];
        char buf[32];
        snprintf(buf, sizeof(buf), "db 0x%02X", code[i]);
        ins.text = buf;
        instrs.push_back(ins);
    }
    (void)base;
    return instrs;
}
#endif

// ---------- Pattern detection helpers ----------

// Returns true if Instruction looks like a conditional jump (Jcc)
static bool isJcc(const Instruction& ins) {
#ifdef ZYDIS_AVAILABLE
    return (ins.mnemonic >= ZYDIS_MNEMONIC_JB && ins.mnemonic <= ZYDIS_MNEMONIC_JZ);
#else
    // In fallback mode, check the raw byte range for Jcc opcodes
    BYTE b = ins.bytes[0];
    return (b >= 0x70 && b <= 0x7F) ||   // short Jcc
           (b == 0x0F && ins.length >= 2 && ins.bytes[1] >= 0x80 && ins.bytes[1] <= 0x8F);
#endif
}

static bool isCmp(const Instruction& ins) {
#ifdef ZYDIS_AVAILABLE
    return ins.mnemonic == ZYDIS_MNEMONIC_CMP;
#else
    BYTE b = ins.bytes[0];
    // CMP opcodes: 38-3D, 80/7, 81/7, 83/7
    return (b >= 0x38 && b <= 0x3D) || b == 0x80 || b == 0x81 || b == 0x83;
#endif
}

static bool isTest(const Instruction& ins) {
#ifdef ZYDIS_AVAILABLE
    return ins.mnemonic == ZYDIS_MNEMONIC_TEST;
#else
    BYTE b = ins.bytes[0];
    return b == 0x84 || b == 0x85 || b == 0xA8 || b == 0xA9 || b == 0xF6 || b == 0xF7;
#endif
}

static bool isMemAccess(const Instruction& ins) {
    // Heuristic: instruction text contains '[' (memory operand)
    return ins.text.find('[') != std::string::npos;
}

static bool isInt3(const Instruction& ins) {
    return ins.bytes[0] == 0xCC;
}

// Extract the first hex immediate token from text like "mov eax, 0x1234"
// Returns "" if none found.
static std::string extractImmediate(const std::string& text) {
    size_t pos = text.find("0x");
    if (pos == std::string::npos) pos = text.find("0X");
    if (pos == std::string::npos) return "";
    size_t end = pos + 2;
    while (end < text.size() &&
           (isxdigit((unsigned char)text[end]))) end++;
    return text.substr(pos, end - pos);
}

// ---------- sideBySide ----------
void sideBySide(const BYTE* codeA, size_t sizeA, ULONGLONG baseA,
                const BYTE* codeB, size_t sizeB, ULONGLONG baseB,
                const std::string& funcName)
{
    auto instrA = disassemble(codeA, sizeA, baseA);
    auto instrB = disassemble(codeB, sizeB, baseB);

    printf("\n[FUNCTION] %s\n", funcName.c_str());
    printf("%-47s  |  %-47s\n", "OLD", "NEW");
    printf("%s\n", std::string(99, '-').c_str());

    // --- Parallel walk ---
    size_t n = std::max(instrA.size(), instrB.size());
    int changes = 0;
    for (size_t i = 0; i < n; i++) {
        bool hasA = (i < instrA.size());
        bool hasB = (i < instrB.size());
        bool same = hasA && hasB && instrA[i].text == instrB[i].text;

        char aText[50] = {}, bText[50] = {};
        if (hasA) snprintf(aText, sizeof(aText), ".+%04zX  %s",
                           instrA[i].offset, instrA[i].text.c_str());
        if (hasB) snprintf(bText, sizeof(bText), ".+%04zX  %s",
                           instrB[i].offset, instrB[i].text.c_str());

        const char* marker = same           ? " "
                           : (hasA && !hasB) ? "-"
                           : (!hasA && hasB) ? "+"
                                             : "~";
        printf("%s %-47s  |  %-47s\n", marker, aText, bText);
        if (!same) changes++;
    }
    printf("[*] %d instruction differences\n", changes);
    if (!changes) return;

    // ================================================================
    // Pattern detection passes
    // ================================================================
    printf("\n--- Pattern Analysis ---\n");

    // --- 1. BOUNDS CHECK ADDED: CMP + Jcc in instrB before a memory access
    //        that is absent in instrA at that position ---
    for (size_t i = 0; i + 1 < instrB.size(); i++) {
        if (!isCmp(instrB[i])) continue;
        if (!isJcc(instrB[i+1])) continue;
        // Look ahead for a memory access within 3 instructions
        for (size_t k = i+2; k < instrB.size() && k < i+5; k++) {
            if (!isMemAccess(instrB[k])) continue;
            // Check if instrA had the same memory access without the CMP+Jcc prefix
            // (if instrA[i] is NOT a CMP, this is a newly added bounds check)
            bool presentInA = (i < instrA.size()) && isCmp(instrA[i]);
            if (!presentInA) {
                printf("  [!] BOUNDS CHECK ADDED at +0x%04zX (CMP+Jcc before mem access)\n",
                       instrB[i].offset);
            }
            break;
        }
    }

    // --- 2. ASSERT REMOVED: INT3 (0xCC) in instrA absent from instrB at same index ---
    for (size_t i = 0; i < instrA.size(); i++) {
        if (!isInt3(instrA[i])) continue;
        // Check if instrB at the same position is also INT3
        bool presentInB = (i < instrB.size()) && isInt3(instrB[i]);
        if (!presentInB) {
            printf("  [!] ASSERT REMOVED at +0x%04zX (INT3 gone in new version)\n",
                   instrA[i].offset);
        }
    }

    // --- 3. NULL CHECK ADDED: TEST reg,reg + JE/JNZ in instrB before a deref ---
    for (size_t i = 0; i + 1 < instrB.size(); i++) {
        if (!isTest(instrB[i])) continue;
        if (!isJcc(instrB[i+1])) continue;
        // Look ahead for memory dereference
        for (size_t k = i+2; k < instrB.size() && k < i+5; k++) {
            if (!isMemAccess(instrB[k])) continue;
            bool presentInA = (i < instrA.size()) && isTest(instrA[i]);
            if (!presentInA) {
                printf("  [!] NULL CHECK ADDED at +0x%04zX (TEST reg,reg + JE/JNZ before deref)\n",
                       instrB[i].offset);
            }
            break;
        }
    }

    // --- 4. CONSTANT CHANGED: immediate value differs ---
    size_t minN = std::min(instrA.size(), instrB.size());
    for (size_t i = 0; i < minN; i++) {
        if (instrA[i].mnemonic != instrB[i].mnemonic) continue;  // different instr, skip
        if (instrA[i].text == instrB[i].text) continue;          // identical, skip
        std::string immA = extractImmediate(instrA[i].text);
        std::string immB = extractImmediate(instrB[i].text);
        if (immA.empty() || immB.empty()) continue;
        if (immA != immB) {
            printf("  [!] CONSTANT CHANGED at +0x%04zX: %s -> %s  (%s  ->  %s)\n",
                   instrA[i].offset,
                   immA.c_str(), immB.c_str(),
                   instrA[i].text.c_str(), instrB[i].text.c_str());
        }
    }
}

// ---------- main ----------
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe> <new.exe> [function_offset_hex]\n", argv[0]);
        return 1;
    }

    std::ifstream fA(argv[1], std::ios::binary);
    std::ifstream fB(argv[2], std::ios::binary);
    if (!fA || !fB) { printf("[-] File open error\n"); return 1; }

    std::vector<BYTE> bufA(std::istreambuf_iterator<char>(fA), {});
    std::vector<BYTE> bufB(std::istreambuf_iterator<char>(fB), {});

    // Optional: user-specified start offset
    size_t startOff = 0;
    if (argc >= 4) startOff = (size_t)strtoul(argv[3], nullptr, 16);

    if (startOff >= bufA.size()) {
        printf("[-] Offset 0x%zX exceeds file A size\n", startOff);
        return 1;
    }

    // Compare up to 256 bytes from the given offset
    size_t szA = std::min(bufA.size() - startOff, (size_t)256);
    size_t szB = startOff < bufB.size()
                     ? std::min(bufB.size() - startOff, (size_t)256)
                     : 0;

    if (!szB) { printf("[-] Offset 0x%zX beyond new file\n", startOff); return 1; }

    char label[64];
    snprintf(label, sizeof(label), "function@0x%zX", startOff);
    if (argc >= 4) snprintf(label, sizeof(label), "%s", argv[3]);

    printf("[*] Comparing %zu / %zu bytes at offset 0x%zX\n", szA, szB, startOff);
    printf("[*] Files: %s  vs  %s\n", argv[1], argv[2]);

    sideBySide(bufA.data() + startOff, szA, 0x140001000ULL + startOff,
               bufB.data() + startOff, szB, 0x140001000ULL + startOff,
               label);
    return 0;
}
