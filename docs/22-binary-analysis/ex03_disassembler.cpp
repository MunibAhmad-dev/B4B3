/*
  Exercise 03 — Disassembler Integration (Zydis)
  ------------------------------------------------
  Static disassembly lets you read the code inside a PE file without
  running it. This is how IDA Pro, Ghidra, and binary security scanners work.

  This exercise uses Zydis — a fast x86/x64 disassembler library.
  You'll disassemble the .text section of a PE file and:
    1. Print every instruction.
    2. Detect "suspicious instruction patterns":
         - INT 3 sequences (0xCC pads — debugger traps or alignment)
         - CPUID in user code (anti-VM check)
         - RDTSC (timing anti-analysis)
         - Indirect call through computed register: CALL [rax+rbx*8]
         - NOP sleds (>= 16 consecutive NOPs)

  Zydis setup (install via vcpkg or download prebuilt):
    vcpkg install zydis:x64-windows
    Or: download from https://github.com/zyantific/zydis/releases

  Tasks:
  1. Implement loadTextSection(filename) — map the PE, find .text,
     return its bytes + base RVA.
  2. Implement disassemble(buf, size, baseRVA) — use Zydis to iterate
     instructions; print offset + bytes + mnemonic + operands.
  3. Implement detectSuspicious(buf, size) — scan for the patterns above.
  4. Run on any PE: your RAT binary, a known clean binary, a malware sample.

  Compile (MSVC with Zydis via vcpkg):
    cl /std:c++17 ex03_disassembler.cpp /I%VCPKG%\include
       /link /LIBPATH:%VCPKG%\lib Zydis.lib Zycore.lib /OUT:ex03.exe

  Usage:
    ex03.exe C:\Windows\System32\notepad.exe
*/

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>

// Zydis headers — comment out if not installed; use the stub below
#ifdef ZYDIS_AVAILABLE
#include <Zydis/Zydis.h>
#endif

struct TextSection {
    std::vector<BYTE> bytes;
    DWORD             rva;       // virtual address in the PE
    ULONGLONG         imageBase; // from optional header
};

// ---------- TODO 1: loadTextSection ----------
TextSection loadTextSection(const char* filename) {
    TextSection ts = {};
    // YOUR CODE HERE:
    // 1. Read the entire file into a buffer (std::ifstream binary)
    // 2. Cast to IMAGE_DOS_HEADER → IMAGE_NT_HEADERS64
    // 3. ts.imageBase = nt->OptionalHeader.ImageBase
    // 4. Walk IMAGE_SECTION_HEADER array, find ".text"
    // 5. Copy bytes: buf + section.PointerToRawData, length SizeOfRawData
    // 6. ts.rva = section.VirtualAddress
    (void)filename;
    return ts;
}

// ---------- TODO 2: disassemble ----------
void disassemble(const BYTE* buf, size_t size, ULONGLONG baseAddr) {
#ifdef ZYDIS_AVAILABLE
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ULONGLONG offset = 0;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char text[256];

    while (offset < size) {
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder,
                                                buf + offset, size - offset,
                                                &instr, operands))) {
            printf("%016llX  db 0x%02X\n", baseAddr + offset, buf[offset]);
            offset++; continue;
        }
        ZydisFormatterFormatInstruction(&formatter, &instr, operands,
                                         instr.operand_count, text, sizeof(text),
                                         baseAddr + offset, nullptr);
        // Print: address  hex_bytes  mnemonic+operands
        printf("%016llX  ", baseAddr + offset);
        for (int i = 0; i < instr.length; i++) printf("%02X ", buf[offset+i]);
        for (int i = instr.length; i < 10; i++) printf("   ");
        printf(" %s\n", text);
        offset += instr.length;
    }
#else
    // Stub when Zydis not available
    printf("[*] Zydis not available — showing raw bytes:\n");
    for (size_t i = 0; i < size && i < 256; i++) {
        if (i % 16 == 0) printf("\n%016llX  ", baseAddr + i);
        printf("%02X ", buf[i]);
    }
    printf("\n");
    (void)size;
#endif
}

// ---------- TODO 3: detectSuspicious ----------
void detectSuspicious(const BYTE* buf, size_t size) {
    printf("\n[SUSPICIOUS PATTERNS]\n");
    int nopStreak = 0;

    for (size_t i = 0; i < size; i++) {
        // INT 3 (0xCC)
        if (buf[i] == 0xCC)
            printf("  [0x%08zX] INT3\n", i);

        // NOP sled
        if (buf[i] == 0x90) { nopStreak++;
            if (nopStreak == 16) printf("  [0x%08zX] NOP sled (>= 16)\n", i - 15);
        } else { nopStreak = 0; }

        // CPUID: 0F A2
        if (i+1 < size && buf[i] == 0x0F && buf[i+1] == 0xA2)
            printf("  [0x%08zX] CPUID (anti-VM?)\n", i);

        // RDTSC: 0F 31
        if (i+1 < size && buf[i] == 0x0F && buf[i+1] == 0x31)
            printf("  [0x%08zX] RDTSC (timing check)\n", i);

        // YOUR CODE HERE: detect CALL [reg+reg*scale] patterns
        // FF D0 = CALL rax, FF D4 = CALL rsp, etc.
        // FF 14 xx = CALL [reg + reg*scale]
        if (i+1 < size && buf[i] == 0xFF && buf[i+1] == 0x14)
            printf("  [0x%08zX] Indirect CALL (computed addr)\n", i);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe> [--no-disasm]\n", argv[0]);
        return 1;
    }
    bool noDisasm = (argc > 2 && strcmp(argv[2], "--no-disasm") == 0);

    TextSection ts = loadTextSection(argv[1]);
    if (ts.bytes.empty()) {
        printf("[-] loadTextSection not implemented or .text not found\n");
        return 1;
    }

    printf("[*] .text: %zu bytes  RVA=0x%08X  ImageBase=0x%016llX\n",
           ts.bytes.size(), ts.rva, ts.imageBase);

    if (!noDisasm) {
        printf("\n[DISASSEMBLY]\n");
        disassemble(ts.bytes.data(), ts.bytes.size(), ts.imageBase + ts.rva);
    }

    detectSuspicious(ts.bytes.data(), ts.bytes.size());
    return 0;
}
