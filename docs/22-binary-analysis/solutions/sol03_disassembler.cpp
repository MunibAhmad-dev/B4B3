/*
  Solution 03 — Disassembler (Complete, Zydis + Fallback)
  ---------------------------------------------------------
  Loads the .text section from a PE file, disassembles it with Zydis
  (if available), and detects suspicious byte patterns.

  Compile WITH Zydis (vcpkg):
    cl /std:c++17 /DZYDIS_AVAILABLE sol03_disassembler.cpp
       /I%VCPKG%\installed\x64-windows\include
       /link /LIBPATH:%VCPKG%\installed\x64-windows\lib
             Zydis.lib Zycore.lib /OUT:sol03.exe

  Compile WITHOUT Zydis (fallback mode):
    g++ -std=c++17 -Wall -o sol03.exe sol03_disassembler.cpp
    cl  /std:c++17 sol03_disassembler.cpp /Fe:sol03.exe

  Usage:
    sol03.exe target.exe
    sol03.exe target.exe --no-disasm   (pattern scan only)
*/

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef ZYDIS_AVAILABLE
#  include <Zydis/Zydis.h>
#endif

// =========================================================
// PE helper: map RVA to file offset
// =========================================================
struct PEContext {
    std::vector<BYTE>        fileData;
    IMAGE_NT_HEADERS64*      nt64  = nullptr;
    IMAGE_NT_HEADERS32*      nt32  = nullptr;
    IMAGE_SECTION_HEADER*    sects = nullptr;
    WORD                     numSects = 0;
    bool                     is64  = false;
};

static DWORD rvaToOffset(const PEContext& pe, DWORD rva) {
    for (WORD i = 0; i < pe.numSects; i++) {
        DWORD vStart = pe.sects[i].VirtualAddress;
        DWORD vEnd   = vStart + pe.sects[i].Misc.VirtualSize;
        if (rva >= vStart && rva < vEnd)
            return pe.sects[i].PointerToRawData + (rva - vStart);
    }
    return 0;
}

// =========================================================
// TextSection result
// =========================================================
struct TextSection {
    std::vector<BYTE> bytes;
    DWORD             rva;
    ULONGLONG         imageBase;
};

// =========================================================
// 1. loadTextSection — parse PE and copy .text bytes
// =========================================================
TextSection loadTextSection(const char* filename) {
    TextSection ts = {};

    std::ifstream f(filename, std::ios::binary);
    if (!f) { printf("[-] Cannot open '%s'\n", filename); return ts; }

    std::vector<BYTE> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();

    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return ts;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a PE file (bad MZ signature)\n");
        return ts;
    }

    DWORD ntOff = dos->e_lfanew;
    if (ntOff + sizeof(IMAGE_NT_HEADERS32) > data.size()) return ts;

    auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(data.data() + ntOff);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Bad PE signature\n");
        return ts;
    }

    WORD machine = nt32->FileHeader.Machine;
    bool is64    = (machine == IMAGE_FILE_MACHINE_AMD64 ||
                    machine == IMAGE_FILE_MACHINE_IA64);

    ULONGLONG imgBase;
    WORD       numSects;
    DWORD      sectOff;

    if (is64) {
        auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(data.data() + ntOff);
        imgBase  = nt64->OptionalHeader.ImageBase;
        numSects = nt64->FileHeader.NumberOfSections;
        sectOff  = ntOff + sizeof(IMAGE_NT_HEADERS64);
    } else {
        imgBase  = nt32->OptionalHeader.ImageBase;
        numSects = nt32->FileHeader.NumberOfSections;
        sectOff  = ntOff + sizeof(IMAGE_NT_HEADERS32);
    }

    if (sectOff + numSects * sizeof(IMAGE_SECTION_HEADER) > data.size()) return ts;

    auto* sects = reinterpret_cast<IMAGE_SECTION_HEADER*>(data.data() + sectOff);

    for (WORD i = 0; i < numSects; i++) {
        // Section names are not always null-terminated within the 8-byte field
        char name[9] = {};
        memcpy(name, sects[i].Name, 8);

        if (strcmp(name, ".text") == 0) {
            DWORD rawOff  = sects[i].PointerToRawData;
            DWORD rawSize = sects[i].SizeOfRawData;

            if (rawOff + rawSize > data.size())
                rawSize = (DWORD)(data.size() - rawOff);

            ts.bytes.assign(data.begin() + rawOff,
                            data.begin() + rawOff + rawSize);
            ts.rva       = sects[i].VirtualAddress;
            ts.imageBase = imgBase;
            return ts;
        }
    }

    printf("[-] .text section not found in '%s'\n", filename);
    return ts;
}


// =========================================================
// 2. disassembleRange — decode and print instructions
// =========================================================
void disassembleRange(const BYTE* buf, size_t size, ULONGLONG baseAddr) {
#ifdef ZYDIS_AVAILABLE
    ZydisDecoder   decoder;
    ZydisFormatter formatter;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ULONGLONG          offset = 0;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    char text[256];

    while (offset < size) {
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, buf + offset, size - offset, &instr, operands);

        if (ZYAN_FAILED(status)) {
            printf("%016llX  %02X                         db 0x%02X\n",
                   baseAddr + offset, buf[offset], buf[offset]);
            offset++;
            continue;
        }

        // Format full instruction text
        ZydisFormatterFormatInstruction(
            &formatter, &instr, operands,
            instr.operand_count, text, sizeof(text),
            baseAddr + offset, nullptr);

        // Print:  address   hex bytes (padded to 10)   mnemonic+operands
        printf("%016llX  ", baseAddr + offset);
        for (ZyanU8 i = 0; i < instr.length; i++)
            printf("%02X ", buf[offset + i]);
        for (ZyanU8 i = instr.length; i < 10; i++) printf("   ");
        printf(" %s\n", text);

        offset += instr.length;
    }

#else
    // Fallback: raw hex dump when Zydis is not available
    printf("[*] Zydis not available — raw hex dump (first 512 bytes):\n");
    size_t show = std::min(size, (size_t)512);
    for (size_t i = 0; i < show; i++) {
        if (i % 16 == 0) printf("\n%016llX  ", baseAddr + i);
        printf("%02X ", buf[i]);
    }
    printf("\n");
    (void)size;
#endif
}


// =========================================================
// 3. detectSuspicious — byte-pattern scan for anti-analysis indicators
// =========================================================
void detectSuspicious(const BYTE* buf, size_t size) {
    printf("\n[SUSPICIOUS PATTERNS]\n");
    printf("%-12s  %s\n", "Offset", "Pattern");
    printf("%s\n", std::string(50, '-').c_str());

    int nopStreak  = 0;
    int int3Streak = 0;
    int found      = 0;

    for (size_t i = 0; i < size; i++) {

        // ---- NOP sled (>= 16 consecutive 0x90) ----
        if (buf[i] == 0x90) {
            nopStreak++;
            if (nopStreak == 16) {
                printf("0x%08zX  NOP sled (>= 16 NOPs)\n", i - 15);
                found++;
            }
        } else { nopStreak = 0; }

        // ---- INT3 sequence (>= 4 consecutive 0xCC) ----
        if (buf[i] == 0xCC) {
            int3Streak++;
            if (int3Streak == 4) {
                printf("0x%08zX  INT3 sequence (>= 4)\n", i - 3);
                found++;
            }
        } else { int3Streak = 0; }

        // Two-byte opcodes
        if (i + 1 < size) {
            // ---- CPUID: 0F A2 ----
            if (buf[i] == 0x0F && buf[i+1] == 0xA2) {
                printf("0x%08zX  CPUID (anti-VM / anti-hypervisor check)\n", i);
                found++;
            }
            // ---- RDTSC: 0F 31 ----
            if (buf[i] == 0x0F && buf[i+1] == 0x31) {
                printf("0x%08zX  RDTSC (timing anti-analysis)\n", i);
                found++;
            }
            // ---- RDTSCP: 0F 01 F9 ----
            if (i + 2 < size &&
                buf[i] == 0x0F && buf[i+1] == 0x01 && buf[i+2] == 0xF9) {
                printf("0x%08zX  RDTSCP (timing)\n", i);
                found++;
            }
        }

        // Indirect CALL patterns
        if (i + 1 < size && buf[i] == 0xFF) {
            BYTE mod = buf[i+1];
            // FF /2 = CALL r/m64; ModRM byte high 3 bits == 010 (opcode ext 2)
            // FF 14 xx = CALL [reg + reg*scale + disp]
            if (mod == 0x14) {
                printf("0x%08zX  Indirect CALL [SIB] (computed address)\n", i);
                found++;
            }
            // FF 15 xx xx xx xx = CALL [RIP+disp32] (common for IAT calls — less suspicious)
            // FF D0..D7 = CALL rax..rdi (register call)
            if (mod >= 0xD0 && mod <= 0xD7) {
                printf("0x%08zX  CALL r%s (indirect via register)\n",
                       i,
                       (const char*[]){"ax","cx","dx","bx",
                                       "sp","bp","si","di"}[mod - 0xD0]);
                found++;
            }
        }

        // IN/OUT instructions (port I/O — anti-VM)
        if (buf[i] == 0xE4 || buf[i] == 0xE5 ||  // IN imm8
            buf[i] == 0xEC || buf[i] == 0xED) {   // IN DX
            printf("0x%08zX  IN instruction (anti-VM port check)\n", i);
            found++;
        }
        if (buf[i] == 0xE6 || buf[i] == 0xE7 ||  // OUT imm8
            buf[i] == 0xEE || buf[i] == 0xEF) {   // OUT DX
            printf("0x%08zX  OUT instruction (anti-VM)\n", i);
            found++;
        }
    }

    if (found == 0)
        printf("  (none found)\n");

    printf("\n[*] Total suspicious patterns: %d\n", found);
}


// =========================================================
// main
// =========================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe> [--no-disasm]\n", argv[0]);
        return 1;
    }
    bool noDisasm = (argc > 2 && strcmp(argv[2], "--no-disasm") == 0);

    TextSection ts = loadTextSection(argv[1]);
    if (ts.bytes.empty()) {
        printf("[-] Failed to load .text section from '%s'\n", argv[1]);
        return 1;
    }

    printf("[*] File      : %s\n",    argv[1]);
    printf("[*] .text     : %zu bytes\n", ts.bytes.size());
    printf("[*] .text RVA : 0x%08X\n",   ts.rva);
    printf("[*] ImageBase : 0x%016llX\n", ts.imageBase);

#ifndef ZYDIS_AVAILABLE
    printf("[!] Compiled without Zydis — disassembly uses raw hex fallback.\n"
           "    Install Zydis via vcpkg and rebuild with -DZYDIS_AVAILABLE for proper disasm.\n");
#endif

    if (!noDisasm) {
        printf("\n[DISASSEMBLY]\n");
        disassembleRange(ts.bytes.data(), ts.bytes.size(),
                         ts.imageBase + ts.rva);
    } else {
        printf("[*] --no-disasm: skipping disassembly.\n");
    }

    detectSuspicious(ts.bytes.data(), ts.bytes.size());
    return 0;
}
