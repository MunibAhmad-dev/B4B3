# Module 22 — Binary Analysis Tools

## Why binary analysis

Every piece of malware you'll encounter in a blue team role is a compiled binary.
You can't read source code — you read the PE file.
Binary analysis skills let you:
- Identify what APIs a binary calls (before running it)
- Find strings, URLs, C2 addresses
- Detect packing/obfuscation
- Reconstruct behavior from assembly
- Compare two versions of a DLL to find what a patch changed

---

## 1. PE File Parsing (deep recap)

Module 04 covered the PE header basics. Here we go deeper.

```
PE file layout:
  DOS Header       (64 bytes) — begins with MZ (4D 5A)
  DOS Stub         (variable) — small DOS program
  PE Signature     (4 bytes)  — PE\0\0 (50 45 00 00)
  COFF Header      (20 bytes) — machine, section count, timestamp
  Optional Header  (240 bytes on x64) — entry point, image base, data dirs
  Section Table    (40 bytes each) — .text, .rdata, .data, .rsrc etc.
  Sections         — the actual content
  Overlay          — data past the last section (common in packed files)
```

**Key fields for analysis:**
```cpp
IMAGE_NT_HEADERS* nt = ...; // parse from DOS header

// When was this binary compiled?
time_t ts = nt->FileHeader.TimeDateStamp;  // seconds since epoch

// Entry point
DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;

// Data directories — index 0=export, 1=import, 2=resource, 5=reloc, 14=COM
IMAGE_DATA_DIRECTORY* dd = nt->OptionalHeader.DataDirectory;
DWORD importRVA = dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
DWORD exportRVA = dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
```

---

## 2. Import Table Analysis

The import table tells you exactly which Windows APIs a binary uses — without running it.
If a binary imports `CreateRemoteThread` and `WriteProcessMemory`, it's almost
certainly doing process injection.

```cpp
void printImports(const BYTE* fileBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBase;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(fileBase + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd.VirtualAddress) { printf("No imports\n"); return; }

    // RVA → file offset conversion (needed when reading from file, not mapped memory)
    auto rvaToOffset = [&](DWORD rva) -> DWORD {
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (rva >= sec[i].VirtualAddress &&
                rva <  sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
        return rva;
    };

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(fileBase + rvaToOffset(dd.VirtualAddress));

    while (imp->Name) {
        const char* dllName = (const char*)(fileBase + rvaToOffset(imp->Name));
        printf("  %s:\n", dllName);

        IMAGE_THUNK_DATA* thunk =
            (IMAGE_THUNK_DATA*)(fileBase + rvaToOffset(imp->OriginalFirstThunk));
        while (thunk->u1.AddressOfData) {
            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                IMAGE_IMPORT_BY_NAME* ibn =
                    (IMAGE_IMPORT_BY_NAME*)(fileBase + rvaToOffset((DWORD)thunk->u1.AddressOfData));
                printf("    %s\n", ibn->Name);
            }
            thunk++;
        }
        imp++;
    }
}
```

---

## 3. Export Table Analysis

```cpp
void printExports(const BYTE* fileBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBase;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(fileBase + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress) { printf("No exports\n"); return; }

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(fileBase + rvaToOffset(dd.VirtualAddress));

    DWORD* names    = (DWORD*)(fileBase + rvaToOffset(exp->AddressOfNames));
    DWORD* funcs    = (DWORD*)(fileBase + rvaToOffset(exp->AddressOfFunctions));
    WORD*  ordinals = (WORD*) (fileBase + rvaToOffset(exp->AddressOfNameOrdinals));

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(fileBase + rvaToOffset(names[i]));
        DWORD rva = funcs[ordinals[i]];
        printf("  [%04u] RVA=0x%08X  %s\n", ordinals[i] + exp->Base, rva, name);
    }
}
```

---

## 4. Disassembly with Capstone / Zydis

**Capstone** and **Zydis** are C disassembly libraries. Integrate them to
decode raw bytes into human-readable assembly.

```cpp
// Using Zydis (header-only mode)
// Download: https://github.com/zyantific/zydis
#include "Zydis/Zydis.h"

void disassemble(const uint8_t* code, size_t size, uint64_t baseAddr) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    uint64_t offset = 0;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offset,
                                               size - offset, &instr, ops))) {
        char text[256];
        ZydisFormatterFormatInstruction(&formatter, &instr, ops,
                                        instr.operand_count, text, sizeof(text),
                                        baseAddr + offset, nullptr);
        printf("0x%016llX  %s\n", baseAddr + offset, text);
        offset += instr.length;
    }
}
```

**Usage for malware analysis:**
1. Map the PE file
2. Find `.text` section offset
3. Run `disassemble()` from the entry point
4. Look for: suspicious API calls, unusual patterns, obfuscation (long NOPs,
   self-modifying code, arithmetic decryption loops)

---

## 5. String Extraction

Malware often contains strings that reveal its purpose:
- C2 URLs, IP addresses
- Registry keys for persistence
- Mutex names (used for single-instance checks)
- Command names parsed from C2

```cpp
void extractStrings(const BYTE* fileBase, size_t fileSize, int minLen) {
    int run = 0;
    size_t start = 0;

    for (size_t i = 0; i <= fileSize; i++) {
        bool printable = (i < fileSize) && (fileBase[i] >= 0x20) && (fileBase[i] <= 0x7E);
        if (printable) {
            if (run == 0) start = i;
            run++;
        } else {
            if (run >= minLen) {
                printf("0x%08zX: %.*s\n", start, run, (char*)fileBase + start);
            }
            run = 0;
        }
    }
}
```

**Wide strings** (UTF-16LE) — search for `printable byte, 0x00, printable byte, 0x00` pattern.

---

## 6. Entropy Analysis

High entropy sections indicate encryption or compression (packing).
Entropy ranges:
- ~0: all-zero section (BSS)
- ~3–5: normal code/data
- ~6–7: compressed data
- ~7.5–8: encrypted or random (suspicious)

```cpp
double shannonEntropy(const BYTE* data, size_t size) {
    int freq[256] = {};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}
```

If `.text` section entropy > 7.5: binary is probably packed (UPX, custom packer).
Unpack before analyzing: run in sandbox, dump memory after unpacking completes.

---

## Exercises

- `ex01_pe_analyzer.cpp` — full PE analysis: headers, imports, exports, entropy per section
- `ex02_string_extractor.cpp` — ASCII + wide string extraction with file offset
- `ex03_disassembler.cpp` — integrate Zydis/Capstone, disassemble .text from entry point
- `ex04_suspicious_api_scanner.cpp` — flag binaries that import injection/credential APIs
