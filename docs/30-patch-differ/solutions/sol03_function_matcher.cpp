/*
  Solution 03 — Function-Level Diff via Export Table + Hash Matching (complete)

  Compile without Zydis:
    g++ -std=c++17 -Wall -o sol03.exe sol03_function_matcher.cpp
  Compile with Zydis (mnemonic-only hash, more accurate):
    g++ -std=c++17 -Wall -DZYDIS_AVAILABLE -I<zydis>/include \
        -o sol03.exe sol03_function_matcher.cpp -L<zydis>/lib -lZydis
  Usage:
    sol03.exe old.dll new.dll
*/

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
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

// ---------- Simple byte-based hash (fallback without Zydis) ----------
uint32_t simpleHash(const BYTE* code, size_t size) {
    uint32_t h = 5381;
    for (size_t i = 0; i < size; i++) h = h * 33 + code[i];
    return h;
}

#ifdef ZYDIS_AVAILABLE
// Mnemonic-sequence hash: ignores operand values, so relocations don't change it
uint32_t mnemonicHash(const BYTE* code, size_t size) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    uint32_t h = 5381;
    size_t   off = 0;
    while (off < size &&
           ZYAN_SUCCESS(ZydisDecoderDecodeFull(
               &decoder, code + off, size - off, &instr, operands)))
    {
        h = h * 33 + (uint32_t)instr.mnemonic;
        off += instr.length;
    }
    return h;
}
#else
uint32_t mnemonicHash(const BYTE* code, size_t size) {
    return simpleHash(code, size);
}
#endif

// ---------- Helper: read a file into a byte vector ----------
std::vector<BYTE> readFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return { std::istreambuf_iterator<char>(f),
             std::istreambuf_iterator<char>() };
}

// ---------- parseFunctions ----------
// Parses the PE export directory to get function names + RVAs,
// then estimates each function's size by scanning for a RET (0xC3/0xC2).
std::vector<FuncInfo> parseFunctions(const std::vector<BYTE>& peBuf) {
    std::vector<FuncInfo> funcs;
    if (peBuf.size() < sizeof(IMAGE_DOS_HEADER)) return funcs;

    const BYTE* b = peBuf.data();

    auto* dos = (const IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return funcs;

    LONG ntOff = dos->e_lfanew;
    if ((size_t)ntOff + sizeof(IMAGE_NT_HEADERS64) > peBuf.size()) return funcs;

    auto* ntSig = (const IMAGE_NT_HEADERS*)(b + ntOff);
    if (ntSig->Signature != IMAGE_NT_SIGNATURE) return funcs;

    // Support both PE32 and PE32+
    DWORD expRVA = 0, expSize = 0;
    WORD  numSections = 0;
    DWORD sectionOffset = 0;

    if (ntSig->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* nt = (const IMAGE_NT_HEADERS64*)(b + ntOff);
        expRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        numSections    = nt->FileHeader.NumberOfSections;
        sectionOffset  = ntOff + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
                       + nt->FileHeader.SizeOfOptionalHeader;
    } else {
        auto* nt = (const IMAGE_NT_HEADERS32*)(b + ntOff);
        expRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        numSections    = nt->FileHeader.NumberOfSections;
        sectionOffset  = ntOff + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
                       + nt->FileHeader.SizeOfOptionalHeader;
    }

    if (!expRVA || !numSections) return funcs;

    // Build RVA->file-offset map from section headers
    auto* secs = (const IMAGE_SECTION_HEADER*)(b + sectionOffset);

    // Helper lambda: convert RVA to raw file offset
    auto rvaToOffset = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < numSections; i++) {
            DWORD va  = secs[i].VirtualAddress;
            DWORD raw = secs[i].PointerToRawData;
            DWORD sz  = secs[i].SizeOfRawData;
            if (rva >= va && rva < va + sz)
                return raw + (rva - va);
        }
        return 0;
    };

    // Locate the .text section for code byte extraction
    DWORD textVA = 0, textRawOff = 0, textRawSize = 0;
    for (WORD i = 0; i < numSections; i++) {
        char secName[9] = {};
        memcpy(secName, secs[i].Name, 8);
        if (strcmp(secName, ".text") == 0) {
            textVA      = secs[i].VirtualAddress;
            textRawOff  = secs[i].PointerToRawData;
            textRawSize = secs[i].SizeOfRawData;
            break;
        }
    }

    // Parse export directory
    DWORD expFileOff = rvaToOffset(expRVA);
    if (!expFileOff || expFileOff + sizeof(IMAGE_EXPORT_DIRECTORY) > peBuf.size())
        return funcs;

    auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(b + expFileOff);

    DWORD namesOff    = rvaToOffset(exp->AddressOfNames);
    DWORD ordOff      = rvaToOffset(exp->AddressOfNameOrdinals);
    DWORD funcsOff    = rvaToOffset(exp->AddressOfFunctions);

    if (!namesOff || !ordOff || !funcsOff) return funcs;

    auto* names    = (const DWORD*)(b + namesOff);
    auto* ordinals = (const WORD*) (b + ordOff);
    auto* funcRVAs = (const DWORD*)(b + funcsOff);

    // Collect all function RVAs to detect boundaries (sort them)
    std::vector<DWORD> allRVAs;
    for (DWORD i = 0; i < exp->NumberOfFunctions; i++)
        if (funcRVAs[i]) allRVAs.push_back(funcRVAs[i]);
    std::sort(allRVAs.begin(), allRVAs.end());

    static const size_t MAX_FUNC_SIZE = 4096;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nameOff = rvaToOffset(names[i]);
        if (!nameOff || nameOff >= peBuf.size()) continue;
        std::string name = (const char*)(b + nameOff);

        DWORD funcRVA    = funcRVAs[ordinals[i]];
        DWORD codeOffset = rvaToOffset(funcRVA);
        if (!codeOffset || codeOffset >= peBuf.size()) continue;

        const BYTE* code = b + codeOffset;

        // Estimate function size: scan until RET (0xC3/0xC2) or next export RVA
        // or MAX_FUNC_SIZE bytes
        size_t maxSize = MAX_FUNC_SIZE;

        // Find next RVA after funcRVA
        auto it = std::upper_bound(allRVAs.begin(), allRVAs.end(), funcRVA);
        if (it != allRVAs.end()) {
            DWORD nextRVA = *it;
            DWORD nextOff = rvaToOffset(nextRVA);
            if (nextOff > codeOffset)
                maxSize = std::min(maxSize, (size_t)(nextOff - codeOffset));
        }
        maxSize = std::min(maxSize, peBuf.size() - codeOffset);

        size_t funcSize = maxSize;
        for (size_t j = 0; j < maxSize; j++) {
            if (code[j] == 0xC3 || code[j] == 0xC2) {
                funcSize = j + 1;
                break;
            }
        }

        uint32_t hash = mnemonicHash(code, funcSize);
        funcs.push_back({ name, funcRVA, hash, funcSize });
    }

    return funcs;
}

// ---------- Match status ----------
enum MatchStatus { UNCHANGED, CHANGED, ADDED, REMOVED };

struct MatchResult {
    std::string name;
    DWORD       rvaOld, rvaNew;
    uint32_t    hashOld, hashNew;
    MatchStatus status;
};

// ---------- matchFunctions ----------
std::vector<MatchResult> matchFunctions(
    const std::vector<FuncInfo>& funcsA,
    const std::vector<FuncInfo>& funcsB)
{
    std::vector<MatchResult> results;

    // Build name->FuncInfo maps
    std::map<std::string, FuncInfo> mapA, mapB;
    for (auto& f : funcsA) mapA[f.name] = f;
    for (auto& f : funcsB) mapB[f.name] = f;

    // Walk A: UNCHANGED, CHANGED, or REMOVED
    for (auto& [name, fa] : mapA) {
        if (mapB.count(name)) {
            auto& fb = mapB[name];
            MatchStatus st = (fa.hash == fb.hash) ? UNCHANGED : CHANGED;
            results.push_back({ name, fa.rva, fb.rva,
                                 fa.hash, fb.hash, st });
        } else {
            results.push_back({ name, fa.rva, 0,
                                 fa.hash, 0, REMOVED });
        }
    }

    // Walk B for names not in A: ADDED
    for (auto& [name, fb] : mapB) {
        if (!mapA.count(name))
            results.push_back({ name, 0, fb.rva, 0, fb.hash, ADDED });
    }

    // Sort by name for consistent output
    std::sort(results.begin(), results.end(),
              [](const MatchResult& a, const MatchResult& b){
                  return a.name < b.name; });

    return results;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <old.exe/dll> <new.exe/dll>\n", argv[0]);
        return 1;
    }

    auto bufA = readFile(argv[1]);
    auto bufB = readFile(argv[2]);
    if (bufA.empty() || bufB.empty()) {
        printf("[-] File read error\n"); return 1;
    }

    auto funcsA = parseFunctions(bufA);
    auto funcsB = parseFunctions(bufB);

    if (funcsA.empty() && funcsB.empty()) {
        printf("[-] No exports found in either file (try a DLL with exports)\n");
        return 1;
    }

    printf("[*] Old: %zu exports   New: %zu exports\n",
           funcsA.size(), funcsB.size());

    auto matches = matchFunctions(funcsA, funcsB);
    if (matches.empty()) {
        printf("[=] No functions to compare\n"); return 0;
    }

    int same=0, changed=0, added=0, removed=0;
    printf("\n%-40s  %10s  %10s  %s\n", "Function", "OldHash", "NewHash", "Status");
    printf("%s\n", std::string(80, '-').c_str());

    for (auto& m : matches) {
        const char* st = m.status == UNCHANGED ? "same"
                       : m.status == CHANGED   ? "CHANGED"
                       : m.status == ADDED     ? "ADDED"
                                               : "REMOVED";
        printf("%-40s  %08X    %08X    %s\n",
               m.name.c_str(), m.hashOld, m.hashNew, st);
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
