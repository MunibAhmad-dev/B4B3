// mem_forensics.cpp — memory forensics toolkit
// Compile: g++ -std=c++17 -o mem_forensics.exe mem_forensics.cpp -ldbghelp
// Usage: mem_forensics.exe scan [pid] | strings <pid> | dump <pid> <addr_hex> <size_hex> <out>
//                              hidden | minidump <pid> <out>

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <set>
#include <cmath>

#pragma comment(lib, "dbghelp.lib")

// ─── Shannon entropy helper ───────────────────────────────────────────────────

static double shannon(const uint8_t* d, size_t n) {
    if (!n) return 0.0;
    uint64_t freq[256]{};
    for (size_t i = 0; i < n; ++i) ++freq[d[i]];
    double h = 0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / n;
        h -= p * log2(p);
    }
    return h;
}

// ─── scan [pid] ───────────────────────────────────────────────────────────────

static void cmd_scan(DWORD pid) {
    HANDLE hProc;
    if (pid == 0) {
        hProc = GetCurrentProcess();
        pid   = GetCurrentProcessId();
        printf("[*] Scanning self (PID=%lu)\n\n", pid);
    } else {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pid);
        if (!hProc) { fprintf(stderr, "Cannot open PID %lu: %lu\n", pid, GetLastError()); return; }
        printf("[*] Scanning PID %lu\n\n", pid);
    }

    printf("%-18s  %-10s  %-6s  %-8s  %-6s  %s\n",
           "Base","Size","State","Protect","Entropy","Flags");
    printf("%s\n", std::string(80, '-').c_str());

    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* addr = nullptr;
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd = 0;
            ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd);
            if (rd > 0) {
                double e = shannon(buf.data(), rd);
                bool mz  = (rd >= 2 && buf[0] == 'M' && buf[1] == 'Z');
                bool high_entropy = e > 6.8;

                printf("0x%-16p  %-10zu  %-6s  0x%-6X  %-6.2f %s%s\n",
                       mbi.BaseAddress, mbi.RegionSize,
                       mbi.State == MEM_COMMIT ? "COM" : "?",
                       mbi.Protect, e,
                       mz ? " [MZ]" : "",
                       high_entropy && mbi.Protect & PAGE_EXECUTE_READ ? " [EXEC+HIGH-E]" : "");
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (!mbi.RegionSize) break;
    }
    if (pid != GetCurrentProcessId()) CloseHandle(hProc);
}

// ─── strings <pid> ────────────────────────────────────────────────────────────

static void cmd_strings(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { fprintf(stderr, "Cannot open PID %lu: %lu\n", pid, GetLastError()); return; }
    printf("[*] Strings from PID %lu\n\n", pid);

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    int count = 0;
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd = 0;
            ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd);
            std::string cur;
            for (size_t i = 0; i < rd; ++i) {
                uint8_t c = buf[i];
                if (c >= 0x20 && c < 0x7F) cur += (char)c;
                else {
                    if (cur.size() >= 5) {
                        printf("0x%p  %s\n",
                               (uint8_t*)mbi.BaseAddress + (i - cur.size()), cur.c_str());
                        ++count;
                    }
                    cur.clear();
                }
            }
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (!mbi.RegionSize) break;
    }
    CloseHandle(hProc);
    printf("\nTotal: %d strings\n", count);
}

// ─── dump <pid> <addr_hex> <size_hex> <out> ──────────────────────────────────

static void cmd_dump(DWORD pid, const char* addr_s, const char* size_s, const char* out) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { fprintf(stderr, "Cannot open PID %lu: %lu\n", pid, GetLastError()); return; }

    uintptr_t addr = (uintptr_t)strtoull(addr_s, nullptr, 16);
    size_t    sz   = (size_t)strtoul(size_s, nullptr, 16);

    std::vector<uint8_t> buf(sz);
    SIZE_T rd = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, buf.data(), sz, &rd)) {
        fprintf(stderr, "ReadProcessMemory failed: %lu\n", GetLastError());
        CloseHandle(hProc); return;
    }
    CloseHandle(hProc);

    FILE* f = fopen(out, "wb");
    if (!f) { fprintf(stderr, "Cannot write %s\n", out); return; }
    fwrite(buf.data(), 1, rd, f);
    fclose(f);
    printf("[+] Dumped %zu bytes from 0x%llX -> %s\n", rd, (unsigned long long)addr, out);
}

// ─── hidden: Toolhelp vs brute-force PID diff ────────────────────────────────

static void cmd_hidden() {
    printf("[*] Hidden process detection (Toolhelp vs brute-force)\n\n");

    std::set<DWORD> snap_pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do { snap_pids.insert(pe.th32ProcessID); }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    int hidden = 0;
    for (DWORD pid = 4; pid < 65536; pid += 4) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            if (snap_pids.find(pid) == snap_pids.end()) {
                char name[MAX_PATH]{};
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameA(h, 0, name, &sz);
                printf("  [HIDDEN] PID=%-6lu  %s\n", pid, name);
                ++hidden;
            }
            CloseHandle(h);
        }
    }
    printf("\nHidden PIDs found: %d\n", hidden);
}

// ─── minidump <pid> <out> ─────────────────────────────────────────────────────

static void cmd_minidump(DWORD pid, const char* out) {
    printf("[*] Minidump PID %lu -> %s\n", pid, out);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError()); return; }

    HANDLE hFile = CreateFileA(out, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile failed: %lu\n", GetLastError());
        CloseHandle(hProc); return;
    }

    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory,
                                nullptr, nullptr, nullptr);
    if (ok) printf("[+] Dump written: %s\n", out);
    else    fprintf(stderr, "[!] MiniDumpWriteDump failed: %lu\n", GetLastError());

    CloseHandle(hFile);
    CloseHandle(hProc);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  mem_forensics.exe scan [pid]\n"
               "  mem_forensics.exe strings <pid>\n"
               "  mem_forensics.exe dump <pid> <addr_hex> <size_hex> <outfile>\n"
               "  mem_forensics.exe hidden\n"
               "  mem_forensics.exe minidump <pid> <outfile>\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if (cmd == "scan") {
        DWORD pid = (argc >= 3) ? (DWORD)strtoul(argv[2], nullptr, 10) : 0;
        cmd_scan(pid);
    } else if (cmd == "strings" && argc >= 3) {
        cmd_strings((DWORD)strtoul(argv[2], nullptr, 10));
    } else if (cmd == "dump" && argc >= 6) {
        cmd_dump((DWORD)strtoul(argv[2], nullptr, 10), argv[3], argv[4], argv[5]);
    } else if (cmd == "hidden") {
        cmd_hidden();
    } else if (cmd == "minidump" && argc >= 4) {
        cmd_minidump((DWORD)strtoul(argv[2], nullptr, 10), argv[3]);
    } else {
        fprintf(stderr, "Unknown command or missing args.\n"); return 1;
    }
    return 0;
}
