// solutions/sol04_memory_scanner.cpp
// Module 12 Solution 04 — Memory Scanner for Injected Code (complete)
// Compile: g++ -std=c++17 -Wall -o sol04.exe sol04_memory_scanner.cpp
//
// Modes:
//   sol04.exe scan [pid]                         -- scan one or all processes
//   sol04.exe dump <pid> <addr_hex> <sz_hex> <out> -- dump a region to file
//
// Detection logic per MEM_PRIVATE+executable region:
//   PE_INJECT          -- first two bytes are 'MZ' (PE reflectively loaded)
//   SHELLCODE_CANDIDATE -- known shellcode patterns (prologue, syscall stub, NOP sled)
//   HIGH_ENTROPY       -- Shannon entropy > 7.0 on first 512 bytes (packed/encrypted)
//   EXEC_PRIVATE       -- executable private page not matching above (still notable)

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>

// ======================================================= Protection helpers

static bool is_exec(DWORD prot) {
    return (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static std::string prot_str(DWORD prot) {
    switch (prot & 0xFF) {
        case PAGE_EXECUTE:            return "X   ";
        case PAGE_EXECUTE_READ:       return "RX  ";
        case PAGE_EXECUTE_READWRITE:  return "RWX ";
        case PAGE_EXECUTE_WRITECOPY:  return "RWXC";
        default:                       return "?   ";
    }
}

// ============================================================= Entropy

static double shannon_entropy(const BYTE* data, size_t len) {
    if (!len) return 0.0;
    int freq[256] = {};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    double e = 0.0;
    const double n = static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = freq[i] / n;
        e -= p * std::log2(p);
    }
    return e;
}

// ========================================================= Pattern matching

struct PatternHit {
    std::string label;
    size_t      offset;
};

static std::vector<PatternHit> find_patterns(const BYTE* buf, size_t len) {
    std::vector<PatternHit> hits;

    // x64 function prologue: 48 83 EC ?? (sub rsp, imm8)
    for (size_t i = 0; i + 3 <= len; ++i) {
        if (buf[i] == 0x48 && buf[i+1] == 0x83 && buf[i+2] == 0xEC) {
            hits.push_back({"x64_PROLOGUE", i});
            break;
        }
    }

    // Syscall stub: 4C 8B D1 (mov r10, rcx)  common in direct-syscall loaders
    for (size_t i = 0; i + 2 <= len; ++i) {
        if (buf[i] == 0x4C && buf[i+1] == 0x8B && buf[i+2] == 0xD1) {
            hits.push_back({"SYSCALL_STUB", i});
            break;
        }
    }

    // NOP sled: 8+ consecutive 0x90
    {
        int run = 0;
        for (size_t i = 0; i < len; ++i) {
            if (buf[i] == 0x90) { if (++run >= 8) { hits.push_back({"NOP_SLED", i - 7}); break; } }
            else run = 0;
        }
    }

    // CALL +0 trick: E8 00 00 00 00 (msfvenom relative call stub)
    for (size_t i = 0; i + 4 <= len; ++i) {
        if (buf[i] == 0xE8 && buf[i+1] == 0 && buf[i+2] == 0 &&
            buf[i+3] == 0 && buf[i+4] == 0) {
            hits.push_back({"CALL_ZERO_NEXT", i});
            break;
        }
    }

    return hits;
}

// ========================================================== Region analysis

struct RegionResult {
    LPVOID   base;
    SIZE_T   size;
    DWORD    prot;
    std::string classification;  // PE_INJECT / SHELLCODE_CANDIDATE / HIGH_ENTROPY / EXEC_PRIVATE
    double   entropy;
    std::vector<PatternHit> patterns;
};

static RegionResult analyse_region(HANDLE hProc, LPVOID base, SIZE_T sz, DWORD prot) {
    RegionResult r{};
    r.base = base;
    r.size = sz;
    r.prot = prot;

    const SIZE_T SAMPLE = 512;
    BYTE buf[512] = {};
    SIZE_T got = 0;

    if (!ReadProcessMemory(hProc, base, buf, std::min(sz, SAMPLE), &got) || !got) {
        r.classification = "UNREADABLE";
        return r;
    }

    r.entropy = shannon_entropy(buf, got);

    // MZ header -> PE injected or reflectively loaded
    if (got >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
        r.classification = "PE_INJECT";
        return r;
    }

    // Shellcode patterns
    r.patterns = find_patterns(buf, got);
    if (!r.patterns.empty()) {
        r.classification = "SHELLCODE_CANDIDATE";
        return r;
    }

    // High entropy -> packed or encrypted payload
    if (r.entropy > 7.0) {
        r.classification = "HIGH_ENTROPY";
        return r;
    }

    r.classification = "EXEC_PRIVATE";
    return r;
}

// ======================================================= PID -> name map

static std::unordered_map<DWORD, std::string> build_name_map() {
    std::unordered_map<DWORD, std::string> m;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;
    if (Process32First(hSnap, &pe))
        do { m[pe.th32ProcessID] = pe.szExeFile; }
        while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    return m;
}

// ========================================================== Scan one process

static int scan_one(DWORD pid, const std::string& name) {
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    std::vector<RegionResult> results;
    ULONG_PTR addr = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr),
                          &mbi, sizeof mbi) == sizeof mbi) {
        if (mbi.State == MEM_COMMIT &&
            mbi.Type  == MEM_PRIVATE &&
            is_exec(mbi.Protect)) {

            RegionResult r = analyse_region(
                hProc, mbi.BaseAddress, mbi.RegionSize, mbi.Protect);

            // Always report everything except plain EXEC_PRIVATE
            if (r.classification != "EXEC_PRIVATE" &&
                r.classification != "UNREADABLE")
                results.push_back(r);
        }

        ULONG_PTR next = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)
                         + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    CloseHandle(hProc);

    if (!results.empty()) {
        std::cout << "\n[PID=" << std::setw(6) << pid << "] " << name << "\n";
        for (const auto& r : results) {
            std::cout << "  Base=0x" << std::hex << std::setw(16)
                      << std::setfill('0')
                      << reinterpret_cast<uintptr_t>(r.base)
                      << std::dec << std::setfill(' ')
                      << "  Sz=" << std::setw(8) << r.size
                      << "  " << prot_str(r.prot)
                      << "  H=" << std::fixed << std::setprecision(2) << r.entropy
                      << "  [" << r.classification << "]";
            for (const auto& p : r.patterns)
                std::cout << " " << p.label << "@+" << std::hex << p.offset << std::dec;
            std::cout << "\n";
        }
        std::cout << "  >> " << results.size() << " suspicious region(s) in " << name << "\n";
    }
    return static_cast<int>(results.size());
}

// ================================================================ scan mode

static void mode_scan(DWORD target_pid) {
    auto names = build_name_map();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Snapshot failed: " << GetLastError() << "\n";
        return;
    }

    int total_procs = 0, total_regions = 0;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;

    if (Process32First(hSnap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid <= 4) continue;
            if (target_pid && pid != target_pid) continue;

            std::string nm = names.count(pid) ? names[pid] : "?";
            int n = scan_one(pid, nm);
            total_regions += n;
            ++total_procs;
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    std::cout << "\n[MemScan] Scanned " << total_procs << " process(es), "
              << total_regions << " suspicious region(s) total.\n";
}

// ================================================================ dump mode

static void mode_dump(DWORD pid, uintptr_t base_addr, SIZE_T sz,
                      const std::string& outfile) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        std::cerr << "[DUMP] Cannot open PID " << pid
                  << ": " << GetLastError() << "\n";
        return;
    }

    std::vector<BYTE> buf(sz, 0);
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(
        hProc, reinterpret_cast<LPCVOID>(base_addr), buf.data(), sz, &got);
    CloseHandle(hProc);

    if (!ok || !got) {
        std::cerr << "[DUMP] ReadProcessMemory failed: " << GetLastError() << "\n";
        return;
    }
    buf.resize(got);

    std::ofstream ofs(outfile, std::ios::binary);
    if (!ofs) {
        std::cerr << "[DUMP] Cannot write: " << outfile << "\n";
        return;
    }
    ofs.write(reinterpret_cast<const char*>(buf.data()),
              static_cast<std::streamsize>(buf.size()));

    std::cout << "[DUMP] Written " << got << " bytes from PID=" << pid
              << " addr=0x" << std::hex << base_addr << std::dec
              << " to " << outfile << "\n";
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sol04.exe scan [pid]\n"
                  << "  sol04.exe dump <pid> <address_hex> <size_hex> <outfile>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "scan") {
        DWORD pid = (argc >= 3) ? static_cast<DWORD>(std::stoul(argv[2])) : 0;
        mode_scan(pid);
        return 0;
    }

    if (cmd == "dump" && argc >= 6) {
        DWORD     pid  = static_cast<DWORD>(std::stoul(argv[2]));
        uintptr_t addr = static_cast<uintptr_t>(std::stoull(argv[3], nullptr, 16));
        SIZE_T    sz   = static_cast<SIZE_T>(std::stoull(argv[4], nullptr, 16));
        mode_dump(pid, addr, sz, argv[5]);
        return 0;
    }

    std::cerr << "Unknown command or missing arguments.\n";
    return 1;
}
