// solutions/sol02_process_monitor.cpp
// Module 12 Solution 02 — Process Monitor with Behavioral Scoring (complete)
// Compile: g++ -std=c++17 -Wall -o sol02.exe sol02_process_monitor.cpp -lpsapi
//
// Modes:
//   sol02.exe list              -- snapshot all processes with full detail
//   sol02.exe watch <ms>        -- continuous diff + behavioral scoring
//
// Behavioral flags applied to new processes:
//   TEMP_PATH          -- image path in %TEMP%, %APPDATA%, or Downloads
//   HOLLOW_CANDIDATE   -- known system exe name but not in System32/SysWOW64
//   SUSPICIOUS_PARENT  -- shell/script process spawned by an Office application
//   UNSIGNED           -- no VERSIONINFO resource in the PE (lightweight check)

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>

// ============================================================ String helpers

static std::string str_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string path_basename(const std::string& path) {
    auto p = path.find_last_of("\\/");
    return (p == std::string::npos) ? path : path.substr(p + 1);
}

// ============================================================= Process info

struct ProcInfo {
    DWORD       pid;
    DWORD       ppid;
    std::string name;          // exe filename
    std::string path;          // full image path
    std::string user;          // DOMAIN\user
    ULONGLONG   kernel_time;   // 100-ns units
    ULONGLONG   user_time;
    ULONGLONG   creation_time; // FILETIME as ULONGLONG
    SIZE_T      working_set;   // bytes
    std::vector<std::string> flags;
};

using ProcMap = std::map<DWORD, ProcInfo>;

// ======================================================= Per-PID accessors

static std::string get_full_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "<denied>";
    char buf[MAX_PATH] = {};
    DWORD sz = sizeof buf;
    QueryFullProcessImageNameA(h, 0, buf, &sz);
    CloseHandle(h);
    return buf[0] ? std::string(buf) : "<unknown>";
}

static std::string get_proc_user(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return "<denied>";

    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return "<no_token>";
    }
    CloseHandle(hProc);

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hTok, TokenUser, buf.data(), needed, &needed)) {
        CloseHandle(hTok);
        return "<token_err>";
    }
    CloseHandle(hTok);

    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    char name[256] = {}, domain[256] = {};
    DWORD nLen = 256, dLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidA(nullptr, tu->User.Sid, name, &nLen, domain, &dLen, &use))
        return "<lookup_err>";

    return std::string(domain) + "\\" + name;
}

static void get_times(DWORD pid,
                      ULONGLONG& kernel, ULONGLONG& user, ULONGLONG& creation) {
    kernel = user = creation = 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    FILETIME cr, ex, k, u;
    if (GetProcessTimes(h, &cr, &ex, &k, &u)) {
        kernel   = (static_cast<ULONGLONG>(k.dwHighDateTime) << 32) | k.dwLowDateTime;
        user     = (static_cast<ULONGLONG>(u.dwHighDateTime) << 32) | u.dwLowDateTime;
        creation = (static_cast<ULONGLONG>(cr.dwHighDateTime) << 32) | cr.dwLowDateTime;
    }
    CloseHandle(h);
}

static SIZE_T get_ws(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return 0;
    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof pmc;
    GetProcessMemoryInfo(h, &pmc, sizeof pmc);
    CloseHandle(h);
    return pmc.WorkingSetSize;
}

// =========================================================== Behavioral sets

static const std::set<std::string> SYSTEM32_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "spoolsv.exe", "winlogon.exe", "smss.exe", "dllhost.exe",
    "taskhostw.exe", "conhost.exe", "lsm.exe"
};

static const std::set<std::string> OFFICE_NAMES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "mspub.exe", "msaccess.exe", "visio.exe", "onenote.exe"
};

static const std::set<std::string> SHELL_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe", "wmic.exe"
};

static std::vector<std::string> score_proc(const ProcInfo& p,
                                            const ProcMap& all) {
    std::vector<std::string> flags;
    std::string plow = str_lower(p.path);
    std::string nlow = str_lower(p.name);

    // TEMP_PATH: running from suspicious user-writable locations
    const char* suspects[] = {
        "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
        "\\downloads\\", "\\desktop\\", "\\public\\"
    };
    for (const char* s : suspects) {
        if (plow.find(s) != std::string::npos) {
            flags.push_back("TEMP_PATH");
            break;
        }
    }

    // HOLLOW_CANDIDATE: system exe name but not in system32/syswow64
    if (SYSTEM32_NAMES.count(nlow)) {
        if (plow.find("\\system32\\") == std::string::npos &&
            plow.find("\\syswow64\\") == std::string::npos &&
            p.path[0] != '<') {
            flags.push_back("HOLLOW_CANDIDATE");
        }
    }

    // SUSPICIOUS_PARENT: shell/script process whose parent is an Office app
    auto it = all.find(p.ppid);
    if (it != all.end()) {
        std::string parlow = str_lower(it->second.name);
        if (OFFICE_NAMES.count(parlow) && SHELL_NAMES.count(nlow))
            flags.push_back("SUSPICIOUS_PARENT");
    }

    // UNSIGNED: no VERSIONINFO resource (simple heuristic)
    if (p.path[0] != '<') {
        DWORD dummy = 0;
        if (GetFileVersionInfoSizeA(p.path.c_str(), &dummy) == 0)
            flags.push_back("UNSIGNED");
    }

    return flags;
}

// ======================================================= Snapshot builder

static ProcMap build_snapshot(bool full_detail) {
    ProcMap result;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof pe;

    if (Process32First(hSnap, &pe)) {
        do {
            ProcInfo info;
            info.pid  = pe.th32ProcessID;
            info.ppid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            if (full_detail && info.pid > 4) {
                info.path        = get_full_path(info.pid);
                info.user        = get_proc_user(info.pid);
                info.working_set = get_ws(info.pid);
                get_times(info.pid, info.kernel_time, info.user_time,
                          info.creation_time);
            }
            result[info.pid] = info;
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return result;
}

// ========================================================== Time formatting

static std::string filetime_str(ULONGLONG ft100ns) {
    if (!ft100ns) return "N/A";
    FILETIME ft;
    ft.dwLowDateTime  = static_cast<DWORD>(ft100ns & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(ft100ns >> 32);
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    char buf[24];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string now_str() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ================================================================ list mode

static void mode_list() {
    ProcMap procs = build_snapshot(true);

    // Header
    std::cout << std::left
              << std::setw(7)  << "PID"
              << std::setw(7)  << "PPID"
              << std::setw(24) << "Name"
              << std::setw(32) << "User"
              << std::setw(10) << "WS(MB)"
              << std::setw(22) << "Created"
              << "Path\n"
              << std::string(110, '-') << "\n";

    for (const auto& [pid, p] : procs) {
        std::string nm   = p.name.size() > 23 ? p.name.substr(0,23) : p.name;
        std::string usr  = p.user.size() > 31 ? p.user.substr(0,31) : p.user;
        std::cout << std::left
                  << std::setw(7)  << pid
                  << std::setw(7)  << p.ppid
                  << std::setw(24) << nm
                  << std::setw(32) << usr
                  << std::setw(10) << (p.working_set / (1024*1024))
                  << std::setw(22) << filetime_str(p.creation_time)
                  << p.path << "\n";
    }
    std::cout << "\n" << procs.size() << " process(es).\n";
}

// =============================================================== watch mode

static void mode_watch(int interval_ms) {
    std::cout << "[ProcWatch] Monitoring every " << interval_ms
              << "ms. Ctrl+C to stop.\n\n";
    ProcMap prev = build_snapshot(true);
    std::cout << "[ProcWatch] Initial: " << prev.size() << " process(es).\n\n";

    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        ProcMap curr = build_snapshot(true);

        // Score new processes
        for (auto& [pid, p] : curr) {
            if (prev.find(pid) != prev.end()) continue;

            ProcInfo& info = curr[pid];
            info.flags = score_proc(info, curr);

            std::cout << "[" << now_str() << "] [+] PID=" << pid
                      << " " << info.name
                      << " (PPID=" << info.ppid
                      << " user=" << info.user
                      << " path=" << info.path << ")";

            if (!info.flags.empty()) {
                std::cout << "  !! FLAGS:";
                for (const auto& f : info.flags)
                    std::cout << " " << f;
            }
            std::cout << "\n";
        }

        for (const auto& [pid, p] : prev) {
            if (curr.find(pid) == curr.end())
                std::cout << "[" << now_str() << "] [-] PID=" << pid
                          << " " << p.name << "\n";
        }

        prev = curr;
    }
}

// ================================================================= main =====

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sol02.exe list\n"
                  << "  sol02.exe watch <interval_ms>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "list") {
        mode_list();
        return 0;
    }
    if (cmd == "watch" && argc >= 3) {
        mode_watch(std::stoi(argv[2]));
        return 0;
    }

    std::cerr << "Unknown command or missing arguments.\n";
    return 1;
}
