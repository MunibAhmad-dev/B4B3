// blue_team_monitor.cpp
// Blue Team Monitoring Dashboard — Unified Security Monitor
// Compile: g++ -std=c++17 -Wall -o blue_team_monitor.exe blue_team_monitor.cpp
//          -ladvapi32 -lbcrypt -lpsapi -liphlpapi
//
// Usage:
//   blue_team_monitor.exe watch              -- run all monitors simultaneously
//   blue_team_monitor.exe fim <dir>          -- file integrity monitor for a directory
//   blue_team_monitor.exe procs              -- process anomaly detector (continuous)
//   blue_team_monitor.exe netconn            -- network connection tracker (continuous)
//   blue_team_monitor.exe memscan [pid]      -- memory injection scanner (one-shot)
//   blue_team_monitor.exe report             -- full security snapshot (one-shot)
//
// Alert format: [HH:MM:SS] [MODULE] [SEVERITY] description
//   SEVERITY: INFO | WARN | ALERT
//
// All four monitor threads share no mutable state — each owns its own data
// structures.  Console output is serialized via g_print_mutex.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <atomic>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

// ===================================================================
//  GLOBALS
// ===================================================================

static std::mutex g_print_mutex;
static std::atomic<bool> g_running{true};

// ===================================================================
//  UTILITY
// ===================================================================

static std::string str_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string now_ts() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d",
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string now_full() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[24];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// Thread-safe console print helper
static void emit(const std::string& ts,
                 const std::string& module,
                 const std::string& sev,
                 const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_print_mutex);
    std::cout << "[" << ts << "] [" << module << "] [" << sev << "] " << msg << "\n";
}

// ===================================================================
//  MODULE 1 — FILE INTEGRITY MONITOR
// ===================================================================

static uint32_t g_crc_table[256];
static bool     g_crc_ready = false;

static void build_crc_table() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_ready = true;
}

static uint32_t file_crc32(const std::string& path) {
    if (!g_crc_ready) build_crc_table();
    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;
    uint32_t crc = 0xFFFFFFFFUL;
    BYTE buf[65536];
    DWORD got;
    while (ReadFile(hf, buf, sizeof buf, &got, nullptr) && got)
        for (DWORD i = 0; i < got; ++i)
            crc = (crc >> 8) ^ g_crc_table[(crc ^ buf[i]) & 0xFF];
    CloseHandle(hf);
    return crc ^ 0xFFFFFFFFUL;
}

using FimMap = std::map<std::string, uint32_t>;

static void fim_scan_dir(const std::string& dir, FimMap& out) {
    std::string pat = dir + "\\*";
    WIN32_FIND_DATA fd;
    HANDLE h = FindFirstFileExA(pat.c_str(), FindExInfoBasic, &fd,
                                FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::string nm(fd.cFileName);
        if (nm == "." || nm == "..") continue;
        std::string full = dir + "\\" + nm;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            fim_scan_dir(full, out);
        else
            out[full] = file_crc32(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void fim_thread(const std::string& dir, int interval_sec) {
    FimMap baseline;
    fim_scan_dir(dir, baseline);
    {
        std::lock_guard<std::mutex> lk(g_print_mutex);
        std::cout << "[FIM] Baseline: " << baseline.size()
                  << " files in " << dir << "\n";
    }

    while (g_running) {
        for (int i = 0; i < interval_sec && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        FimMap curr;
        fim_scan_dir(dir, curr);

        for (const auto& [path, hash] : curr) {
            auto it = baseline.find(path);
            if (it == baseline.end())
                emit(now_ts(), "FIM", "WARN", "NEW      " + path);
            else if (it->second != hash && hash != 0xFFFFFFFF)
                emit(now_ts(), "FIM", "ALERT", "MODIFIED " + path);
        }
        for (const auto& [path, hash] : baseline)
            if (curr.find(path) == curr.end())
                emit(now_ts(), "FIM", "WARN", "DELETED  " + path);

        baseline = curr;
    }
}

// ===================================================================
//  MODULE 2 — PROCESS MONITOR
// ===================================================================

struct ProcRec {
    DWORD       pid, ppid;
    std::string name, path, user;
};

using ProcSnap = std::map<DWORD, ProcRec>;

static std::string proc_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "<denied>";
    char buf[MAX_PATH] = {};
    DWORD sz = sizeof buf;
    QueryFullProcessImageNameA(h, 0, buf, &sz);
    CloseHandle(h);
    return buf[0] ? std::string(buf) : "<unknown>";
}

static std::string proc_user(DWORD pid) {
    HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hP) return "<denied>";
    HANDLE hT = nullptr;
    if (!OpenProcessToken(hP, TOKEN_QUERY, &hT)) { CloseHandle(hP); return "<no_tok>"; }
    CloseHandle(hP);
    DWORD need = 0;
    GetTokenInformation(hT, TokenUser, nullptr, 0, &need);
    std::vector<BYTE> buf(need);
    if (!GetTokenInformation(hT, TokenUser, buf.data(), need, &need)) {
        CloseHandle(hT); return "<tok_err>";
    }
    CloseHandle(hT);
    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    char nm[256] = {}, dom[256] = {};
    DWORD nL = 256, dL = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidA(nullptr, tu->User.Sid, nm, &nL, dom, &dL, &use))
        return "<lookup_err>";
    return std::string(dom) + "\\" + nm;
}

static ProcSnap proc_snapshot(bool full) {
    ProcSnap r;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return r;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof pe;
    if (Process32First(h, &pe))
        do {
            ProcRec rec;
            rec.pid = pe.th32ProcessID; rec.ppid = pe.th32ParentProcessID;
            rec.name = pe.szExeFile;
            if (full && rec.pid > 4) {
                rec.path = proc_path(rec.pid);
                rec.user = proc_user(rec.pid);
            }
            r[rec.pid] = rec;
        } while (Process32Next(h, &pe));
    CloseHandle(h);
    return r;
}

static const std::set<std::string> SYSTEM32_EXE = {
    "svchost.exe","lsass.exe","csrss.exe","wininit.exe","services.exe",
    "spoolsv.exe","winlogon.exe","smss.exe","dllhost.exe","conhost.exe"
};
static const std::set<std::string> OFFICE_EXE = {
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe"
};
static const std::set<std::string> SHELL_EXE = {
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe",
    "cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe"
};

static std::string score_proc(const ProcRec& p, const ProcSnap& all) {
    std::string flags;
    std::string plow = str_lower(p.path);
    std::string nlow = str_lower(p.name);

    for (const char* s : {"\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
                           "\\downloads\\", "\\public\\"})
        if (plow.find(s) != std::string::npos) { flags += " TEMP_PATH"; break; }

    if (SYSTEM32_EXE.count(nlow) &&
        plow.find("\\system32\\") == std::string::npos &&
        plow.find("\\syswow64\\") == std::string::npos &&
        p.path[0] != '<')
        flags += " HOLLOW_CANDIDATE";

    auto it = all.find(p.ppid);
    if (it != all.end()) {
        std::string parlow = str_lower(it->second.name);
        if (OFFICE_EXE.count(parlow) && SHELL_EXE.count(nlow))
            flags += " SUSPICIOUS_PARENT";
    }

    if (p.path[0] != '<') {
        DWORD d;
        if (GetFileVersionInfoSizeA(p.path.c_str(), &d) == 0)
            flags += " UNSIGNED";
    }
    return flags;
}

static void proc_thread(int interval_ms) {
    ProcSnap prev = proc_snapshot(true);
    {
        std::lock_guard<std::mutex> lk(g_print_mutex);
        std::cout << "[PROCS] Initial: " << prev.size() << " process(es).\n";
    }

    while (g_running) {
        for (int i = 0; i < interval_ms / 500 && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

        ProcSnap curr = proc_snapshot(true);

        for (auto& [pid, p] : curr) {
            if (prev.find(pid) != prev.end()) continue;
            std::string flags = score_proc(p, curr);
            std::string sev   = flags.empty() ? "INFO" : "ALERT";
            emit(now_ts(), "PROCS", sev,
                 "[+] PID=" + std::to_string(pid) + " " + p.name +
                 " PPID=" + std::to_string(p.ppid) +
                 " user=" + p.user +
                 " path=" + p.path +
                 (flags.empty() ? "" : " !!" + flags));
        }
        for (const auto& [pid, p] : prev)
            if (curr.find(pid) == curr.end())
                emit(now_ts(), "PROCS", "INFO",
                     "[-] PID=" + std::to_string(pid) + " " + p.name);

        prev = curr;
    }
}

// ===================================================================
//  MODULE 3 — NETWORK MONITOR
// ===================================================================

static std::unordered_map<DWORD, std::string> g_net_pid_names;

static void net_refresh_pids() {
    g_net_pid_names.clear();
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof pe;
    if (Process32First(h, &pe))
        do { g_net_pid_names[pe.th32ProcessID] = pe.szExeFile; }
        while (Process32Next(h, &pe));
    CloseHandle(h);
}

static std::string net_pid_name(DWORD pid) {
    auto it = g_net_pid_names.find(pid);
    return it != g_net_pid_names.end() ? it->second : "?";
}

static std::string ipv4_s(DWORD a, DWORD p) {
    struct in_addr in; in.s_addr = a;
    char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &in, ip, sizeof ip);
    return std::string(ip) + ":" + std::to_string(ntohs((u_short)p));
}

struct NetConn {
    std::string local, remote, state;
    DWORD pid;
    bool is_udp;
    std::string key() const {
        return local + "|" + remote + "|" + state + "|" + std::to_string(pid);
    }
};
using NetMap = std::map<std::string, NetConn>;

static const char* tcp_st(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_ESTAB:  return "ESTABLISHED";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default: return "OTHER";
    }
}

static NetMap net_snapshot() {
    net_refresh_pids();
    NetMap out;

    // TCP4
    {
        DWORD sz = 0;
        GetExtendedTcpTable(nullptr, &sz, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz + 256);
        if (GetExtendedTcpTable(buf.data(), &sz, TRUE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                NetConn c;
                c.local  = ipv4_s(r.dwLocalAddr,  r.dwLocalPort);
                c.remote = ipv4_s(r.dwRemoteAddr, r.dwRemotePort);
                c.state  = tcp_st(r.dwState);
                c.pid    = r.dwOwningPid;
                c.is_udp = false;
                out[c.key()] = c;
            }
        }
    }
    // UDP4 (listening endpoints only — remote is wildcard)
    {
        DWORD sz = 0;
        GetExtendedUdpTable(nullptr, &sz, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> buf(sz + 256);
        if (GetExtendedUdpTable(buf.data(), &sz, TRUE, AF_INET,
                                 UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                NetConn c;
                c.local  = ipv4_s(r.dwLocalAddr, r.dwLocalPort);
                c.remote = "*:*"; c.state = "UDP";
                c.pid    = r.dwOwningPid; c.is_udp = true;
                out[c.key()] = c;
            }
        }
    }
    return out;
}

static const std::set<int> NET_BAD_PORTS = {
    4444, 4445, 5555, 31337, 1337, 8888, 9999, 12345, 54321
};
static const std::set<std::string> NET_UNUSUAL_PROCS = {
    "regsvr32.exe","mshta.exe","wscript.exe","cscript.exe",
    "msiexec.exe","rundll32.exe","certutil.exe"
};

static int port_of(const std::string& ap) {
    auto p = ap.rfind(':');
    try { return p != std::string::npos ? std::stoi(ap.substr(p + 1)) : 0; }
    catch (...) { return 0; }
}

static void net_thread(int interval_sec) {
    NetMap prev = net_snapshot();
    {
        std::lock_guard<std::mutex> lk(g_print_mutex);
        std::cout << "[NETCONN] Initial: " << prev.size() << " connection(s).\n";
    }

    while (g_running) {
        for (int i = 0; i < interval_sec && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        NetMap curr = net_snapshot();

        for (const auto& [k, c] : curr) {
            if (prev.find(k) != prev.end()) continue;
            std::string nm    = net_pid_name(c.pid);
            std::string flags;
            if (!c.is_udp && c.state == "ESTABLISHED") {
                if (NET_BAD_PORTS.count(port_of(c.remote)))
                    flags += " BAD_PORT";
                if (NET_UNUSUAL_PROCS.count(str_lower(nm)))
                    flags += " UNUSUAL_PROCESS";
            }
            std::string sev = flags.empty() ? "INFO" : "ALERT";
            if (c.state == "LISTEN")
                emit(now_ts(), "NETCONN", "INFO",
                     "[LISTENING] PID=" + std::to_string(c.pid) +
                     " " + nm + " " + c.local);
            else
                emit(now_ts(), "NETCONN", sev,
                     "[NEW] PID=" + std::to_string(c.pid) +
                     " " + nm + " " + c.local + " -> " + c.remote +
                     " " + c.state + flags);
        }
        for (const auto& [k, c] : prev)
            if (curr.find(k) == curr.end() && !c.is_udp && c.state == "ESTABLISHED")
                emit(now_ts(), "NETCONN", "INFO",
                     "[CLOSED] PID=" + std::to_string(c.pid) +
                     " " + net_pid_name(c.pid) +
                     " " + c.local + " -> " + c.remote);

        prev = curr;
    }
}

// ===================================================================
//  MODULE 4 — MEMORY SCANNER (one-shot per call)
// ===================================================================

static bool mem_is_exec(DWORD p) {
    return (p & (PAGE_EXECUTE|PAGE_EXECUTE_READ|
                 PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0;
}

static double mem_entropy(const BYTE* d, size_t n) {
    if (!n) return 0.0;
    int f[256] = {};
    for (size_t i = 0; i < n; ++i) ++f[d[i]];
    double e = 0.0; double N = static_cast<double>(n);
    for (int i = 0; i < 256; ++i)
        if (f[i]) { double p = f[i] / N; e -= p * std::log2(p); }
    return e;
}

struct MemHit {
    DWORD pid;
    std::string name;
    LPVOID base;
    SIZE_T size;
    std::string classification;
    double entropy;
};

static std::vector<MemHit> memscan_run(DWORD target_pid) {
    std::vector<MemHit> hits;

    // Build pid->name map
    std::unordered_map<DWORD, std::string> pnames;
    {
        HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof pe;
        if (Process32First(h, &pe))
            do { pnames[pe.th32ProcessID] = pe.szExeFile; }
            while (Process32Next(h, &pe));
        CloseHandle(h);
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return hits;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof pe;

    if (Process32First(hSnap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid <= 4) continue;
            if (target_pid && pid != target_pid) continue;

            HANDLE hP = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                    FALSE, pid);
            if (!hP) continue;

            ULONG_PTR addr = 0;
            MEMORY_BASIC_INFORMATION mbi{};
            while (VirtualQueryEx(hP, reinterpret_cast<LPCVOID>(addr),
                                  &mbi, sizeof mbi) == sizeof mbi) {
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    mem_is_exec(mbi.Protect)) {

                    BYTE buf[512] = {};
                    SIZE_T got = 0;
                    ReadProcessMemory(hP, mbi.BaseAddress, buf,
                                      std::min(mbi.RegionSize, (SIZE_T)512), &got);

                    MemHit h2;
                    h2.pid  = pid;
                    h2.name = pnames.count(pid) ? pnames[pid] : "?";
                    h2.base = mbi.BaseAddress;
                    h2.size = mbi.RegionSize;
                    h2.entropy = mem_entropy(buf, got);

                    if (got >= 2 && buf[0] == 'M' && buf[1] == 'Z')
                        h2.classification = "PE_INJECT";
                    else if (got >= 3 && buf[0] == 0x48 && buf[1] == 0x83 && buf[2] == 0xEC)
                        h2.classification = "SHELLCODE_CANDIDATE";
                    else if (h2.entropy > 7.0)
                        h2.classification = "HIGH_ENTROPY";
                    else
                        h2.classification = "";  // not suspicious

                    if (!h2.classification.empty())
                        hits.push_back(h2);
                }
                ULONG_PTR next = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)
                                 + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
            }
            CloseHandle(hP);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return hits;
}

// ===================================================================
//  MODULE 5 — PERSISTENCE CHECK (report mode)
// ===================================================================

static void report_registry_run(const std::string& hive_name,
                                 HKEY hive,
                                 const std::string& subkey) {
    HKEY hk;
    if (RegOpenKeyExA(hive, subkey.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    char  vname[256];
    BYTE  vdata[1024];
    DWORD vname_sz, vdata_sz, vtype;

    while (true) {
        vname_sz = sizeof vname;
        vdata_sz = sizeof vdata;
        LONG ret = RegEnumValueA(hk, idx++, vname, &vname_sz,
                                 nullptr, &vtype, vdata, &vdata_sz);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) break;
        if (vtype == REG_SZ || vtype == REG_EXPAND_SZ) {
            std::string val(reinterpret_cast<char*>(vdata),
                            strnlen(reinterpret_cast<char*>(vdata), vdata_sz));
            emit("--:--:--", "PERSIST", "WARN",
                 "RUN_KEY [" + hive_name + "\\" + subkey + "] " +
                 std::string(vname) + " = " + val);
        }
    }
    RegCloseKey(hk);
}

static void report_ifeo() {
    // Image File Execution Options debugger hijacks
    const char* root = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, root, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    char  subname[256];
    DWORD subname_sz;

    while (RegEnumKeyExA(hk, idx++, subname, &(subname_sz = sizeof subname),
                         nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::string full = std::string(root) + "\\" + subname;
        HKEY hSub;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full.c_str(), 0, KEY_READ, &hSub)
            != ERROR_SUCCESS) continue;
        BYTE val[512]; DWORD vsz = sizeof val; DWORD vtype;
        if (RegQueryValueExA(hSub, "Debugger", nullptr, &vtype, val, &vsz) == ERROR_SUCCESS)
            emit("--:--:--", "PERSIST", "ALERT",
                 "IFEO_DEBUGGER " + std::string(subname) + " -> " +
                 std::string(reinterpret_cast<char*>(val),
                             strnlen(reinterpret_cast<char*>(val), vsz)));
        RegCloseKey(hSub);
    }
    RegCloseKey(hk);
}

static void report_appinit() {
    const char* key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;
    BYTE val[1024]; DWORD vsz = sizeof val; DWORD vtype;
    if (RegQueryValueExA(hk, "AppInit_DLLs", nullptr, &vtype, val, &vsz) == ERROR_SUCCESS) {
        std::string v(reinterpret_cast<char*>(val),
                      strnlen(reinterpret_cast<char*>(val), vsz));
        if (!v.empty())
            emit("--:--:--", "PERSIST", "ALERT",
                 "APPINIT_DLLS = " + v);
    }
    RegCloseKey(hk);
}

static void report_startup_folder() {
    const char* paths[] = {
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        nullptr  // user profile handled below
    };

    char userStartup[MAX_PATH] = {};
    {
        HANDLE hTok;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
            DWORD sz = sizeof userStartup;
            GetUserProfileDirectoryA(hTok, userStartup, &sz);
            CloseHandle(hTok);
        }
        if (userStartup[0])
            std::strncat(userStartup,
                         "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                         sizeof userStartup - strlen(userStartup) - 1);
    }

    auto check_dir = [](const std::string& dir) {
        WIN32_FIND_DATA fd;
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            std::string nm(fd.cFileName);
            if (nm == "." || nm == "..") continue;
            emit("--:--:--", "PERSIST", "WARN",
                 "STARTUP_FOLDER " + dir + "\\" + nm);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    };

    check_dir("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    if (userStartup[0]) check_dir(userStartup);
}

// ===================================================================
//  COMMAND: watch
// ===================================================================

static void cmd_watch(const std::string& fim_dir) {
    std::cout << "[BTM] watch mode started. Press Ctrl+C to stop.\n"
              << "[BTM] Monitors: FIM(" << fim_dir << ") | PROCS | NETCONN | MEMSCAN\n\n";

    std::thread t_fim([&]() { fim_thread(fim_dir, 30); });
    std::thread t_procs([]() { proc_thread(2000); });
    std::thread t_net([]() { net_thread(5); });

    // Memory scanner runs every 60s in background
    std::thread t_mem([]() {
        while (g_running) {
            auto hits = memscan_run(0);
            for (const auto& h : hits)
                emit(now_ts(), "MEMSCAN", "ALERT",
                     h.classification + " PID=" + std::to_string(h.pid) +
                     " " + h.name +
                     " base=0x" + [&]() {
                         std::ostringstream o;
                         o << std::hex << reinterpret_cast<uintptr_t>(h.base);
                         return o.str(); }() +
                     " sz=" + std::to_string(h.size) +
                     " H=" + [&]() {
                         std::ostringstream o;
                         o << std::fixed << std::setprecision(2) << h.entropy;
                         return o.str(); }());
            for (int i = 0; i < 60 && g_running; ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    t_fim.join();
    t_procs.join();
    t_net.join();
    t_mem.join();
}

// ===================================================================
//  COMMAND: report  (one-shot, all checks)
// ===================================================================

static void cmd_report() {
    std::cout << "=== Blue Team Security Snapshot — " << now_full() << " ===\n\n";

    // 1. Process anomalies
    std::cout << "--- [1] Process Anomalies ---\n";
    ProcSnap procs = proc_snapshot(true);
    int proc_issues = 0;
    for (const auto& [pid, p] : procs) {
        if (p.pid <= 4) continue;
        std::string flags = score_proc(p, procs);
        if (!flags.empty()) {
            emit("--:--:--", "PROCS", "ALERT",
                 "PID=" + std::to_string(pid) + " " + p.name +
                 " path=" + p.path + " !!" + flags);
            ++proc_issues;
        }
    }
    if (!proc_issues) std::cout << "  No process anomalies.\n";

    // 2. Network anomalies
    std::cout << "\n--- [2] Network Anomalies ---\n";
    NetMap conns = net_snapshot();
    int net_issues = 0;
    for (const auto& [k, c] : conns) {
        if (c.is_udp || c.state != "ESTABLISHED") continue;
        std::string nm = net_pid_name(c.pid);
        bool bad_port    = NET_BAD_PORTS.count(port_of(c.remote)) > 0;
        bool unusual_proc = NET_UNUSUAL_PROCS.count(str_lower(nm)) > 0;
        if (bad_port || unusual_proc) {
            std::string flags;
            if (bad_port)     flags += " BAD_PORT";
            if (unusual_proc) flags += " UNUSUAL_PROCESS";
            emit("--:--:--", "NETCONN", "ALERT",
                 "PID=" + std::to_string(c.pid) + " " + nm +
                 " " + c.local + " -> " + c.remote + " !!" + flags);
            ++net_issues;
        }
    }
    if (!net_issues) std::cout << "  No network anomalies.\n";

    // 3. Memory anomalies
    std::cout << "\n--- [3] Memory Anomalies ---\n";
    auto mhits = memscan_run(0);
    if (mhits.empty())
        std::cout << "  No suspicious memory regions.\n";
    else
        for (const auto& h : mhits) {
            std::ostringstream addr_s;
            addr_s << std::hex << reinterpret_cast<uintptr_t>(h.base);
            emit("--:--:--", "MEMSCAN", "ALERT",
                 h.classification + " PID=" + std::to_string(h.pid) +
                 " " + h.name + " base=0x" + addr_s.str() +
                 " sz=" + std::to_string(h.size));
        }

    // 4. Persistence
    std::cout << "\n--- [4] Persistence Mechanisms ---\n";
    report_registry_run("HKLM",
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    report_registry_run("HKLM",
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    report_registry_run("HKCU",
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    report_registry_run("HKCU",
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    report_ifeo();
    report_appinit();
    report_startup_folder();

    std::cout << "\n=== Snapshot complete ===\n";
}

// ===================================================================
//  COMMAND: fim  (standalone FIM for one directory)
// ===================================================================

static void cmd_fim(const std::string& dir) {
    std::cout << "[FIM] Monitoring " << dir << " — Ctrl+C to stop.\n\n";
    FimMap baseline;
    fim_scan_dir(dir, baseline);
    std::cout << "[FIM] Baseline: " << baseline.size() << " file(s).\n\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        FimMap curr;
        fim_scan_dir(dir, curr);
        int changes = 0;
        for (const auto& [p, h] : curr) {
            auto it = baseline.find(p);
            if (it == baseline.end()) { std::cout << "[" << now_ts() << "] [NEW]      " << p << "\n"; ++changes; }
            else if (it->second != h && h != 0xFFFFFFFF) { std::cout << "[" << now_ts() << "] [MODIFIED] " << p << "\n"; ++changes; }
        }
        for (const auto& [p, h] : baseline)
            if (curr.find(p) == curr.end()) { std::cout << "[" << now_ts() << "] [DELETED]  " << p << "\n"; ++changes; }
        if (!changes) std::cout << "[" << now_ts() << "] No changes (" << curr.size() << " files)\n";
        baseline = curr;
    }
}

// ===================================================================
//  COMMAND: procs / netconn / memscan (standalone)
// ===================================================================

static void cmd_procs() {
    std::cout << "[PROCS] Continuous process monitor — Ctrl+C to stop.\n\n";
    proc_thread(2000);
}

static void cmd_netconn() {
    std::cout << "[NETCONN] Continuous connection monitor — Ctrl+C to stop.\n\n";
    net_thread(3);
}

static void cmd_memscan(DWORD pid) {
    std::cout << "[MEMSCAN] Scanning memory";
    if (pid) std::cout << " for PID " << pid;
    std::cout << "...\n\n";
    auto hits = memscan_run(pid);
    if (hits.empty()) {
        std::cout << "No suspicious regions found.\n";
        return;
    }
    for (const auto& h : hits) {
        std::ostringstream addr_s;
        addr_s << std::hex << reinterpret_cast<uintptr_t>(h.base);
        std::cout << "  PID=" << std::setw(6) << h.pid
                  << "  " << std::left << std::setw(22) << h.name << std::right
                  << "  base=0x" << addr_s.str()
                  << "  sz=" << h.size
                  << "  H=" << std::fixed << std::setprecision(2) << h.entropy
                  << "  [" << h.classification << "]\n";
    }
    std::cout << "\n" << hits.size() << " suspicious region(s).\n";
}

// ===================================================================
//  main
// ===================================================================

static void usage() {
    std::cout << "Blue Team Monitor\n\n"
              << "Usage:\n"
              << "  blue_team_monitor.exe watch              "
                 "-- all monitors simultaneously\n"
              << "  blue_team_monitor.exe fim <dir>          "
                 "-- file integrity monitor\n"
              << "  blue_team_monitor.exe procs              "
                 "-- process anomaly detector\n"
              << "  blue_team_monitor.exe netconn            "
                 "-- network connection tracker\n"
              << "  blue_team_monitor.exe memscan [pid]      "
                 "-- memory injection scanner\n"
              << "  blue_team_monitor.exe report             "
                 "-- one-shot security snapshot\n";
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) { usage(); WSACleanup(); return 1; }

    std::string cmd = argv[1];

    if (cmd == "watch") {
        std::string dir = (argc >= 3) ? argv[2] : "C:\\Windows\\System32";
        cmd_watch(dir);
    }
    else if (cmd == "fim" && argc >= 3) {
        cmd_fim(argv[2]);
    }
    else if (cmd == "procs") {
        cmd_procs();
    }
    else if (cmd == "netconn") {
        cmd_netconn();
    }
    else if (cmd == "memscan") {
        DWORD pid = (argc >= 3) ? static_cast<DWORD>(std::stoul(argv[2])) : 0;
        cmd_memscan(pid);
    }
    else if (cmd == "report") {
        cmd_report();
    }
    else {
        usage();
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
}
