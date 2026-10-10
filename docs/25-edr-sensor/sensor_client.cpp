// sensor_client.cpp — behavioral EDR sensor (ETW 4688 + scoring)
// Compile: g++ -std=c++17 -o sensor_client.exe sensor_client.cpp -ladvapi32 -ltdh
// Usage: sensor_client.exe monitor | score <pid> | blocklist | watch

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <atomic>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Microsoft-Windows-Security-Auditing GUID (Kernel Audit)
static const GUID GUID_Security = {
    0x54849625, 0x5478, 0x4994,
    {0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D}
};

// Suspicious parent processes that score higher
static const char* BAD_PARENTS[] = {
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","svchost.exe",nullptr
};

// Known injection-associated DLLs
static const char* INJECT_DLLS[] = {
    "msvbvm60.dll","scrobj.dll","jscript.dll","vbscript.dll",
    "mshtml.dll","urlmon.dll",nullptr
};

static std::atomic<bool> g_running{true};
static TRACEHANDLE g_hTrace = INVALID_PROCESSTRACE_HANDLE;

// ─── Scoring engine ───────────────────────────────────────────────────────────

struct ProcessRecord {
    DWORD  pid;
    std::string image;
    std::string parent;
    int    score;
    std::vector<std::string> reasons;
};

static std::map<DWORD, ProcessRecord> g_processes;

static int score_process(DWORD pid, const std::string& image, const std::string& parent) {
    int score = 0;
    ProcessRecord rec{ pid, image, parent, 0, {} };

    // Temp path: +50
    std::string low_img = image;
    for (auto& c : low_img) c = (char)tolower(c);
    if (low_img.find("\\temp\\") != std::string::npos ||
        low_img.find("\\tmp\\") != std::string::npos ||
        low_img.find("\\appdata\\local\\temp") != std::string::npos) {
        score += 50; rec.reasons.push_back("image in temp (+50)");
    }

    // Suspicious parent: +70
    std::string low_par = parent;
    for (auto& c : low_par) c = (char)tolower(c);
    for (int i = 0; BAD_PARENTS[i]; ++i) {
        if (low_par.find(BAD_PARENTS[i]) != std::string::npos) {
            score += 70; rec.reasons.push_back(std::string("parent=") + BAD_PARENTS[i] + " (+70)");
            break;
        }
    }

    // Check loaded DLLs: +30 each
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        HMODULE mods[256]; DWORD needed = 0;
        EnumProcessModules(hProc, mods, sizeof(mods), &needed);
        DWORD n = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < n; ++i) {
            char name[MAX_PATH]{};
            GetModuleBaseNameA(hProc, mods[i], name, MAX_PATH);
            std::string low_mod(name);
            for (auto& c : low_mod) c = (char)tolower(c);
            for (int j = 0; INJECT_DLLS[j]; ++j) {
                if (low_mod == INJECT_DLLS[j]) {
                    score += 30;
                    rec.reasons.push_back(std::string("loaded ") + INJECT_DLLS[j] + " (+30)");
                }
            }
        }
        CloseHandle(hProc);
    }

    rec.score = score;
    g_processes[pid] = rec;
    return score;
}

// ─── ETW callback ─────────────────────────────────────────────────────────────

static VOID WINAPI event_callback(PEVENT_RECORD ev) {
    if (!ev) return;
    // Event 4688 = process create
    if (ev->EventHeader.EventDescriptor.Id != 4688) return;

    // Extract properties via TDH
    auto get_str = [&](const wchar_t* prop) -> std::wstring {
        PROPERTY_DATA_DESCRIPTOR dd{};
        dd.PropertyName = (ULONGLONG)prop;
        dd.ArrayIndex   = ULONG_MAX;
        ULONG sz = 0;
        if (TdhGetPropertySize(ev, 0, nullptr, 1, &dd, &sz) != ERROR_SUCCESS) return L"";
        std::vector<BYTE> buf(sz);
        if (TdhGetProperty(ev, 0, nullptr, 1, &dd, sz, buf.data()) != ERROR_SUCCESS) return L"";
        return std::wstring((wchar_t*)buf.data());
    };

    std::wstring img_w    = get_str(L"NewProcessName");
    std::wstring parent_w = get_str(L"ParentProcessName");
    DWORD pid = 0;
    {
        std::wstring pid_w = get_str(L"NewProcessId");
        pid = (DWORD)wcstoul(pid_w.c_str(), nullptr, 16);
    }

    std::string img(img_w.begin(), img_w.end());
    std::string par(parent_w.begin(), parent_w.end());

    int s = score_process(pid, img, par);
    const char* level = s >= 100 ? " *** ALERT ***" : s >= 50 ? " [suspicious]" : "";
    printf("[4688] PID=%-6lu  score=%-4d%s\n  img=%s\n  par=%s\n",
           pid, s, level, img.c_str(), par.c_str());
}

// ─── monitor ─────────────────────────────────────────────────────────────────

static void cmd_monitor() {
    const wchar_t* SESSION = L"SensorClientSession";
    printf("[*] Starting ETW monitor (Event 4688)\n");
    printf("    Run as Administrator for full audit events\n\n");

    DWORD props_sz = sizeof(EVENT_TRACE_PROPERTIES) + (DWORD)((wcslen(SESSION)+1)*2);
    std::vector<BYTE> props_buf(props_sz, 0);
    auto* props = (EVENT_TRACE_PROPERTIES*)props_buf.data();
    props->Wnode.BufferSize    = props_sz;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE hSess = 0;
    ULONG st = StartTraceW(&hSess, SESSION, props);
    if (st == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, SESSION, props, EVENT_TRACE_CONTROL_STOP);
        st = StartTraceW(&hSess, SESSION, props);
    }
    if (st != ERROR_SUCCESS) {
        fprintf(stderr, "[!] StartTraceW: %lu\n", st); return;
    }

    ENABLE_TRACE_PARAMETERS etp{};
    etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    EnableTraceEx2(hSess, &GUID_Security, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, &etp);

    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = (LPWSTR)SESSION;
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = event_callback;
    g_hTrace = OpenTraceW(&lf);

    SetConsoleCtrlHandler([](DWORD) -> BOOL {
        g_running = false; CloseTrace(g_hTrace); return TRUE;
    }, TRUE);

    printf("[+] Listening for process creation events (Ctrl+C to stop)\n\n");
    std::thread t([&]{ ProcessTrace(&g_hTrace, 1, nullptr, nullptr); });
    t.join();
    ControlTraceW(hSess, nullptr, props, EVENT_TRACE_CONTROL_STOP);
}

// ─── score <pid> ─────────────────────────────────────────────────────────────

static void cmd_score(DWORD pid) {
    char img[MAX_PATH]{};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) { GetModuleFileNameExA(hProc, nullptr, img, MAX_PATH); CloseHandle(hProc); }
    int s = score_process(pid, img, "");
    auto& rec = g_processes[pid];
    printf("[*] Score for PID %lu: %d\n  image: %s\n", pid, s, img);
    for (auto& r : rec.reasons) printf("  + %s\n", r.c_str());
}

// ─── blocklist ────────────────────────────────────────────────────────────────

static void cmd_blocklist() {
    printf("[*] Blocklist check (known suspicious image names):\n\n");
    const char* BLOCKED[] = {
        "mimikatz.exe","meterpreter.exe","cobalt","metasploit",
        "nmap.exe","psexec.exe","wce.exe","pwdump","laZagne",nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            std::string nm(pe.szExeFile);
            std::string low = nm;
            for (auto& c : low) c = (char)tolower(c);
            for (int i = 0; BLOCKED[i]; ++i)
                if (low.find(BLOCKED[i]) != std::string::npos)
                    printf("  [BLOCK] PID=%-6lu  %s\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ─── watch: continuous periodic scoring ───────────────────────────────────────

static void cmd_watch() {
    printf("[*] Watching all processes (5s interval, Ctrl+C to stop)\n\n");
    SetConsoleCtrlHandler([](DWORD) -> BOOL { g_running = false; return TRUE; }, TRUE);
    while (g_running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe{ sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                char img[MAX_PATH]{};
                HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (h) { GetModuleFileNameExA(h, nullptr, img, MAX_PATH); CloseHandle(h); }
                int s = score_process(pe.th32ProcessID, img, pe.szExeFile);
                if (s >= 50)
                    printf("  [SCORE=%d] PID=%-6lu  %s\n", s, pe.th32ProcessID, img);
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        Sleep(5000);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n"
               "  sensor_client.exe monitor\n"
               "  sensor_client.exe score <pid>\n"
               "  sensor_client.exe blocklist\n"
               "  sensor_client.exe watch\n");
        return 1;
    }
    std::string cmd(argv[1]);
    if      (cmd == "monitor")                  cmd_monitor();
    else if (cmd == "score" && argc >= 3)        cmd_score((DWORD)strtoul(argv[2], nullptr, 10));
    else if (cmd == "blocklist")                cmd_blocklist();
    else if (cmd == "watch")                    cmd_watch();
    else { fprintf(stderr, "Unknown command.\n"); return 1; }
    return 0;
}
