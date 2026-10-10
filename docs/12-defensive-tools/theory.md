# Module 12 — Defensive Tools (Blue Team Engineering)

This module covers tools a company's security team actually builds and uses.
If you join a blue team, these are the things they will ask you to write.

---

## 1. File Integrity Monitor (FIM)

A FIM watches critical files and directories and alerts when they change.
Used to detect web shell drops, config file tampering, and binary replacements.

**Core concept:**
1. Baseline: compute a hash (SHA-256) of every file in a watched directory
2. Periodically re-hash and compare to baseline
3. Alert on: new files, deleted files, changed files (hash mismatch)

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <map>
#include <string>
#include <filesystem>

using FileHashMap = std::map<std::string, std::string>;  // path → sha256 hex

std::string sha256File(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);

    BYTE buf[65536];
    DWORD read;
    while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0)
        CryptHashData(hHash, buf, read, 0);

    BYTE hashBytes[32];
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    char hex[65] = {};
    for (int i = 0; i < 32; i++)
        snprintf(hex + i*2, 3, "%02x", hashBytes[i]);
    return hex;
}

FileHashMap baseline(const std::string& dir) {
    FileHashMap map;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            std::string path = entry.path().string();
            map[path] = sha256File(path);
        }
    }
    return map;
}

void checkIntegrity(const FileHashMap& base, const std::string& dir) {
    FileHashMap current = baseline(dir);

    for (const auto& [path, hash] : current) {
        if (base.count(path) == 0)
            printf("[NEW]     %s\n", path.c_str());
        else if (base.at(path) != hash)
            printf("[CHANGED] %s\n", path.c_str());
    }
    for (const auto& [path, hash] : base) {
        if (current.count(path) == 0)
            printf("[DELETED] %s\n", path.c_str());
    }
}
```

**Real-time version:** use `ReadDirectoryChangesW` instead of polling.
It's a Win32 API that notifies you immediately when a file changes.

---

## 2. Process Monitor / Anomaly Detector

Watch for suspicious process creation patterns:

```cpp
// Use WMI event subscription to receive real-time process creation events
// OR poll every 2 seconds and diff against previous snapshot

struct ProcSnapshot {
    std::map<DWORD, std::string> pids;  // pid → exe name
};

ProcSnapshot current = takeSnapshot();

while (true) {
    Sleep(2000);
    ProcSnapshot next = takeSnapshot();

    // New processes
    for (const auto& [pid, name] : next.pids) {
        if (!current.pids.count(pid)) {
            printf("[NEW PROCESS] PID=%lu  %s\n", pid, name.c_str());

            // Check against suspicious list
            std::vector<std::string> suspicious = {
                "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"
            };
            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), tolower);
            for (const auto& s : suspicious)
                if (nameLower.find(s) != std::string::npos)
                    printf("  *** SUSPICIOUS: %s ***\n", name.c_str());
        }
    }

    // Exited processes
    for (const auto& [pid, name] : current.pids)
        if (!next.pids.count(pid))
            printf("[EXITED]      PID=%lu  %s\n", pid, name.c_str());

    current = next;
}
```

---

## 3. Network Connection Monitor

```cpp
#include <iphlpapi.h>

void monitorConnections(const std::vector<std::string>& watchedIPs) {
    while (true) {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(size);
        auto* table = (MIB_TCPTABLE_OWNER_PID*)buf.data();
        GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            auto& row = table->table[i];
            if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

            char remoteIP[16];
            in_addr addr;
            addr.s_addr = row.dwRemoteAddr;
            strcpy(remoteIP, inet_ntoa(addr));

            for (const auto& watched : watchedIPs) {
                if (std::string(remoteIP).find(watched) != std::string::npos) {
                    printf("[ALERT] Process %lu connected to %s:%d\n",
                           row.dwOwningPid, remoteIP, ntohs((u_short)row.dwRemotePort));
                }
            }
        }
        Sleep(5000);
    }
}
```

---

## 4. Log Parser / SIEM Event Correlator

Windows Security Event Log contains all the forensic gold:

| Event ID | What it means |
|----------|---------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4688 | New process created |
| 4698 | Scheduled task created |
| 4702 | Scheduled task updated |
| 4719 | System audit policy changed |
| 7045 | New service installed |

```cpp
#include <windows.h>
#include <evntprov.h>
// Use EvtQuery / EvtNext / EvtRender from wevtapi.dll

// Simple version using system() for PowerShell query:
std::string QueryEventLog(int eventId, int lastHours) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Get-WinEvent -FilterHashtable "
        "@{LogName='Security'; Id=%d; StartTime=(Get-Date).AddHours(-%d)} "
        "| Select-Object TimeCreated,Id,Message | Format-List\"",
        eventId, lastHours);
    return RunCommand(cmd);
}
```

**Better approach:** use the Windows Event Log API (`EvtQuery`, `EvtNext`,
`EvtRender`) for direct programmatic access. This avoids spawning PowerShell
and is much faster for bulk queries.

---

## 5. Honeypot File / Canary Token

A canary file is a file that should never be touched. If it is — someone is
enumerating your filesystem (attacker, ransomware, insider).

```cpp
// Place a canary file and monitor its access via a change notification
HANDLE hChange = FindFirstChangeNotificationA(
    "C:\\Users\\user\\Documents\\",
    FALSE,                     // don't watch subdirectories
    FILE_NOTIFY_CHANGE_LAST_ACCESS   // fire when any file is accessed
);

while (true) {
    if (WaitForSingleObject(hChange, INFINITE) == WAIT_OBJECT_0) {
        printf("[CANARY] File accessed in Documents — possible enumeration!\n");
        // Log + alert
        FindNextChangeNotification(hChange);
    }
}
```

**Real canary tokens** (canarytokens.org): embed a unique URL in a Word doc,
PDF, or environment variable. When it's opened/read, it makes a DNS request
that alerts you. No code needed — just sign up and download the file.

---

## 6. Memory Scanner

Scan all processes for shellcode indicators:

```cpp
void scanProcessMemory(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                FALSE, pid);
    if (!hProc) return;

    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Suspicious: committed + executable + not backed by a file (MEM_PRIVATE)
        bool executable = (mbi.Protect & PAGE_EXECUTE) ||
                          (mbi.Protect & PAGE_EXECUTE_READ) ||
                          (mbi.Protect & PAGE_EXECUTE_READWRITE);
        bool unbacked = (mbi.Type == MEM_PRIVATE);

        if (mbi.State == MEM_COMMIT && executable && unbacked) {
            printf("[SUSPICIOUS] PID=%lu Addr=0x%p Size=%llu Protect=0x%X\n",
                   pid, mbi.BaseAddress, (ULONG64)mbi.RegionSize, mbi.Protect);
        }

        addr = (LPVOID)((ULONG_PTR)addr + mbi.RegionSize);
    }
    CloseHandle(hProc);
}
```

Private executable memory (not backed by a file on disk) is a strong indicator
of injected shellcode. Legitimate code has `MEM_IMAGE` type (backed by a DLL/EXE).

---

## Exercises

- `ex01_file_integrity_monitor.cpp` — SHA-256 baseline + diff
- `ex02_process_monitor.cpp` — poll + diff process list, flag suspicious exes
- `ex03_connection_monitor.cpp` — monitor TCP connections to flagged IPs
- `ex04_canary_file.cpp` — place canary + monitor access with FindFirstChangeNotification
- `ex05_memory_scanner.cpp` — scan all processes for private executable regions
- `ex06_event_log_reader.cpp` — query Security event log for logon events
