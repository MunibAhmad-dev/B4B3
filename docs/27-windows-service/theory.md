# Module 27 — Windows Service Development

## Why services matter for security tools

A Windows Service:
- Starts automatically at boot (before any user logs in)
- Runs in the background continuously
- Runs as SYSTEM, Local Service, or Network Service
- Is managed by the Service Control Manager (SCM)
- Survives user logoff

**Security uses:**
- Deploy your EDR agent as a service (always running, auto-start)
- Backdoor persistence (malware installs as a service)
- Detection: services are a major persistence vector (Module 10)
- Blue team: build monitoring daemons as services

---

## 2. Service Architecture

A Windows Service binary has a specific structure:
```
main()
  → StartServiceCtrlDispatcher()  ← registers the service entry point with SCM
      ↓ SCM calls:
  ServiceMain(argc, argv)
      → RegisterServiceCtrlHandlerEx()  ← registers control handler
      → SetServiceStatus(SERVICE_RUNNING)
      → <do your work in a loop or start worker threads>
      → SetServiceStatus(SERVICE_STOPPED) on exit

ServiceCtrlHandler(control)
  → handles: SERVICE_CONTROL_STOP, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE
```

---

## 3. Complete Service Skeleton

```cpp
#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>

static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static SERVICE_STATUS        g_Status       = {};
static std::atomic<bool>     g_Running      = true;

void setStatus(DWORD state, DWORD exitCode = NO_ERROR) {
    g_Status.dwCurrentState = state;
    g_Status.dwWin32ExitCode = exitCode;
    SetServiceStatus(g_StatusHandle, &g_Status);
}

// Handler for SCM commands (stop, pause, continue)
DWORD WINAPI ServiceCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        setStatus(SERVICE_STOP_PENDING);
        g_Running = false;
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

// Main service function — called by SCM
VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    // Register control handler
    g_StatusHandle = RegisterServiceCtrlHandlerExA(
        "MyService", ServiceCtrlHandler, nullptr);
    if (!g_StatusHandle) return;

    // Configure status struct
    g_Status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    g_Status.dwCurrentState            = SERVICE_START_PENDING;
    g_Status.dwWin32ExitCode           = NO_ERROR;
    g_Status.dwServiceSpecificExitCode = 0;
    g_Status.dwCheckPoint              = 0;
    g_Status.dwWaitHint                = 3000;
    SetServiceStatus(g_StatusHandle, &g_Status);

    // --- Initialization ---
    // Open log file, initialize networking, load config, etc.

    setStatus(SERVICE_RUNNING);

    // --- Main Loop ---
    while (g_Running) {
        // Your service work goes here
        // Example: check for new tasks, monitor files, beacon home, etc.
        Sleep(5000);
    }

    // --- Cleanup ---
    setStatus(SERVICE_STOPPED);
}

int main() {
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)"MyService", ServiceMain },
        { nullptr, nullptr }
    };
    // This call blocks until the service stops
    StartServiceCtrlDispatcherA(table);
    return 0;
}
```

**Install and test:**
```cmd
sc create MyService type= own start= auto binPath= "C:\path\MyService.exe"
sc description MyService "My Security Agent"
sc start MyService
sc query MyService
sc stop MyService
sc delete MyService
```

---

## 4. Running as SYSTEM

By default a service runs as `Local System` (SYSTEM) — the highest local privilege.
This means your service can:
- Read/write any file
- Open any process
- Write HKLM registry keys
- Call `AdjustTokenPrivileges` to enable any privilege

For a security agent, running as SYSTEM is usually what you want.

---

## 5. Interactive Service (Reading Output)

Services run in session 0 (isolated, no desktop access).
To show a UI or communicate with a logged-in user:
- Named pipes (service writes, user-mode GUI reads)
- Shared memory sections
- WM_COPYDATA message to a GUI process
- WTS session query + WTSSendMessage for simple notifications

---

## 6. Service as Persistence (attacker use)

```cmd
// Attacker installs persistence as a service
sc create SvcName type= own start= auto
  binPath= "C:\Windows\Temp\backdoor.exe -run"

// Survives: reboot, user logoff, process kill (SCM restarts if configured)
// Detected by: sc query, Get-Service, services.msc, Module 10 persistence scanner
```

**Blue team detection of malicious services:**
- Binaries in unusual paths (Temp, AppData, root of C:\)
- Services with auto-start pointing to binaries that don't exist
- Services registered recently (compared to baseline)
- Services with no display name or generic name

---

## Exercises

- `ex01_service_skeleton.cpp` — full service that writes a heartbeat log every 30 seconds
- `ex02_service_pipe_ipc.cpp` — service exposes a named pipe; GUI client sends queries
- `ex03_service_installer.cpp` — programmatically install/start/stop/delete a service
- `ex04_service_persistence_sim.cpp` — install a service as a persistence technique (blue team lab)
