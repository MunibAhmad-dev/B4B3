# Module 08 — AV Evasion Theory

## 1. How Antivirus Works — The Full Picture

Understanding your adversary is the foundation. AV uses four layers:

### Layer 1: Static Analysis (File Scanning)

Runs **before** the file executes. Operates on the raw bytes on disk.

**a) Signature matching**
The AV has a database of byte patterns (signatures) extracted from known malware.
It slides a window over the file's sections looking for any matching pattern.

- Where it looks: `.text` (code), `.rdata` (strings), import table
- What it matches: specific byte sequences, string literals, import combos

**b) Heuristic analysis**
Rules like:
- "Has `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` in imports"
- "Contains suspicious string `Software\Microsoft\Windows\CurrentVersion\Run`"
- "File has 0 imports but calls Win32 APIs" (suggests dynamic resolution)
- "PE timestamp is in the future or year 1970" (repacked binary)

**c) ML models**
Modern AVs run the PE through a trained ML model that outputs a probability
score. Features include import table, section entropy, PE header values,
byte n-grams from `.rdata`.

### Layer 2: Behavioral Analysis (Sandbox)

The AV detonates the file in a controlled virtual environment and watches:

- Registry writes (especially Run keys)
- Process creation (especially `cmd.exe`, `powershell.exe`)
- Network connections
- File drops in suspicious locations (Temp, AppData)
- API call sequences

The sandbox has a time limit (~30–60 seconds). If the malware sleeps longer
than the limit, it never exhibits malicious behaviour during the scan.

**Known sandbox indicators:**
- Computer name is "HAL9TH" (Defender's internal sandbox)
- Username is "ADMIN" or "user" or "Administrator" on a machine with zero personal files
- RAM < 1 GB
- Process count < 20
- Screen resolution < 800×600
- Sleep is accelerated (sandbox speeds up time to force behaviour)
- CPUID returns hypervisor bit set (VM indicator)
- Single hard drive with no user documents

### Layer 3: Real-Time Behavioral Detection (EDR)

After the file executes on a real machine, an EDR (Endpoint Detection &
Response) driver sits in kernel mode and hooks API calls. Every call to:
- `RegSetValueEx` → logged
- `CreateProcess` → logged
- `NtAllocateVirtualMemory` → logged
- `NtCreateThreadEx` → logged

The EDR correlates events. "Process X wrote a Run key AND established an
outbound TCP connection" → incident raised.

**Key difference from sandbox:** the EDR runs indefinitely on real hardware.
A sleep delay doesn't help here — it just delays detection, not prevents it.

### Layer 4: Network Detection (IDS/IPS/Firewall)

- Signature matching on traffic content
- Beaconing pattern detection (regular intervals)
- Connecting to known malicious IPs / domains
- Unusual TLS certificate properties
- HTTP User-Agent strings that don't match real browsers

---

## 2. Static Evasion Techniques

### String Obfuscation (already covered in Module 03)

XOR-encrypt all strings at compile time so they don't appear in `.rdata`.

```cpp
// BAD — "cmd.exe" visible in .rdata
const char* s = "cmd.exe";

// GOOD — encrypted at compile time, decrypted only when used
constexpr ObfStr s("cmd.exe");
std::string decoded = s.decode();
```

### Import Table Minimisation

Remove suspicious API combinations from the static import table by resolving
at runtime:

```cpp
// BAD — these three together = injection triad in import table
#include <windows.h>  // pulls in VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

// GOOD — resolve at runtime
typedef LPVOID (WINAPI* pVirtualAllocEx)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
auto fn = (pVirtualAllocEx)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
```

**Limitation:** `GetProcAddress` itself appears in your import table. To remove
it entirely, walk the PEB export directory (Module 06).

### Section Entropy

Encrypted or compressed data has high entropy (near 8.0 bits/byte).
Unencrypted code has lower entropy (~6.0). AV flags sections with entropy > 7.0.

**Fix:** don't encrypt the entire binary. Only encrypt the strings and config
data. The code section itself stays normal entropy.

### PE Header Modifications

- Set a realistic compile timestamp (current date, not 1970 or the future)
- Remove the `.comment` section (`-fno-ident` removes GCC version string)
- Strip debug symbols (`-s`)
- Sign the binary (code signing cert — most effective single measure)

---

## 3. Sandbox Evasion Techniques

### Sleep and Verify (Time Distortion Check)

```cpp
// Sandbox accelerates time to force malware to run faster.
// Verify real time passed using QueryPerformanceCounter:

LARGE_INTEGER freq, t1, t2;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&t1);
Sleep(3000);
QueryPerformanceCounter(&t2);
double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0;
if (elapsed < 1500.0) ExitProcess(0);  // sleep was skipped → sandbox
```

### Environment Checks

```cpp
// HAL9TH check — Defender's sandbox machine name
char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
DWORD len = sizeof(name);
GetComputerNameA(name, &len);
if (_stricmp(name, "HAL9TH") == 0) ExitProcess(0);

// RAM check
MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) ExitProcess(0);  // < 2 GB

// Process count
DWORD count = 0;
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
if (Process32First(snap, &pe)) do { count++; } while (Process32Next(snap, &pe));
CloseHandle(snap);
if (count < 30) ExitProcess(0);
```

### Screen Resolution Check

```cpp
if (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768)
    ExitProcess(0);
```

### CPUID Hypervisor Bit

```cpp
int cpui[4];
__cpuid(cpui, 1);
if (cpui[2] & (1 << 31)) ExitProcess(0);  // hypervisor present
```

### Extended Delay

Run for 18+ seconds before any malicious activity. Defender's sandbox window
is ~30 seconds. Split into chunks and verify each chunk with QPC:

```cpp
for (int i = 0; i < 6; i++) {
    LARGE_INTEGER f, t1, t2;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t1);
    Sleep(3000);
    QueryPerformanceCounter(&t2);
    if ((t2.QuadPart - t1.QuadPart) * 1000.0 / f.QuadPart < 1500.0)
        ExitProcess(0);
}
```

---

## 4. What You Cannot Fully Evade

Be honest with yourself about limitations:

| Technique | Evaded by | NOT evaded by |
|-----------|-----------|---------------|
| String obfuscation | Static signature for known strings | Behavioural (strings decoded at runtime) |
| Import table cleanup | Static import scan | Runtime API monitoring by EDR |
| Startup delay | Sandbox time limit | Real machine EDR (runs indefinitely) |
| VM checks | Sandbox VMs | Real machine with Defender ATP |
| Code signing | SmartScreen reputation | EDR behavioural detection |

**Conclusion:** static evasion is solvable. Behavioural evasion against a
mature EDR on a real machine is an arms race — you need to change what the
malware does (startup folder instead of Run key, encrypted C2 traffic, living
off the land) not just how it looks.

---

## 5. Defensive Perspective (Blue Team)

As a defender, you:
- Enable `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
  Execution Options` monitoring for Run key writes
- Deploy Sysmon with rules for: `ProcessCreate`, `RegistryEvent`, `NetworkConnect`
- Alert on: new EXE in AppData + Run key write within 60 seconds
- Check beacon regularity with IDS rules
- Use memory scanning to find injected shellcode in running processes

Understanding both sides makes you better at both sides.

---

## Exercises

- `ex01_string_obfuscation.cpp` — build and verify compile-time obfuscation
- `ex02_sandbox_detection.cpp` — all sandbox checks in one function, returns score
- `ex03_pe_entropy.cpp` — calculate section entropy of a PE file
