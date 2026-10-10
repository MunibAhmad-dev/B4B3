/*
  Exercise 03 — Beacon Object File (BOF) Skeleton
  -------------------------------------------------
  A BOF is a COFF object file that Cobalt Strike's Beacon executes
  in-process via its internal loader. No new process spawned.

  BOF advantages:
  - Code runs inside Beacon — no new process to detect
  - Full access to all Win32 APIs (resolved at runtime via DECLSPEC_IMPORT)
  - Can call BeaconPrintf to return output to the operator
  - Very small and fast to deploy

  This skeleton implements a "process lister" BOF — the same thing as
  using Toolhelp32 but running inside Beacon.

  Tasks:
  1. Include the beacon.h header (provided by Cobalt Strike SDK).
     For this exercise a stub is included below.
  2. Complete go() — use Toolhelp32 to list processes.
     All API calls must use the WINAPI macros (KERNEL32$CreateToolhelp32Snapshot, etc.)
  3. Use BeaconPrintf(CALLBACK_OUTPUT, ...) to return output.
  4. Parse args using BeaconDataParse / BeaconDataInt / BeaconDataExtract
     (the operator can pass arguments when running the BOF).

  BONUS:
  - Add a filter: list processes matching a substring passed as arg.
  - Add a PID-kill action: if arg is a PID, call OpenProcess + TerminateProcess.
  - Add a module list action: list DLLs loaded in each process.

  Compile (requires mingw-w64 or CL):
    x86_64-w64-mingw32-gcc -o proclist.o -c ex03_bof_skeleton.c -masm=intel
  Load in Cobalt Strike:
    beacon> inline-execute /path/to/proclist.o

  For local testing (no CS), compile as a normal exe:
    gcc -DTEST_LOCALLY -o bof_test.exe ex03_bof_skeleton.c
*/

#include <windows.h>
#include <tlhelp32.h>

// ---------- beacon.h stub (for compilation without CS SDK) ----------
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d
typedef void BEACON_API;

// Macro: KERNEL32$Func maps to Kernel32!Func resolved at runtime in CS
// For local testing, map directly to the API
#ifdef TEST_LOCALLY
  #define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
  #define KERNEL32$Process32FirstA          Process32First
  #define KERNEL32$Process32NextA           Process32Next
  #define KERNEL32$CloseHandle              CloseHandle
  #define KERNEL32$GetCurrentProcessId      GetCurrentProcessId
  void BeaconPrintf(int type, const char* fmt, ...) {
      (void)type;
      va_list ap; va_start(ap, fmt);
      vprintf(fmt, ap); va_end(ap);
  }
#else
  DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
  DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstA(HANDLE, PROCESSENTRY32A*);
  DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextA(HANDLE, PROCESSENTRY32A*);
  DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
  DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
  // BeaconPrintf is provided by the beacon runtime
  void BeaconPrintf(int type, const char* fmt, ...);
#endif

// ---------- TODO: complete go() ----------
void go(char* args, int len) {
    (void)args; (void)len;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[BOF] Process Lister running in PID %lu\n",
                 KERNEL32$GetCurrentProcessId());

    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] CreateToolhelp32Snapshot failed\n");
        return;
    }

    PROCESSENTRY32A pe;
    pe.dwSize = sizeof(pe);

    if (!KERNEL32$Process32FirstA(hSnap, &pe)) {
        KERNEL32$CloseHandle(hSnap);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%-8s  %-8s  %s\n", "PID", "PPID", "Image");
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", "-------------------------------");

    do {
        // TODO: print each process
        // BeaconPrintf(CALLBACK_OUTPUT, "%-8lu  %-8lu  %s\n",
        //              pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        (void)pe;
    } while (KERNEL32$Process32NextA(hSnap, &pe));

    KERNEL32$CloseHandle(hSnap);
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Done\n");
}

#ifdef TEST_LOCALLY
int main() {
    go(NULL, 0);
    return 0;
}
#endif
