/*
  Solution 03 — Beacon Object File (BOF) Skeleton
  -------------------------------------------------
  A BOF is a COFF .o file loaded directly into Beacon's process. All Win32
  calls go through KERNEL32$FunctionName macros that Beacon resolves.

  When compiled with TEST_LOCALLY defined, falls back to direct API calls
  so you can test in a normal executable before deploying to Cobalt Strike.

  Compile as BOF (for Cobalt Strike):
    x86_64-w64-mingw32-gcc -c -o sol03.o sol03_bof_skeleton.c
    # then use aggressor: bof sol03.o

  Compile for local testing:
    gcc -DTEST_LOCALLY -o sol03_test.exe sol03_bof_skeleton.c -lkernel32

  Usage in Cobalt Strike:
    # In Aggressor script:
    $bof = openf(script_resource("sol03.o"));
    bof $bof, bof_pack("", "");
*/

#ifdef TEST_LOCALLY
// ── Local test mode: use real API calls directly ──────────────────────────────
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define BeaconPrintf(type, fmt, ...) printf(fmt, ##__VA_ARGS__)
#define BeaconOutput(type, str, len) printf("%.*s", (int)(len), (char*)(str))

#define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define KERNEL32$Process32First           Process32First
#define KERNEL32$Process32Next            Process32Next
#define KERNEL32$CloseHandle              CloseHandle

typedef HANDLE (WINAPI* pCreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL   (WINAPI* pProcess32First_t)(HANDLE, PROCESSENTRY32*);
typedef BOOL   (WINAPI* pProcess32Next_t)(HANDLE, PROCESSENTRY32*);

#else
// ── BOF mode: all API calls through Beacon's internal resolver ────────────────
#include "beacon.h"

// These macros expand to the DECLSPEC_IMPORT declarations Beacon expects.
// beacon.h provides the stub — you import via KERNEL32$Name syntax.
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, PROCESSENTRY32*);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, PROCESSENTRY32*);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

#define CALLBACK_OUTPUT 0x0  // BeaconPrintf output type

#endif

// ── go: the BOF entry point ───────────────────────────────────────────────────
// Beacon calls go(args, len) after loading the BOF. args is a packed buffer.
// For this exercise args is empty (no parameters).
void go(char* args, int len) {
    (void)args; (void)len;

    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] CreateToolhelp32Snapshot failed\n");
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    BeaconPrintf(CALLBACK_OUTPUT, "%-8s  %s\n", "PID", "Image Name");
    BeaconPrintf(CALLBACK_OUTPUT, "%-8s  %s\n", "---", "----------");

    if (KERNEL32$Process32First(hSnap, &pe)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT, "%-8lu  %s\n",
                         pe.th32ProcessID, pe.szExeFile);
        } while (KERNEL32$Process32Next(hSnap, &pe));
    }

    KERNEL32$CloseHandle(hSnap);
}

// ── main (local test only) ────────────────────────────────────────────────────
#ifdef TEST_LOCALLY
int main(void) {
    printf("=== BOF Local Test: Process List ===\n\n");
    go(NULL, 0);
    return 0;
}
#endif
