/*
 * Module 35 — Solution 01: Complete Basic DLL
 * =============================================
 * Exports: Add, Sub, GetVersion, LogMessage
 * DllMain logs all four lifecycle events to OutputDebugString.
 * LogMessage appends a timestamped line to %TEMP%\sol01_log.txt.
 *
 * Companion .def file content (included as a comment below).
 *
 * Compile (MinGW / g++):
 *   g++ -shared -std=c++17 -o sol01.dll sol01_basic_dll.cpp -Wl,--export-all-symbols
 *
 * Compile (MSVC):
 *   cl /LD /EHsc /std:c++17 sol01_basic_dll.cpp /link /OUT:sol01.dll
 *
 * .def file for ordinal exports — save as sol01.def and pass to linker:
 *   g++ -shared -std=c++17 -o sol01.dll sol01_basic_dll.cpp sol01.def
 *
 * Inspect exports:
 *   dumpbin /exports sol01.dll   (MSVC)
 *   objdump -x sol01.dll | grep -A20 "Export Table"  (MinGW)
 *
 * --- sol01.def ---
 * LIBRARY   sol01
 * EXPORTS
 *     Add         @1
 *     Sub         @2
 *     GetVersion  @3
 *     LogMessage  @4
 * -----------------
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <string>

// ---------------------------------------------------------------------------
// Internal: open (or create) the log file in %TEMP%
// ---------------------------------------------------------------------------
static void WriteToLog(const char* message)
{
    char tempPath[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, tempPath)) {
        return;
    }

    char logPath[MAX_PATH] = {};
    _snprintf_s(logPath, MAX_PATH, _TRUNCATE, "%s\\sol01_log.txt", tempPath);

    // Get current time
    time_t now = time(nullptr);
    struct tm tmBuf {};
    localtime_s(&tmBuf, &now);
    char timeBuf[32] = {};
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmBuf);

    FILE* f = nullptr;
    fopen_s(&f, logPath, "a");
    if (f) {
        fprintf(f, "[%s] %s\n", timeBuf, message);
        fclose(f);
    }
}

// ---------------------------------------------------------------------------
// DllMain — logs all four lifecycle events
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char buf[256] = {};

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Suppress DLL_THREAD_ATTACH / DLL_THREAD_DETACH notifications.
            // This is a common optimization when thread tracking is not needed.
            DisableThreadLibraryCalls(hinstDLL);

            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "[sol01] DLL_PROCESS_ATTACH hinstDLL=0x%p", (void*)hinstDLL);
            OutputDebugStringA(buf);
            WriteToLog(buf);
            break;

        case DLL_PROCESS_DETACH:
            // lpvReserved != NULL → process is terminating; avoid heap allocation.
            if (lpvReserved == nullptr) {
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "[sol01] DLL_PROCESS_DETACH (FreeLibrary called)");
            } else {
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "[sol01] DLL_PROCESS_DETACH (process terminating)");
            }
            OutputDebugStringA(buf);
            // Note: avoid WriteToLog on terminate path — heap may be inconsistent
            if (lpvReserved == nullptr) WriteToLog(buf);
            break;

        case DLL_THREAD_ATTACH:
            // Only reached if DisableThreadLibraryCalls was not called.
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "[sol01] DLL_THREAD_ATTACH tid=%lu", GetCurrentThreadId());
            OutputDebugStringA(buf);
            break;

        case DLL_THREAD_DETACH:
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "[sol01] DLL_THREAD_DETACH tid=%lu", GetCurrentThreadId());
            OutputDebugStringA(buf);
            break;
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport)
int __cdecl Add(int a, int b)
{
    return a + b;
}

extern "C" __declspec(dllexport)
int __cdecl Sub(int a, int b)
{
    return a - b;
}

extern "C" __declspec(dllexport)
const char* __cdecl GetVersion()
{
    // Static string — valid for the lifetime of the DLL in the process.
    static const char version[] = "1.0.0";
    return version;
}

/*
 * LogMessage — appends a message to %TEMP%\sol01_log.txt.
 * Callers pass a null-terminated C string.
 * Returns 1 on success, 0 on failure.
 */
extern "C" __declspec(dllexport)
int __cdecl LogMessage(const char* msg)
{
    if (!msg) return 0;
    char buf[512] = {};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[LogMessage] %s", msg);
    WriteToLog(buf);
    OutputDebugStringA(buf);
    return 1;
}

/*
 * ===========================================================================
 * .def file reference — create this as sol01.def in the same directory
 * and pass it to the linker to control ordinal assignments:
 *
 *   LIBRARY   sol01
 *   EXPORTS
 *       Add         @1
 *       Sub         @2
 *       GetVersion  @3
 *       LogMessage  @4
 *
 * To test ordinal import from a caller:
 *   typedef int (*AddFn)(int,int);
 *   HMODULE h  = LoadLibraryA("sol01.dll");
 *   AddFn fn   = (AddFn)GetProcAddress(h, (LPCSTR)1);  // ordinal 1 = Add
 *   int result = fn(3, 4);  // 7
 *   FreeLibrary(h);
 * ===========================================================================
 */
