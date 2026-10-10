/*
 * Module 35 — Exercise 01: Basic DLL Skeleton
 * ============================================
 * Learning objectives:
 *   - Understand DllMain and its four notification reasons
 *   - Export functions by name using __declspec(dllexport) and extern "C"
 *   - Understand how to use OutputDebugString for DLL diagnostics
 *   - Learn about .def files and ordinal exports
 *
 * Compile (MinGW / g++):
 *   g++ -shared -std=c++17 -o ex01.dll exercise_01_basic_dll.cpp -Wl,--export-all-symbols
 *
 * Compile (MSVC):
 *   cl /LD /EHsc exercise_01_basic_dll.cpp /link /OUT:ex01.dll
 *
 * Test (PowerShell):
 *   $dll = Add-Type -Path ".\ex01.dll" -PassThru  # see note below
 *   # Or use a small loader executable, or rundll32 if you add a suitable exported entry.
 *
 * .def file note (see TODO section at bottom for ordinal export example):
 *   To build with a .def file instead of __declspec:
 *   g++ -shared -std=c++17 -o ex01.dll exercise_01_basic_dll.cpp -Wl,--output-def,ex01.def
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

// ---------------------------------------------------------------------------
// DllMain — entry point called by the loader for four lifecycle events
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char buf[256];
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // TODO: Log "DLL_PROCESS_ATTACH" to OutputDebugString.
            // Hint: snprintf into buf, then call OutputDebugStringA(buf).
            // Also call DisableThreadLibraryCalls(hinstDLL) to suppress thread notifications.
            break;

        case DLL_PROCESS_DETACH:
            // TODO: Log "DLL_PROCESS_DETACH" to OutputDebugString.
            // Note: if lpvReserved != NULL the process is terminating; avoid heap allocation.
            break;

        case DLL_THREAD_ATTACH:
            // TODO: Log "DLL_THREAD_ATTACH" to OutputDebugString.
            break;

        case DLL_THREAD_DETACH:
            // TODO: Log "DLL_THREAD_DETACH" to OutputDebugString.
            break;
    }
    return TRUE;  // Return FALSE on DLL_PROCESS_ATTACH to abort the load
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/*
 * TODO: Implement Add.
 *   - The function signature is already correct.
 *   - extern "C" prevents C++ name mangling.
 *   - __declspec(dllexport) makes it visible in the EAT.
 *   - Just return the sum of a and b.
 */
extern "C" __declspec(dllexport) int Add(int a, int b)
{
    // TODO: implement — return a + b
    return 0;
}

/*
 * TODO: Implement GetVersion.
 *   - Return a static string literal "1.0.0".
 *   - Why static? The returned pointer must remain valid after the function returns.
 *     A local char array would be on the stack and invalid after return.
 */
extern "C" __declspec(dllexport) const char* GetVersion()
{
    // TODO: return a static string "1.0.0"
    return "";
}

// ---------------------------------------------------------------------------
// TODO: .def file — ordinal exports
// ---------------------------------------------------------------------------
/*
 * To export functions by ordinal instead of (or in addition to) by name,
 * create a file named ex01.def alongside this source with the following content:
 *
 *   LIBRARY   ex01
 *   EXPORTS
 *       Add         @1          ; exported by name AND ordinal 1
 *       GetVersion  @2          ; exported by name AND ordinal 2
 *       AddOrdOnly  @3 NONAME   ; exported ONLY by ordinal 3 (no name in EAT)
 *
 * Then compile with:
 *   g++ -shared -std=c++17 -o ex01.dll exercise_01_basic_dll.cpp -Wl,--output-def,ex01_gen.def
 *   # Or pass the .def file explicitly to the linker:
 *   g++ -shared -std=c++17 -o ex01.dll exercise_01_basic_dll.cpp ex01.def
 *
 * To import by ordinal from a client:
 *   typedef int (*AddFn)(int, int);
 *   HMODULE h = LoadLibraryA("ex01.dll");
 *   AddFn fn = (AddFn)GetProcAddress(h, (LPCSTR)1);  // ordinal 1
 *   int result = fn(3, 4);  // result == 7
 */
