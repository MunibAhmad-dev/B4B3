// ex02_dynamic_hooks.cpp — IAT hooking tracer exercise
// Compile: g++ -std=c++17 -o ex02.exe ex02_dynamic_hooks.cpp -lws2_32
// Usage: ex02.exe (runs in-process hooks, then triggers the hooked APIs)
//
// TODO 1: Implement install_iat_hook(module, dll_name, func_name, hook_fn):
//         - Get module base, parse IMAGE_IMPORT_DESCRIPTOR for dll_name
//         - Find the IAT entry matching func_name via OriginalFirstThunk / FirstThunk
//         - VirtualProtect PAGE_READWRITE, save old ptr, write hook_fn, restore protect
//
// TODO 2: Write hook stubs for:
//         - CreateFileA: log filename + access flags, call original
//         - RegSetValueExA: log hKey + value name + data, call original
//         - send (Winsock): log socket + first 32 bytes of buffer, call original
//
// TODO 3: After installing hooks, call each API and verify the hook fires.
//         Uninstall hooks by restoring the saved original pointer.

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")

int main() {
    printf("IAT hook tracer — implement TODOs\n");
    // After hooks are installed these calls should be logged:
    HANDLE h = CreateFileA("test_hook.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    RegSetValueExA(HKEY_CURRENT_USER, "HookTest", 0, REG_SZ, (BYTE*)"hooked", 7);
    printf("Done — implement hooks to see API calls logged above\n");
    return 0;
}
