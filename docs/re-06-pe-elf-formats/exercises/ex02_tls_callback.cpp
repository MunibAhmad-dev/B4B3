// ex02_tls_callback.cpp — TLS callback demo
// Observe: the TLS callback prints BEFORE main() executes.
// This is how malware hides early anti-debug checks.
// Compile: g++ -std=c++17 -o ex02.exe ex02_tls_callback.cpp
#include <windows.h>
#include <stdio.h>

// TODO: Define a TLS callback function with signature:
//   void NTAPI tls_callback(PVOID, DWORD, PVOID)
// TODO: Register it in the .CRT$XLB section so the loader calls it.
//   #pragma comment(linker, "/INCLUDE:_tls_used")
//   #pragma data_seg(".CRT$XLB")
//   extern "C" PIMAGE_TLS_CALLBACK tls_cb_arr[] = { tls_callback, nullptr };
//   #pragma data_seg()
// TODO: Print "[TLS] reason=<DLL_PROCESS_ATTACH|THREAD_ATTACH>" in the callback.

int main() {
    printf("[main] Running\n");
    return 0;
}
