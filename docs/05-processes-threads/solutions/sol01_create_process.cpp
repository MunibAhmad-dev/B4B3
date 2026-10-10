// Solution 01 — CreateProcess and Output Capture

#include <windows.h>
#include <iostream>
#include <string>

std::string RunCommand(const char* cmd) {
    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;  // child inherits handles

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return "";

    // Make the read end non-inheritable (parent only)
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;

    PROCESS_INFORMATION pi = {};

    // cmd.exe /C <command>
    char cmdline[1024];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", cmd);

    BOOL ok = CreateProcessA(nullptr, cmdline, nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    // Close write end in parent — otherwise ReadFile blocks forever
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        return "";
    }

    // Read all output
    std::string output;
    char buf[4096];
    DWORD read = 0;
    while (ReadFile(hReadPipe, buf, sizeof(buf), &read, nullptr) && read > 0)
        output.append(buf, read);

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    return output;
}

int main() {
    std::string who = RunCommand("whoami");
    std::cout << "=== whoami ===\n" << who << "\n";

    std::string ip = RunCommand("ipconfig");
    std::cout << "=== ipconfig ===\n" << ip << "\n";

    // Write whoami result to file
    HANDLE hFile = CreateFileA("result.txt", GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, who.c_str(), (DWORD)who.size(), &written, nullptr);
        CloseHandle(hFile);
        std::cout << "Written to result.txt\n";
    }

    return 0;
}
