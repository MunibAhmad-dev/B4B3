/*
  Exercise 04 — Persistence Scanner (Blue Team Tool)
  -----------------------------------------------------
  Build a tool that scans all common persistence locations and reports
  what is registered there. This is what Autoruns.exe does.

  Tasks:
  1. Write: void scanRunKeys()
     Check both HKCU and HKLM Run and RunOnce keys.
     Print each registered value name + data (executable path).
     Flag any executable not in C:\Windows\ or C:\Program Files\ as suspicious.

  2. Write: void scanStartupFolders()
     List contents of:
       %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
       C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
     Print each file found.

  3. Write: void scanScheduledTasks()
     Use system("schtasks /query /fo CSV /nh") and parse the output.
     List all tasks whose "Task To Run" path is NOT in C:\Windows\.

  4. Write: void scanServices()
     Enumerate services using EnumServicesStatusExA.
     For each SERVICE_WIN32 type service, get its binary path from the registry:
       HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath
     Flag paths outside C:\Windows\ as worth investigating.

  5. Write: void scanIFEO()
     Enumerate keys under:
       HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
     For each key that has a "Debugger" value, print the exe name + debugger.
     Any non-empty debugger is a red flag.

  6. In main(): run all scanners, print a formatted report:
     ===== PERSISTENCE SCAN REPORT =====
     [RUN KEYS]
     ...
     [STARTUP FOLDERS]
     ...
     [SCHEDULED TASKS]
     ...
     [SERVICES (non-Windows paths)]
     ...
     [IFEO DEBUGGERS]
     ...

  This tool should be something you can run on any machine to quickly
  audit its persistence state.

  Compile:
    g++ -std=c++17 -Wall -o persistence_scan.exe ex04_detection.cpp
        -ladvapi32 -lkernel32 -lshlwapi
*/

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// YOUR CODE HERE

int main() {
    std::cout << "===== PERSISTENCE SCAN REPORT =====\n\n";
    scanRunKeys();
    scanStartupFolders();
    scanScheduledTasks();
    scanServices();
    scanIFEO();
    std::cout << "\n===== END OF REPORT =====\n";
    return 0;
}
