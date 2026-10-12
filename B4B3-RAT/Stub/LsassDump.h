#pragma once
#ifndef LSASSDUMP_H
#define LSASSDUMP_H
#include "common.h"

namespace LsassDump {
    // Dump lsass.exe memory with MiniDumpWriteDump from dbghelp.dll.
    // Requires SeDebugPrivilege — run "tokensteal" first if not already SYSTEM/Admin.
    // Detection signals:
    //   OpenProcess(PROCESS_ALL_ACCESS) on lsass.exe
    //   MiniDumpWriteDump called from a non-Windows process
    //   Large .dmp file written to disk by a suspicious binary
    std::string Dump(const std::string& outPath);

    // Alternative: spawn rundll32.exe with comsvcs.dll,MiniDump.
    // Generates a different detection surface than the direct API path.
    // Detection: rundll32 loading comsvcs.dll with suspicious arguments.
    std::string DumpViaComsvcs(const std::string& outPath);
}

#endif
