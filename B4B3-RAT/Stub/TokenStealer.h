#pragma once
#ifndef TOKEN_STEALER_H
#define TOKEN_STEALER_H
#include "common.h"

namespace TokenStealer {
    // Enable SeDebugPrivilege and duplicate the primary token of winlogon.exe.
    // Calls ImpersonateLoggedOnUser — subsequent operations in this thread run as
    // NT AUTHORITY\SYSTEM.  Returns a status string.
    std::string StealSystem();

    // Spawn `exe` as a new process running under the stolen SYSTEM primary token.
    // Requires SeAssignPrimaryTokenPrivilege + SeImpersonatePrivilege (both granted
    // automatically when already elevated).
    // Returns the spawned PID, or 0 on failure.
    DWORD SpawnAsSystem(const std::string& exe);

    // Revert any impersonation on the calling thread.
    void Revert();
}

#endif
