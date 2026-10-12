#pragma once
#ifndef ANTIFORENSICS_H
#define ANTIFORENSICS_H
#include "common.h"

namespace AntiForensics {
    // Wipe all Windows Event Log channels (Security, System, Application, Defender, Sysmon…).
    // Detection: EvtClearLog from a non-system process = high-confidence evidence-tampering alert.
    std::string ClearEventLogs();

    // Delete all Volume Shadow Copies via WMI Win32_ShadowCopy.Delete().
    // This is the exact technique used by Conti, REvil, BlackCat, and other ransomware.
    // Detection: WMI shadow-copy deletion = tier-1 ransomware indicator.
    std::string DeleteShadowCopies();

    // Modify a file's creation/modify/access timestamps.
    // If refPath is non-empty, copy its timestamps; otherwise set a fixed past date.
    // Detection: SetFileTime from a suspicious process = anti-forensics/timestomping alert.
    std::string Timestomp(const std::string& targetPath, const std::string& refPath);

    // Write arbitrary data into an NTFS Alternate Data Stream.
    // Data is invisible to dir, Explorer, and most tools — only visible via "dir /r" or streams.exe.
    // Detection: CreateFile with ":streamName" suffix in path = NTFS ADS data-hiding alert.
    std::string AdsWrite(const std::string& filePath, const std::string& streamName,
                         const std::string& data);

    // Read data back from an NTFS Alternate Data Stream.
    std::string AdsRead(const std::string& filePath, const std::string& streamName);
}

#endif
