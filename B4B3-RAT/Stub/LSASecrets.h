#pragma once
#ifndef LSASECRETS_H
#define LSASECRETS_H
#include "common.h"

// LSASecrets — dump LSA secrets and cached domain credentials.
// MITRE T1003.004 (LSA Secrets), T1003.005 (Cached Domain Credentials).
//
// LSA secrets (HKLM\SECURITY\Policy\Secrets) contain:
//   - Service account passwords (_SC_<ServiceName>)
//   - DPAPI machine key (DPAPI_SYSTEM)
//   - Cached domain logon hashes (NL$KM + NL$1..NL$10 = last 10 domain users)
//   - VPN/dial-up credentials (RasDialParams)
//   - DefaultPassword (auto-logon password if set)
//
// Requires SYSTEM privilege to read HKLM\SECURITY (not even admin is enough).
// Use TokenStealer::StealSystem() first if running as admin.
//
// Two extraction methods:
//   1. LsaOpenPolicy + LsaRetrievePrivateData (LSA RPC, logs Security event 4662)
//   2. Direct registry hive read (HKLM\SECURITY via NtQuerySystemInformation,
//      bypasses LsaRetrievePrivateData logging — better for detection testing)
//
// What a strong detector catches:
//   - Security event 4662: object access on LSA Secret objects
//   - HKLM\SECURITY access at all = SACL audit log (if configured)
//   - LsaRetrievePrivateData API call via ETW
//
// MITRE T1003.004, T1003.005

namespace LSASecrets {
    // Dump via LsaOpenPolicy + LsaRetrievePrivateData (standard API path).
    std::string DumpViaAPI();

    // Dump via direct registry: save SECURITY hive to temp file, parse offline.
    std::string DumpViaRegistry();

    // List all LSA secret key names (without values — less noisy, confirms access).
    std::string ListSecretNames();
}

#endif
