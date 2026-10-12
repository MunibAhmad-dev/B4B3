#pragma once
#ifndef DCSYNC_H
#define DCSYNC_H
#include "common.h"

// DCSync — simulate a Domain Controller replication request to pull NTLM hashes
// without running code on the DC itself. MITRE T1003.006.
//
// Real DCSync (Mimikatz lsadump::dcsync) uses MS-DRSR (Directory Replication Service
// Remote Protocol) — specifically the IDL_DRSGetNCChanges RPC call — to request
// replication of a specific user account object from any DC.
//
// The DC believes it is talking to another DC doing normal AD replication.
// The response contains the NT hash, LM hash, and Kerberos keys.
//
// This implementation uses the LDAP approach to perform initial account enumeration
// and then calls DsGetDcName + DsBind + DsReplicaGetInfo to demonstrate the protocol
// path your detection system must monitor.
//
// Requirements:
//   - Domain-joined machine
//   - Credentials with "Replicating Directory Changes" + "Replicating Directory
//     Changes All" permissions (default: Domain Admins, Domain Controllers)
//
// What a strong detector catches:
//   - Windows Security event 4662: "Replicating Directory Changes" on domain NC
//   - NetFlow anomaly: unusual DRS RPC from workstation to DC
//   - Microsoft Defender for Identity (MDI): DCSync alert is built-in
//   - LDAP query for user objectclass + ntSecurityDescriptor
//
// MITRE T1003.006 — OS Credential Dumping: DCSync

namespace DCSync {
    // Check if the current machine is domain-joined and return DC info.
    std::string CheckDomain();

    // Enumerate domain users via LDAP (preliminary step, no hash extraction).
    // Returns: samAccountName, userPrincipalName, last logon, pwdLastSet.
    std::string EnumDomainUsers(const char* dcHostname = NULL);

    // Attempt DRS replication request for a specific user's password attributes.
    // This generates the Security 4662 event your detector should catch.
    // username: SAM account name (e.g. "Administrator")
    // Returns the replication attempt result (hash extraction if permitted).
    std::string ReplicateUser(const char* username, const char* dcHostname = NULL);

    // Check if current user has DCSync privileges (Replicating Directory Changes).
    std::string CheckPrivileges(const char* dcHostname = NULL);
}

#endif
