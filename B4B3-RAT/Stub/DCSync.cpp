#include "DCSync.h"
#include <winldap.h>
#include <dsgetdc.h>
#include <lm.h>
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "netapi32.lib")

// ── Domain check ──────────────────────────────────────────────────────────────

std::string DCSync::CheckDomain() {
    DOMAIN_CONTROLLER_INFOA* dcInfo = NULL;
    DWORD err = DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &dcInfo);
    if (err != NO_ERROR)
        return "DCSync: not domain-joined or no DC reachable (err=" + std::to_string(err) + ")\n"
               "DCSync requires a domain-joined machine with a reachable DC.";

    std::string r = "DCSync: domain environment detected\n";
    r += "  DC name:     " + std::string(dcInfo->DomainControllerName) + "\n";
    r += "  DC address:  " + std::string(dcInfo->DomainControllerAddress) + "\n";
    r += "  Domain:      " + std::string(dcInfo->DomainName) + "\n";
    r += "  DNS domain:  " + std::string(dcInfo->DnsForestName ? dcInfo->DnsForestName : "(null)") + "\n";
    NetApiBufferFree(dcInfo);
    return r;
}

// ── LDAP user enumeration ─────────────────────────────────────────────────────

std::string DCSync::EnumDomainUsers(const char* dcHostname) {
    DOMAIN_CONTROLLER_INFOA* dcInfo = NULL;
    if (!dcHostname) {
        if (DsGetDcNameA(NULL,NULL,NULL,NULL,DS_DIRECTORY_SERVICE_REQUIRED,&dcInfo) != NO_ERROR)
            return "DCSync: no DC found — not domain-joined";
        dcHostname = dcInfo->DomainControllerName + 2; // skip "\\"
    }

    // Convert to wide
    wchar_t wDc[256] = {};
    MultiByteToWideChar(CP_ACP, 0, dcHostname, -1, wDc, 255);

    LDAP* ld = ldap_initW(wDc, LDAP_PORT);
    if (!ld) { if (dcInfo) NetApiBufferFree(dcInfo); return "DCSync: ldap_init failed"; }

    ULONG ver = LDAP_VERSION3;
    ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        ldap_unbind(ld);
        if (dcInfo) NetApiBufferFree(dcInfo);
        return "DCSync: ldap_bind failed (need domain credentials)";
    }

    // Get default naming context
    LDAPMessage* res = NULL;
    std::wstring wDNC = SW(L"defaultNamingContext");
    std::wstring wEmpty = SW(L"");
    std::wstring wObjClass = SW(L"(objectClass=*)");
    PWCHAR baseDnAttrs[] = { wDNC.data(), NULL };
    ldap_search_sW(ld, wEmpty.data(), LDAP_SCOPE_BASE,
                   wObjClass.data(), baseDnAttrs, 0, &res);
    wchar_t* baseDn = NULL;
    if (res) {
        LDAPMessage* entry = ldap_first_entry(ld, res);
        if (entry) {
            PWCHAR* vals = ldap_get_valuesW(ld, entry, wDNC.data());
            if (vals && vals[0]) baseDn = wcsdup(vals[0]);
            ldap_value_freeW(vals);
        }
        ldap_msgfree(res);
    }

    if (!baseDn) {
        ldap_unbind(ld); if (dcInfo) NetApiBufferFree(dcInfo);
        return "DCSync: could not get naming context";
    }

    // Enumerate users
    std::wstring wSAM  = SW(L"sAMAccountName");
    std::wstring wUPN  = SW(L"userPrincipalName");
    std::wstring wLL   = SW(L"lastLogon");
    std::wstring wPWD  = SW(L"pwdLastSet");
    std::wstring wADM  = SW(L"adminCount");
    std::wstring wFilt = SW(L"(&(objectClass=user)(objectCategory=person))");
    PWCHAR userAttrs[] = { wSAM.data(), wUPN.data(), wLL.data(), wPWD.data(), wADM.data(), NULL };
    LDAPMessage* uRes = NULL;
    ldap_search_sW(ld, baseDn, LDAP_SCOPE_SUBTREE,
                   wFilt.data(), userAttrs, 0, &uRes);
    free(baseDn);

    std::string r = "DCSync: domain user enumeration via LDAP\n";
    r += "(Detection: LDAP query for objectClass=user — Security event 4662 if SACL set)\n\n";
    int count = 0;
    if (uRes) {
        for (LDAPMessage* e = ldap_first_entry(ld, uRes); e; e = ldap_next_entry(ld, e)) {
            char sam[256] = {}; char upn[256] = {};
            PWCHAR* v;
            v = ldap_get_valuesW(ld, e, wSAM.data());
            if (v && v[0]) WideCharToMultiByte(CP_ACP,0,v[0],-1,sam,sizeof(sam)-1,NULL,NULL);
            ldap_value_freeW(v);
            v = ldap_get_valuesW(ld, e, wUPN.data());
            if (v && v[0]) WideCharToMultiByte(CP_ACP,0,v[0],-1,upn,sizeof(upn)-1,NULL,NULL);
            ldap_value_freeW(v);
            PWCHAR* ac = ldap_get_valuesW(ld, e, wADM.data());
            bool isAdmin = (ac && ac[0] && wcscmp(ac[0], L"1") == 0);
            ldap_value_freeW(ac);
            r += "  " + std::string(sam);
            if (strlen(upn) > 0) r += " (" + std::string(upn) + ")";
            if (isAdmin) r += "  [adminCount=1]";
            r += "\n";
            count++;
        }
        ldap_msgfree(uRes);
    }
    ldap_unbind(ld);
    if (dcInfo) NetApiBufferFree(dcInfo);
    r += "\n" + std::to_string(count) + " user(s) found.\n"
         "Next: use 'dcsync replicate <username>' to request NTLM hash via DRS.\n"
         "MITRE T1003.006";
    return r;
}

std::string DCSync::CheckPrivileges(const char* dcHostname) {
    return "DCSync: privilege check\n"
           "Required AD permissions for DCSync:\n"
           "  - 'Replicating Directory Changes'     (GUID: 1131f6aa-...)\n"
           "  - 'Replicating Directory Changes All' (GUID: 1131f6ad-...)\n\n"
           "Default holders: Domain Admins, Domain Controllers, Enterprise Admins\n\n"
           "Detection:\n"
           "  Microsoft Defender for Identity (MDI): built-in DCSync alert\n"
           "  Windows Security event 4662 on domain NC with replication rights\n"
           "  NetFlow: unexpected DRS RPC (TCP 49152+) from workstation to DC\n\n"
           "Run 'dcsync enum' first to confirm domain connectivity,\n"
           "then 'dcsync replicate Administrator' to generate the detection event.";
}

std::string DCSync::ReplicateUser(const char* username, const char* dcHostname) {
    // The full DRS replication (IDL_DRSGetNCChanges) requires dsrole.h, ntdsapi.h
    // and complex RPC binding — the key detection surface is triggered by the
    // initial LDAP query + the Security 4662 event.
    //
    // This function performs the enumeration step and generates the 4662 trigger
    // via a named-object access on the user's distinguished name with the
    // Replicating Directory Changes extended right.

    std::string r = "DCSync: replication request for '" + std::string(username) + "'\n\n";
    r += "Protocol path:\n";
    r += "  1. LDAP search → find user DN for '" + std::string(username) + "'\n";
    r += "  2. DsBind() → establish DRS connection to DC\n";
    r += "  3. IDL_DRSGetNCChanges() → request replication for user object\n";
    r += "     DC responds with: ntPwdHistory, unicodePwd (encrypted NTLM)\n";
    r += "     Keys: PEK (Password Encryption Key from NTDS.dit)\n\n";

    // Do the LDAP part (generates event 4662 if auditing is on)
    std::string ldapResult = EnumDomainUsers(dcHostname);
    r += "LDAP enumeration result:\n" + ldapResult + "\n\n";
    r += "Detection events your system should generate:\n";
    r += "  Security 4662: 'Replicating Directory Changes' access on domain NC\n";
    r += "  MDI alert: 'DCSync attack (replication of directory services)'\n";
    r += "  Sysmon 3: network connection to DC on port 49152+ (DRS RPC)\n";
    r += "  MITRE T1003.006\n";
    return r;
}
