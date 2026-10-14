#pragma once
#ifndef PRIVESC_H
#define PRIVESC_H
#include "common.h"

namespace PrivEsc {

    // ── UAC Bypass ────────────────────────────────────────────────────────────
    // uac fodhelper <cmd>  — ms-settings COM hijack → auto-elevate
    std::string FodhelperBypass(const std::string& cmd);
    // uac eventvwr <cmd>   — mscfile COM hijack → auto-elevate
    std::string EventvwrBypass(const std::string& cmd);

    // ── Hash / Hive Extraction ────────────────────────────────────────────────
    // samdump [dir]        — save SAM/SYSTEM/SECURITY hives (needs SYSTEM)
    std::string SamDump(const std::string& outDir);
    // hivenightmare        — CVE-2021-36934: check shadow-copy SAM readability
    std::string HiveNightmare();

    // ── Looting: Passwords in Files ───────────────────────────────────────────
    // pwfiles              — search unattend.xml, sysprep.inf, web.config, PS history
    std::string PasswordFileSearch();
    // pshist               — dump PowerShell ConsoleHost_history.txt
    std::string PSHistory();
    // sticky               — dump Sticky Notes (plum.sqlite + legacy .snt)
    std::string StickyNotes();

    // ── Looting: Passwords in Registry ───────────────────────────────────────
    // pwreg                — search Winlogon, VNC, PuTTY, SNMP for cleartext creds
    std::string RegistryPasswordSearch();

    // ── Looting: Windows Credential Manager ──────────────────────────────────
    // storedcreds          — CredEnumerateA: list all saved Windows credentials
    std::string StoredCredentials();

    // ── Wi-Fi Passwords ───────────────────────────────────────────────────────
    // wifi                 — WlanGetProfile with PLAINTEXT_KEY (needs admin)
    std::string WiFiDump();

    // ── Service Misconfigurations ─────────────────────────────────────────────
    // unquoted             — enumerate services with unquoted paths containing spaces
    std::string UnquotedServicePaths();
    // svcperms             — check if current user can write any service binary
    std::string WeakServicePerms();

    // ── Windows Installer ─────────────────────────────────────────────────────
    // aie                  — check AlwaysInstallElevated registry keys
    std::string AlwaysInstallElevated();

    // ── LAPS ─────────────────────────────────────────────────────────────────
    // laps                 — check if LAPS is deployed and read cached password
    std::string LAPSCheck();

    // ── Impersonation Privileges ──────────────────────────────────────────────
    // sepriv               — check token for SeImpersonate/SeDebug/SeBackup etc.
    std::string ImpersonationPrivCheck();

    // ── Local Admin → SYSTEM ─────────────────────────────────────────────────
    // system <cmd>         — create temp service to run <cmd> as SYSTEM (needs admin)
    std::string LocalAdminToSystem(const std::string& cmd);

    // ── WSL ───────────────────────────────────────────────────────────────────
    // wsl                  — detect WSL installations + enumerate distros
    std::string WSLCheck();

    // ── Named Pipes ──────────────────────────────────────────────────────────
    // pipes                — enumerate all \\.\pipe\* named pipes
    std::string NamedPipeEnum();

    // ── PrintSpoofer prerequisite check ──────────────────────────────────────
    // printspoof           — check Spooler running + SeImpersonatePrivilege
    std::string PrintSpooferCheck();

    // ── Full Scan ─────────────────────────────────────────────────────────────
    // privesc scan         — run all checks above in sequence
    std::string FullScan();
}

#endif
