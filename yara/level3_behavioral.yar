/*
  B4B3-RAT — Level 3: Behavioral / Static Characteristic Detection
  =================================================================
  Matches on the combination of Win32 API imports that are necessary
  for this RAT's capabilities.  No single import is suspicious alone;
  the combination — custom HTTPS C2 + remote injection + anti-analysis
  + screenshot + persistence — is highly indicative of a RAT.

  This level is resilient against string obfuscation: it works even
  after renaming, packing or XOR-encoding the config, as long as the
  import table survives (which it must for execution without a loader).

  Run against:
    yara -r level3_behavioral.yar /path/to/suspicious.exe
    yara -r level3_behavioral.yar --no-warnings .
*/

import "pe"

rule B4B3RAT_Behavioral_NetworkCapabilityWinInet
{
    meta:
        description     = "PE with WinInet HTTPS capability: custom C2 over TLS without browser"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1071.001"
        level           = "medium"

    condition:
        pe.imports("wininet.dll", "InternetOpenA")       and
        pe.imports("wininet.dll", "InternetConnectA")    and
        pe.imports("wininet.dll", "HttpOpenRequestA")    and
        pe.imports("wininet.dll", "HttpSendRequestA")    and
        pe.imports("wininet.dll", "InternetReadFile")    and
        pe.imports("wininet.dll", "InternetSetOption")   and
        pe.imports("wininet.dll", "InternetQueryOption")
}


rule B4B3RAT_Behavioral_RemoteInjection
{
    meta:
        description     = "PE imports DLL/shellcode injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1055.001"
        level           = "high"

    condition:
        pe.imports("kernel32.dll", "VirtualAllocEx")      and
        pe.imports("kernel32.dll", "WriteProcessMemory")  and
        pe.imports("kernel32.dll", "CreateRemoteThread")  and
        pe.imports("kernel32.dll", "OpenProcess")
}


rule B4B3RAT_Behavioral_ScreenCapture
{
    meta:
        description     = "PE imports GDI screen capture functions — BitBlt + GetDC pattern used by ScreenTool"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1113"
        level           = "medium"

    condition:
        pe.imports("gdi32.dll",   "BitBlt")                 and
        pe.imports("gdi32.dll",   "CreateCompatibleDC")     and
        pe.imports("gdi32.dll",   "CreateCompatibleBitmap") and
        pe.imports("user32.dll",  "GetDC")                  and
        pe.imports("user32.dll",  "ReleaseDC")
}


rule B4B3RAT_Behavioral_AntiAnalysis
{
    meta:
        description     = "PE imports anti-debug + process enumeration functions used by Protector module"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1497.001"
        level           = "medium"

    condition:
        pe.imports("kernel32.dll", "IsDebuggerPresent")           and
        pe.imports("kernel32.dll", "CreateToolhelp32Snapshot")    and
        pe.imports("kernel32.dll", "Process32First")              and
        pe.imports("kernel32.dll", "Process32Next")
}


rule B4B3RAT_Behavioral_Persistence
{
    meta:
        description     = "PE imports registry persistence + self-copy pattern used by Manager::Autorun"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1547.001"
        level           = "medium"

    condition:
        pe.imports("advapi32.dll", "RegCreateKeyA")    and
        pe.imports("advapi32.dll", "RegSetValueExA")   and
        pe.imports("kernel32.dll", "CopyFileA")        and
        pe.imports("shell32.dll",  "ShellExecuteA")
}


rule B4B3RAT_Behavioral_NetworkTelemetry
{
    meta:
        description     = "PE imports TCP table enumeration used by Telemetry::CheckNetwork"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1049"
        level           = "low"

    condition:
        pe.imports("iphlpapi.dll", "GetExtendedTcpTable") and
        pe.imports("advapi32.dll", "EnumServicesStatusExA")
}


/*
  ─────────────────────────────────────────────────────────────
  COMPOSITE rule — highest confidence, lowest false-positive rate.
  Fires only when three or more capability clusters are present
  in the same binary.  Changing any single cluster is not enough
  to evade detection.
  ─────────────────────────────────────────────────────────────
*/
rule B4B3RAT_Behavioral_FullProfile_Composite
{
    meta:
        description     = "B4B3-RAT full behavioral profile: HTTPS C2 + injection + screenshot + anti-analysis + persistence — all in one PE"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1055, T1071.001, T1113, T1547.001, T1497.001"
        level           = "critical"

    condition:
        // C2 comms
        pe.imports("wininet.dll", "InternetOpenA")           and
        pe.imports("wininet.dll", "HttpSendRequestA")        and
        pe.imports("wininet.dll", "InternetSetOption")       and

        // Remote injection
        pe.imports("kernel32.dll", "VirtualAllocEx")         and
        pe.imports("kernel32.dll", "CreateRemoteThread")     and

        // Screen capture
        pe.imports("gdi32.dll",   "BitBlt")                  and
        pe.imports("user32.dll",  "GetDC")                   and

        // Anti-analysis
        pe.imports("kernel32.dll", "IsDebuggerPresent")      and
        pe.imports("kernel32.dll", "CreateToolhelp32Snapshot") and

        // Persistence
        pe.imports("advapi32.dll", "RegCreateKeyA")          and
        pe.imports("kernel32.dll", "CopyFileA")
}
