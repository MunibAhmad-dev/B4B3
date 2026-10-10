/*
  Solution 01 — YARA Rules for Common Malware Patterns
  -------------------------------------------------------
  Five rules covering: RAT, Ransomware, Process Hollowing, Dropper, Packed binary.

  Test with:
    yara -r sol01_write_rules.yar C:\Windows\System32\  → should produce few/no hits
    yara -r sol01_write_rules.yar your_sample.exe       → should match relevant rules

  Note: some rules use the "pe" module and "math" module.
  Install yara with: pip install yara-python  (or download binary from GitHub releases)
*/

import "pe"
import "math"

// ------------------------------------------------------------------
// RULE 1: Remote Access Trojan (RAT)
// Injection triad APIs + network communication + mutex pattern.
// Requires at least 2 of the injection APIs and 1 of the network/mutex strings.
// ------------------------------------------------------------------
rule GenericRAT
{
    meta:
        description = "Generic RAT — injection triad + network + mutex"
        author      = "Security Curriculum"
        date        = "2026-10-01"
        tlp         = "WHITE"
        reference   = "Module 26 solution"

    strings:
        // Injection triad
        $va  = "VirtualAllocEx"    ascii
        $wpm = "WriteProcessMemory" ascii
        $crt = "CreateRemoteThread" ascii

        // Network communication (WinINet / WinHTTP / raw socket)
        $net1 = "WinINet"        ascii wide nocase
        $net2 = "winhttp"        ascii wide nocase
        $net3 = "WSAConnect"     ascii
        $net4 = "InternetOpenA"  ascii
        $net5 = "HttpSendRequestA" ascii

        // Mutex prefix bytes: "Mutex" = 4D 75 74 65 78
        $mx = { 4D 75 74 65 78 }

        // Global mutex
        $gm = "Global\\" ascii wide

    condition:
        uint16(0) == 0x5A4D                  // MZ header
        and filesize < 10MB
        and 2 of ($va, $wpm, $crt)
        and (1 of ($net1, $net2, $net3, $net4, $net5) or 1 of ($mx, $gm))
}

// ------------------------------------------------------------------
// RULE 2: Ransomware Indicators
// Crypto key generation + encryption + file enumeration + ransom note.
// ------------------------------------------------------------------
rule RansomwareIndicators
{
    meta:
        description = "Ransomware — file enumeration + crypto API + ransom note"
        author      = "Security Curriculum"
        date        = "2026-10-01"

    strings:
        // Windows Crypto API: key generation + encryption
        $enc = "CryptEncrypt"  ascii
        $key = "CryptGenKey"   ascii

        // File enumeration
        $ff1 = "FindFirstFileA" ascii
        $ff2 = "FindFirstFileW" ascii
        $ff3 = "FindFirstFileExA" ascii

        // File rename / move (used to replace originals with encrypted versions)
        $ren1 = "MoveFileExA"  ascii
        $ren2 = "MoveFileExW"  ascii
        $ren3 = "RenameFile"   ascii

        // Ransom note filename: "README" = 52 45 41 44 4D 45
        $note1 = { 52 45 41 44 4D 45 }
        $note2 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note3 = "DECRYPT_INSTRUCTIONS"            ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and all of ($enc, $key)
        and 1 of ($ff1, $ff2, $ff3)
        and (1 of ($ren1, $ren2, $ren3) or 1 of ($note1, $note2, $note3))
}

// ------------------------------------------------------------------
// RULE 3: Process Hollowing
// NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext.
// All four must be present because hollowing uses every one of them.
// ------------------------------------------------------------------
rule ProcessHollowing
{
    meta:
        description = "Process hollowing — unmap original image and inject replacement"
        author      = "Security Curriculum"
        date        = "2026-10-01"

    strings:
        // Unmap the original image
        $zu1 = "ZwUnmapViewOfSection"  ascii
        $zu2 = "NtUnmapViewOfSection"  ascii

        // Inject the replacement PE
        $va  = "VirtualAllocEx"        ascii
        $wpm = "WriteProcessMemory"    ascii

        // Resume with hijacked EIP/RIP
        $sc  = "SetThreadContext"      ascii
        $rt  = "ResumeThread"          ascii

    condition:
        uint16(0) == 0x5A4D
        and 1 of ($zu1, $zu2)
        and $va
        and $wpm
        and ($sc or $rt)
}

// ------------------------------------------------------------------
// RULE 4: Dropper / Downloader
// Downloads a payload over HTTP and executes it from a temp path.
// ------------------------------------------------------------------
rule DropperDownloader
{
    meta:
        description = "Dropper/Downloader — HTTP download + execute from temp path"
        author      = "Security Curriculum"
        date        = "2026-10-01"

    strings:
        // Download functions
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "WinHttpOpen"        ascii
        $dl4 = "InternetReadFile"   ascii

        // Execution functions
        $ex1 = "ShellExecuteA"   ascii
        $ex2 = "ShellExecuteW"   ascii
        $ex3 = "CreateProcessA"  ascii
        $ex4 = "CreateProcessW"  ascii
        $ex5 = "WinExec"         ascii

        // Written to temp path: "\Temp\" = 5C 54 65 6D 70 5C
        $tmp1 = { 5C 54 65 6D 70 5C }
        $tmp2 = "%TEMP%"   ascii wide nocase
        $tmp3 = "%APPDATA%" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and 1 of ($dl1, $dl2, $dl3, $dl4)
        and 1 of ($ex1, $ex2, $ex3, $ex4, $ex5)
        and 1 of ($tmp1, $tmp2, $tmp3)
}

// ------------------------------------------------------------------
// RULE 5: Packed / Obfuscated Binary
// Detects UPX packing or high-entropy sections typical of custom packers.
// Uses the pe and math modules.
// ------------------------------------------------------------------
rule PackedExecutable
{
    meta:
        description = "Packed/obfuscated binary — UPX or high-entropy sections"
        author      = "Security Curriculum"
        date        = "2026-10-01"

    strings:
        // UPX magic bytes in section name
        $upx0 = ".UPX0" ascii
        $upx1 = ".UPX1" ascii
        $upx_magic = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D
        and (
            // UPX packer signature
            1 of ($upx0, $upx1, $upx_magic)

            // Or very few PE sections (packed files typically have 1-3)
            or pe.number_of_sections < 4

            // Or overall file entropy > 7.0 (highly compressed/encrypted)
            or math.entropy(0, filesize) > 7.0
        )
}
