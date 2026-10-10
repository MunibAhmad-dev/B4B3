/*
  Exercise 01 — Write YARA Rules
  --------------------------------
  Write 5 YARA rules that detect common malware patterns.
  The goal is to understand: rule structure, string types,
  conditions, the pe module, and false positive avoidance.

  After writing them, test with:
    yara -r ex01_write_rules.yar C:\Windows\     → should produce 0 hits on clean system
    yara -r ex01_write_rules.yar your_rat.exe    → should match relevant rules

  TASKS: Each rule has a TODO. Fill in the strings + condition.
*/

import "pe"

// ------------------------------------------------------------------
// RULE 1: Remote Access Trojan (RAT)
// Detect a generic RAT by the combination of:
//   - injection triad APIs
//   - network functions
//   - mutex prefix
// ------------------------------------------------------------------
rule GenericRAT
{
    meta:
        description = "Generic RAT — injection + network + mutex"
        author      = "Your Name"
        date        = "2026-10-01"
        tlp         = "WHITE"

    strings:
        // TODO: add strings for injection triad
        // $api1 = "CreateRemoteThread" ascii
        // $api2 = "VirtualAllocEx" ascii
        // $api3 = "WriteProcessMemory" ascii

        // TODO: add strings for network communication
        // $net1 = "InternetOpen" ascii wide
        // $net2 = "HttpSendRequest" ascii wide

        // TODO: add a mutex pattern
        // $mutex = "Global\\" ascii wide

    condition:
        // TODO: write condition
        // uint16(0) == 0x5A4D       // MZ header
        // and filesize < 10MB
        // and (all of ($api*))
        // and (1 of ($net*))
        false  // replace with your condition
}

// ------------------------------------------------------------------
// RULE 2: Ransomware Simulator
// Detect a program that enumerates files AND uses encryption APIs.
// ------------------------------------------------------------------
rule RansomwareIndicators
{
    meta:
        description = "Ransomware — file enumeration + crypto"
        author      = "Your Name"

    strings:
        // TODO: file enumeration APIs
        // $find1 = "FindFirstFileA" ascii
        // $find2 = "FindFirstFileW" ascii

        // TODO: crypto APIs used for key generation + encryption
        // $cry1 = "CryptGenKey" ascii
        // $cry2 = "CryptEncrypt" ascii

        // TODO: file extension targeting pattern
        // $ext1 = ".docx" ascii wide nocase
        // $ext2 = ".xlsx" ascii wide nocase
        // $ext3 = ".pdf"  ascii wide nocase

        // TODO: ransom note indicator
        // $note = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase

    condition:
        false  // replace
}

// ------------------------------------------------------------------
// RULE 3: Process Hollowing
// Detect a binary that uses the APIs required for process hollowing.
// ------------------------------------------------------------------
rule ProcessHollowing
{
    meta:
        description = "Process hollowing — unmap + rewrite"

    strings:
        // TODO: APIs specific to hollowing
        // $f1 = "NtUnmapViewOfSection" ascii
        // $f2 = "ZwUnmapViewOfSection" ascii
        // $f3 = "NtWriteVirtualMemory" ascii
        // $f4 = "SetThreadContext" ascii
        // $f5 = "ResumeThread" ascii

    condition:
        // TODO: 3 or more of the APIs
        false
}

// ------------------------------------------------------------------
// RULE 4: Dropper / Downloader
// A program that downloads and executes a second payload.
// ------------------------------------------------------------------
rule DropperDownloader
{
    meta:
        description = "Downloader — HTTP + execute"

    strings:
        // TODO: download indicators
        // $dl1 = "URLDownloadToFile" ascii wide
        // $dl2 = "WinHttpReadData" ascii
        // $dl3 = "InternetReadFile" ascii

        // TODO: execution indicators
        // $ex1 = "ShellExecuteA" ascii
        // $ex2 = "WinExec" ascii
        // $ex3 = "CreateProcessA" ascii

        // TODO: suspicious paths
        // $path1 = "%TEMP%" ascii wide nocase
        // $path2 = "%APPDATA%" ascii wide nocase

    condition:
        false  // replace
}

// ------------------------------------------------------------------
// RULE 5: Packed / Obfuscated Binary (entropy + pe module)
// Detect UPX-packed or custom-packed executables.
// ------------------------------------------------------------------
rule PackedExecutable
{
    meta:
        description = "Packed binary — high entropy or UPX"

    condition:
        // TODO: use pe module to detect packing indicators
        // uint16(0) == 0x5A4D
        // and (
        //     pe.section_index(".UPX0") >= 0             // UPX signature
        //     or pe.section_index(".UPX1") >= 0
        //     or pe.number_of_sections < 3               // packed files have few sections
        //     or for any section in pe.sections : (
        //         section.raw_size > 0 and
        //         math.entropy(section.raw_data_offset, section.raw_size) > 7.0
        //     )
        // )
        false
}
