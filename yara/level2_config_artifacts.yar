/*
  B4B3-RAT — Level 2: Configuration Artifact Detection
  ======================================================
  Matches combinations of strings that together reveal the RAT's compiled
  configuration, regardless of whether individual strings were renamed.
  These rules are resilient to simple string-patch evasion: an attacker
  would need to change multiple independent artifacts simultaneously.

  Targets:
    - C2 communication protocol (endpoint paths + auth param pattern)
    - AES-128 CBC encrypted config block (magic marker + key material)
    - Payload build artifacts (watchdog copy path, scheduler name, drop path)
    - Telemetry event JSON keys emitted to the C2 server
*/

import "pe"

rule B4B3RAT_Config_C2Protocol
{
    meta:
        description     = "B4B3-RAT: combination of custom C2 HTTP endpoint paths and auth query pattern"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1071.001"
        level           = "high"

    strings:
        // Endpoint paths embedded in the stub
        $path_checkin   = "/checkin" ascii
        $path_cmd       = "/cmd"     ascii
        $path_result    = "/result"  ascii
        $path_upload    = "/upload"  ascii
        $path_event     = "/event"   ascii

        // Auth and bot ID query params
        $qp_auth        = "auth="    ascii
        $qp_id          = "?id="     ascii

        // Default user-agent used for all WinInet calls
        $ua             = "Mozilla/5.0" ascii

    condition:
        // Need the protocol structure AND at least 3 endpoints
        $qp_auth and $qp_id and $ua
        and 3 of ($path_*)
}


rule B4B3RAT_Config_TelemetrySchema
{
    meta:
        description     = "B4B3-RAT: telemetry JSON field names emitted by the monitoring thread"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1071.001"
        level           = "medium"

    strings:
        // JSON keys from Telemetry.cpp Emit()
        $jk_bot         = "\"bot\":"   ascii
        $jk_cat         = "\"cat\":"   ascii
        $jk_type        = "\"type\":"  ascii
        $jk_sev         = "\"sev\":"   ascii
        $jk_rule        = "\"rule\":"  ascii
        $jk_ev          = "\"ev\":"    ascii
        $jk_tid         = "\"tid\":"   ascii
        $jk_tname       = "\"tname\":" ascii

        // Detection rule IDs hardcoded in Telemetry.cpp
        $dr_proc001     = "PROC_001"   ascii
        $dr_reg001      = "REG_001"    ascii
        $dr_net002      = "NET_002"    ascii
        $dr_svc001      = "SVC_001"    ascii
        $dr_file001     = "FILE_001"   ascii

    condition:
        5 of ($jk_*) and 2 of ($dr_*)
}


rule B4B3RAT_Config_PersistenceMechanisms
{
    meta:
        description     = "B4B3-RAT: combination of persistence-related config strings in a single binary"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1547.001"
        level           = "high"

    strings:
        // Registry path used for both persistence and single-instance check
        $reg_path       = "Software\\4B4DB4B3"   ascii

        // Scheduler task name field (default from Builder)
        $schtask_key    = "schtasks /create"      ascii nocase

        // Drop-and-run path markers written to encrypted config
        $drop_marker    = ".exe"  ascii
        $autorun_flag   = "autorun" ascii nocase

        // Self-delete bat pattern
        $autodel_bat    = "@echo off" ascii
        $autodel_del    = "del "      ascii

    condition:
        $reg_path
        and ($schtask_key or ($autodel_bat and $autodel_del))
        and $drop_marker
}


rule B4B3RAT_Config_AntiAnalysis
{
    meta:
        description     = "B4B3-RAT: anti-analysis strings — process names checked against sandbox/AV tools"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1497.001"
        level           = "medium"

    strings:
        // Known analysis process names the Protector module kills
        $tool1          = "wireshark"     nocase ascii
        $tool2          = "processhacker" nocase ascii
        $tool3          = "procmon"       nocase ascii
        $tool4          = "ollydbg"       nocase ascii
        $tool5          = "x64dbg"        nocase ascii
        $tool6          = "fiddler"       nocase ascii

        // VM artifact strings
        $vm1            = "VBoxService"   nocase ascii
        $vm2            = "vmtoolsd"      nocase ascii
        $vm3            = "vmsrvc"        nocase ascii

    condition:
        // Needs at least 3 tool names AND at least 1 VM string
        3 of ($tool*) and 1 of ($vm*)
}
