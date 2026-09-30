/*
  B4B3-RAT — Level 1: Exact IOC Detection
  =========================================
  Matches binary artifacts that are unique to this specific RAT family:
  the registry key name, the encrypted-file extension, the config marker,
  and the self-delete batch path.  Any one of these strings in a binary
  or memory region is a near-certain indicator.

  False-positive risk: very low — these strings have no legitimate use.
*/

rule B4B3RAT_ExactIOC_RegistryKey
{
    meta:
        description     = "Detects B4B3-RAT registry persistence key name"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        reference       = "B4B3-RAT analysis"
        attack_technique = "T1547.001"
        level           = "critical"
        hash_sample     = "n/a — generic family rule"

    strings:
        $reg_key        = "Software\\4B4DB4B3" nocase
        $reg_key_wide   = "Software\\4B4DB4B3" wide nocase

    condition:
        any of them
}


rule B4B3RAT_ExactIOC_EncryptionExtension
{
    meta:
        description     = "Detects B4B3-RAT encrypted-file extension appended by FileCryptor"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1486"
        level           = "critical"

    strings:
        $ext            = ".b4db4b3" nocase
        $ext_wide       = ".b4db4b3" wide nocase

    condition:
        any of them
}


rule B4B3RAT_ExactIOC_AuthorString
{
    meta:
        description     = "Detects the B4B3-RAT author marker string present in all builds"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        level           = "high"

    strings:
        $marker         = "4B4DB4B3" ascii
        $marker_wide    = "4B4DB4B3" wide
        $bat_autodel    = "4B4DB4B3_autodel.bat" nocase

    condition:
        any of them
}


rule B4B3RAT_ExactIOC_C2Endpoints
{
    meta:
        description     = "Detects B4B3-RAT custom C2 endpoint path strings"
        author          = "B4B3-RAT Red Team"
        date            = "2026-09-29"
        attack_technique = "T1071.001"
        level           = "high"

    strings:
        $ep_checkin     = "/checkin?id=" ascii
        $ep_cmd         = "/cmd?id="     ascii
        $ep_result      = "/result?id="  ascii
        $ep_upload      = "/upload?id="  ascii
        $ep_event       = "/event?id="   ascii
        $ep_ping        = "/ping"        ascii fullword

    condition:
        3 of them
}
