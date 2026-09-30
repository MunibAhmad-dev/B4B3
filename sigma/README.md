# Sigma Detection Rules

Behavior-based detections for B4DB4B3-RAT observables.
Rules target Windows telemetry sources (Sysmon + Windows Security/System event logs)
and follow the [Sigma](https://github.com/SigmaHQ/sigma) specification — importable
into Splunk, Elastic, Microsoft Sentinel, QRadar, and any SIEM with a Sigma backend.

## Files

| File | Behaviors | ATT&CK |
|---|---|---|
| `run_key_persistence.yml` | Registry Run key writes from non-standard paths | T1547.001 |
| `suspicious_scheduled_task.yml` | Scheduled task pointing to Temp/AppData binary | T1053.005 |
| `unusual_service_creation.yml` | Service created from user-writable path (sc.exe + Event 4697/7045) | T1543.003 |
| `suspicious_process_injection.yml` | Cross-process injection, hollowing via unusual parent-child | T1055, T1055.012 |
| `suspicious_shell_execution.yml` | Encoded PowerShell, cmd.exe spawned from non-interactive parent | T1059.001, T1059.003 |
| `rat_c2_communication.yml` | HTTPS from non-browser process; Telegram API from non-Telegram process | T1071.001, T1102 |
| `unusual_screenshot_activity.yml` | JPEG/PNG written to Temp by non-imaging process | T1113 |
| `suspicious_file_encryption.yml` | Custom extension appends (.b4db4b3); bulk rename velocity | T1486 |
| `self_copying_executable.yml` | EXE written to AppData/ProgramData then executed | T1036, T1547, T1204.002 |
| `anti_analysis_process_enumeration.yml` | taskkill on analysis tools; rapid process access; VM registry checks | T1562.001, T1497.001, T1057 |

## Convert to SIEM query language

Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
pip install sigma-cli
```

Convert to Splunk SPL:
```bash
sigma convert -t splunk sigma/run_key_persistence.yml
```

Convert to Elastic (EQL):
```bash
sigma convert -t elasticsearch sigma/suspicious_file_encryption.yml
```

Convert to Microsoft Sentinel (KQL):
```bash
sigma convert -t microsoft365defender sigma/*.yml
```

## Sysmon requirements

Most rules require Sysmon with at minimum:
- Event ID 1  (process_creation)
- Event ID 3  (network_connection)
- Event ID 10 (process_access)
- Event ID 11 (file_event)
- Event ID 13 (registry_value_set)
- Event ID 23 (file_delete)

Recommended config: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

## Severity levels

| Level | Meaning |
|---|---|
| `critical` | Near-certain malicious activity; immediate response |
| `high` | Strong indicator; investigate promptly |
| `medium` | Suspicious; correlate with other signals |
| `low` | Informational; tune out FPs in your environment first |
