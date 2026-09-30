# Android Sigma Detection Rules

Detection rules for Android mobile malware behaviors, mapped to MITRE ATT&CK for Mobile.
These rules target the B4DB4B3-RAT telemetry format (`product: b4db4b3_rat`, `category: android_telemetry`).

## Logsource

```yaml
logsource:
    product: b4db4b3_rat
    category: android_telemetry
```

For production MDM/SIEM environments, remap the logsource to:
- **VMware Workspace ONE**: `product: workspace_one, category: app_permission`
- **Microsoft Intune**: `product: intune, category: mobile_audit`
- **Zimperium zIPS**: `product: zimperium, category: behavioral_threat`
- **ADB logcat**: `product: android, category: logcat` (requires logcat collection pipeline)

## Rules

### Single-Event Detection Rules

| File | Rule ID | ATT&CK Technique | Severity | Description |
|------|---------|-----------------|----------|-------------|
| `android_camera_access.yml` | ACAM_001 | T1512 | High | Camera permission access |
| `android_microphone_access.yml` | AMIC_001 | T1429 | High | Microphone/audio recording |
| `android_background_location_tracking.yml` | ALOC_001/002 | T1430 | High/Critical | Location tracking (foreground/background) |
| `android_sms_intercept.yml` | ASMS_001/002 | T1412 | Critical | SMS read and send abuse |
| `android_accessibility_service_abuse.yml` | AACC_001 | T1411 | Critical | Accessibility service keylogging |
| `android_device_admin_activation.yml` | AADM_001 | T1626 | Critical | Device admin anti-uninstall |
| `android_boot_receiver_persistence.yml` | ABOOT_001 | T1624.001 | Medium | Boot receiver autostart |
| `android_overlay_attack.yml` | AOVL_001 | T1411 | High | SYSTEM_ALERT_WINDOW overlay |
| `android_suspicious_c2_communication.yml` | ANET_001/002 | T1437/T1521 | High | Suspicious C2 network traffic |
| `android_anti_analysis_evasion.yml` | AEMU_001 | T1633 | High | Frida/Xposed/emulator detection |
| `android_screen_capture.yml` | ASCR_001 | T1513 | High | MediaProjection screen capture |
| `android_root_access_attempt.yml` | AROOT_001 | T1626 | Critical | Root privilege escalation |
| `android_notification_listener_abuse.yml` | ANOT_001 | T1517 | High | Notification listener service |
| `android_foreground_service_persistence.yml` | AFGS_001 | T1541 | Medium | Foreground service persistence |
| `android_app_enumeration.yml` | AAPP_001/AAPK_001 | T1418 | Medium | Installed app enumeration |
| `android_call_log_access.yml` | ACALL_001/ACON_001 | T1432 | High | Call log and contacts access |
| `android_external_storage_exfiltration.yml` | AFILE_001 | T1533 | Medium | External storage data collection |
| `android_clipboard_monitoring.yml` | ACLIP_001 | T1409 | High | Clipboard credential theft |

### Correlation Rules (multi-event, time-windowed)

| File | Correlation ID | Confidence | Techniques | Description |
|------|---------------|------------|------------|-------------|
| `android_full_surveillance_correlation.yml` | ACOR_001 | 95% | T1512+T1429+T1430 | Camera + mic + location (10 min) |
| `android_spyware_persistence_c2_correlation.yml` | ACOR_003 | 90% | T1624.001+collection+T1437 | Full spyware cycle (10 min) |
| `android_credential_theft_overlay_correlation.yml` | ACOR_005 | 90% | T1411+T1437/T1521 | Overlay + accessibility + C2 (10 min) |

## ATT&CK for Mobile Coverage

```
Collection:         T1512 ✓  T1429 ✓  T1430 ✓  T1412 ✓  T1411 ✓  T1517 ✓
                    T1513 ✓  T1433 ✓  T1432 ✓  T1533 ✓  T1409 ✓
Discovery:          T1418 ✓
Persistence:        T1624.001 ✓  T1541 ✓
Privilege Esc:      T1626 ✓
Defense Evasion:    T1633 ✓
Command & Control:  T1437 ✓  T1521 ✓
Credential Access:  T1411 (overlay) ✓
```

## Usage with Coverage Tester

Run the Android coverage tester to validate these rules against live telemetry:

```bash
node android-module/android-simulator.js --scenario full_spyware --auth YOUR_KEY
node attack-simulator/coverage-tester.js --auth YOUR_KEY --platform android
```
