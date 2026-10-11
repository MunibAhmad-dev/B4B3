# Android RAT — Module 38 Overview

This module is the complete, production-ready Android RAT built throughout the curriculum. This page is a quick reference for the source code in this module.

## What's in This Module

```
project/                        ← Android Studio project (open this folder)
  app/
    src/main/
      AndroidManifest.xml       ← component declarations, minimal permissions
      assets/config.json        ← XOR-encoded C2 host + auth key
      cpp/native_probe.cpp      ← C++ JNI kernel probe library
      java/com/company/rat/
        MainActivity.java       ← first-launch activity (starts service, hides itself)
        RatService.java         ← foreground service, beacon loop, command dispatch
        SelfSetup.java          ← root: grant permissions, enable accessibility, hide icon
        C2Client.java           ← HTTPS communication with C2 server
        KeylogService.java      ← accessibility-based keylogger
        RootKeylogger.java      ← su -c getevent keylogger
        NativeProbe.java        ← JNI bridge to native_probe.cpp
        KernelProbe.java        ← Java-level kernel interface tests
        MicCapture.java         ← MediaRecorder silent audio recording
        CameraCapture.java      ← Camera2 API silent photo
        ScreenCaptureActivity   ← MediaProjection screenshot
        DeviceData.java         ← SMS, contacts, location, device info
        FileEnumerator.java     ← external storage listing
        BootReceiver.java       ← auto-start on BOOT_COMPLETED
        SelfDestruct.java       ← remote wipe + uninstall
      CMakeLists.txt            ← NDK/CMake build for native_probe.cpp
    build.gradle                ← NDK config, R8 obfuscation, release signing

solutions/                      ← (empty — all code is in project/)
```

## Quick Build

```bash
# From project/ directory:
./gradlew assembleRelease

# APK output:
app/build/outputs/apk/release/app-release.apk
```

Requires NDK 27 + CMake 3.22.1 installed via Android Studio SDK Manager.

## Commands Reference (summary)

| Command | Description |
|---|---|
| `info` | Device info: model, Android version, operator |
| `keylogs` | Dump all three keylog sources (accessibility + root + native) |
| `screenshot` | Capture screen via MediaProjection |
| `cam` / `cam_back` | Silent front / back camera photo |
| `mic <secs>` | Record microphone (default 15s, max 120s) |
| `sms` | List SMS inbox |
| `contacts` | List all contacts |
| `location` | Last GPS coordinates |
| `files` | List external storage |
| `pull <path>` | Upload file from device to C2 |
| `shell <cmd>` | Run shell command |
| `kernel_probe` | Generate all kernel-level detection signals |
| `self_destruct` | Wipe traces + uninstall |

## Full Documentation

See the **Build Guide** section in the sidebar for:
- Complete build and deploy guide
- Code walkthrough (every file explained)
- Red team design methodology
- How to extend the RAT
