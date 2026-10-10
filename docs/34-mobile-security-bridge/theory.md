# Module 34 — Mobile Security Bridge

## Overview

This module bridges from desktop/network security to Android mobile security. You will learn to inspect APK files without needing decompilers, understand the binary formats that Android actually stores on disk, analyze permissions for malware indicators, and interact with live devices via ADB.

---

## 1. APK Structure

An APK (Android Package) is a standard ZIP archive. You can open any `.apk` with `zipfile.ZipFile` or even rename it to `.zip` and unzip it. Key contents:

| Path | Description |
|------|-------------|
| `AndroidManifest.xml` | Binary-encoded XML (AXML format) — NOT plain text |
| `classes.dex` | Dalvik Executable — all compiled Java/Kotlin bytecode |
| `classes2.dex`, `classes3.dex` | Additional DEX files (multidex) |
| `resources.arsc` | Compiled resource table (strings, layouts indexed by ID) |
| `lib/<abi>/*.so` | Native libraries for each CPU architecture |
| `assets/` | Raw asset files accessible via AssetManager |
| `META-INF/MANIFEST.MF` | File digest manifest |
| `META-INF/*.RSA` or `*.DSA` | DER-encoded PKCS#7 signature certificate |
| `res/` | Compiled layout XML files and drawables |
| `kotlin/` | Kotlin metadata (optional) |

```
app.apk (ZIP)
├── AndroidManifest.xml       ← binary AXML
├── classes.dex               ← DEX bytecode
├── resources.arsc            ← compiled resources
├── lib/
│   ├── arm64-v8a/libfoo.so
│   └── armeabi-v7a/libfoo.so
├── assets/
│   └── config.json
└── META-INF/
    ├── CERT.RSA
    └── MANIFEST.MF
```

The presence of certain files is itself a signal:
- Multiple DEX files → large app or deliberate code splitting to hide classes
- Files in `assets/` with high entropy → encrypted payloads
- `.so` files outside `lib/` → unusual, worth examining
- `lib/<abi>/libdvm.so` or JNI with suspicious names → potential rootkit

---

## 2. Android Binary XML (AXML) Format

The `AndroidManifest.xml` inside an APK is **not** plain XML. It is compiled into a binary format by the Android build tools (aapt). You must parse this binary format to read permissions, package names, activities, and receivers.

### 2.1 File-Level Structure

AXML is a chunked binary format. Every section starts with a 4-byte **chunk type** and a 4-byte **chunk size** (little-endian). The file always begins with:

```
Offset  Size  Field
0       4     File magic: 0x00080003 (chunk type = XML)
4       4     File size (total bytes)
```

Verify the magic: `struct.unpack_from('<I', data, 0)` should equal `0x00080003`. If it does not, the manifest was not compiled by aapt (rare).

### 2.2 Chunk Types

| Chunk Type (LE uint32) | Name |
|------------------------|------|
| `0x001C0001` | String Pool |
| `0x00080180` | Resource Map |
| `0x00100100` | XML Start Namespace |
| `0x00100101` | XML End Namespace |
| `0x00100102` | XML Start Element |
| `0x00100103` | XML End Element |
| `0x00100104` | XML CDATA |

### 2.3 String Pool Chunk (`0x001C0001`)

The string pool stores all string values used in the XML tree (element names, attribute names, attribute values). Layout:

```
Offset  Size  Field
0       4     Chunk type: 0x001C0001
4       4     Chunk size
8       4     string_count
12      4     style_count
16      4     flags  (0x100 = UTF-8 encoded, else UTF-16LE)
20      4     strings_start  (offset from chunk start to first string data)
24      4     styles_start
28+     4*n   String offsets (n = string_count), relative to strings_start
```

Each string is stored as:
- **UTF-16LE** (flags & 0x100 == 0): 2-byte length prefix + UTF-16LE chars + 2-byte null terminator
- **UTF-8** (flags & 0x100 != 0): 1-or-2-byte encoded length prefix + UTF-8 chars + null byte

### 2.4 XML Start Element (`0x00100102`)

```
Offset  Size  Field
0       4     Chunk type: 0x00100102
4       4     Chunk size
8       4     Line number (in original XML)
12      4     Comment string index (-1 = none)
16      4     Namespace string index (-1 = default NS)
20      4     Name string index
24      4     Attribute start offset (usually 0x14 = 20)
28      2     Attribute size (bytes per attribute, usually 0x14 = 20)
30      2     Attribute count
32      2     idAttribute index + 1 (0 = none)
34      2     classAttribute index + 1
36      2     styleAttribute index + 1
38+     20*n  Attributes (n = attribute_count)
```

Each attribute is 20 bytes:
```
0   4  Namespace string index
4   4  Name string index
8   4  Raw value string index (-1 if typed)
12  4  Data type (see below)
16  4  Data value
```

Data types:
- `0x03` = String (data = string pool index)
- `0x10` = Integer (data = raw int32)
- `0x11` = Boolean (data: 0 = false, != 0 = true)
- `0x01` = Reference (data = resource ID)

### 2.5 Parsing the Manifest

To find `<uses-permission android:name="...">`:
1. Read the string pool (get all strings).
2. Walk the XML tree looking for Start Element chunks where `name_idx` resolves to `"uses-permission"`.
3. For each such element, find the attribute where name is `"name"` and read its string value.

---

## 3. DEX File Format

`classes.dex` contains all compiled bytecode for the application. Understanding its structure lets you extract strings (URLs, keys, commands) without a decompiler.

### 3.1 Header (`header_item`, 112 bytes at offset 0)

```
Offset  Size  Field
0       8     magic: "dex\n035\0" or "dex\n036\0" or "dex\n037\0"
8       4     checksum (Adler-32 of bytes 12..end)
12      20    SHA-1 hash (bytes 32..end)
32      4     file_size
36      4     header_size (always 0x70 = 112)
40      4     endian_tag (0x12345678 = little-endian)
44      4     link_size
48      4     link_off
52      4     map_off
56      4     string_ids_size       ← number of strings
60      4     string_ids_off        ← offset to string ID list
64      4     type_ids_size
68      4     type_ids_off
72      4     proto_ids_size
76      4     proto_ids_off
80      4     field_ids_size
84      4     field_ids_off
88      4     method_ids_size
92      4     method_ids_off
96      4     class_defs_size
100     4     class_defs_off
104     4     data_size
108     4     data_off
```

### 3.2 String Table

The string IDs section is an array of `string_ids_size` uint32 values, each pointing to a `string_data_item`:

```
string_id_list[i] = uint32 offset to string_data_item
```

A `string_data_item` stores:
1. **ULEB128-encoded length** (number of UTF-16 code units)
2. **MUTF-8-encoded bytes** (Modified UTF-8 — Java's internal encoding; differs from standard UTF-8 only in null character encoding: null is `0xC0 0x80` not `0x00`, and supplementary characters use two CESU-8 surrogates)
3. **Null terminator byte** `0x00`

### 3.3 ULEB128 Encoding

ULEB128 (Unsigned Little-Endian Base 128) encodes variable-length integers:
- Each byte stores 7 bits of value in the low bits.
- If the high bit is 1, more bytes follow; if 0, this is the last byte.

```python
def read_uleb128(data, offset):
    result = 0
    shift  = 0
    while True:
        byte    = data[offset]; offset += 1
        result |= (byte & 0x7F) << shift
        shift  += 7
        if not (byte & 0x80):
            break
    return result, offset
```

### 3.4 Interesting Strings to Extract

When you dump all strings from a DEX file, look for:

| Category | Pattern | Significance |
|----------|---------|--------------|
| URLs | `http://`, `https://` | C2 endpoints, exfil targets |
| IP addresses | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | Hardcoded server IPs |
| Base64 blobs | 32+ chars matching `[A-Za-z0-9+/]{32,}={0,2}` | Encoded payloads |
| Root commands | `su`, `busybox`, `mount -o remount`, `/system/xbin` | Root exploit / rootkit |
| Crypto material | 32/64 hex chars, `BEGIN RSA PRIVATE KEY` | Hardcoded keys |
| Credentials | `password=`, `apikey=`, `token=` followed by value | Hardcoded secrets |
| ADB | `adb connect`, `tcpip`, `forward` | Remote ADB abuse |
| Package names | `com.google.android.gms` vs unknown prefixes | Check for spoofing |

---

## 4. Android Permission Model

### 4.1 Protection Levels

| Level | Meaning |
|-------|---------|
| `normal` | Granted automatically, not shown to user during install |
| `dangerous` | Requires runtime prompt (Android 6.0+); shown during install on older |
| `signature` | Only granted to apps signed with the same certificate as the definer |
| `signatureOrSystem` | Granted to system apps or same-signature apps |

### 4.2 Dangerous Permissions (Runtime Prompt)

These are the permissions Android surfaces to the user because they access sensitive data or device features:

```
READ_CONTACTS           WRITE_CONTACTS        GET_ACCOUNTS
READ_CALL_LOG           WRITE_CALL_LOG        PROCESS_OUTGOING_CALLS
READ_SMS                SEND_SMS              RECEIVE_SMS
RECORD_AUDIO            CAMERA
ACCESS_FINE_LOCATION    ACCESS_COARSE_LOCATION  ACCESS_BACKGROUND_LOCATION
READ_EXTERNAL_STORAGE   WRITE_EXTERNAL_STORAGE  MANAGE_EXTERNAL_STORAGE
READ_PHONE_STATE        READ_PHONE_NUMBERS    CALL_PHONE
ANSWER_PHONE_CALLS      ADD_VOICEMAIL         USE_SIP
BODY_SENSORS            ACTIVITY_RECOGNITION
```

### 4.3 Dangerous Permission Combinations That Indicate Malware

| Combination | Malware Type | Severity |
|-------------|-------------|----------|
| `RECORD_AUDIO` + `INTERNET` | Remote microphone tap | CRITICAL |
| `CAMERA` + `INTERNET` | Remote camera streaming | CRITICAL |
| `READ_SMS` + `SEND_SMS` | SMS fraud / 2FA interception | CRITICAL |
| `READ_SMS` + `INTERNET` | SMS exfiltration | CRITICAL |
| `PROCESS_OUTGOING_CALLS` + `INTERNET` | Call interception | HIGH |
| `ACCESS_FINE_LOCATION` + `ACCESS_BACKGROUND_LOCATION` | Persistent tracking | HIGH |
| `READ_CONTACTS` + `INTERNET` | Contact exfiltration | HIGH |
| `READ_CALL_LOG` + `INTERNET` | Call log exfiltration | HIGH |
| `BIND_DEVICE_ADMIN` | Ransomware / persistence | CRITICAL |
| `BIND_ACCESSIBILITY_SERVICE` | UI scraping / auto-tap | CRITICAL |
| `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE` | Overlay attack | CRITICAL |
| `REQUEST_INSTALL_PACKAGES` | Dropper / secondary install | HIGH |
| `RECEIVE_BOOT_COMPLETED` + suspicious combos | Boot persistence | HIGH |

**`BIND_DEVICE_ADMIN`**: allows the app to become a Device Administrator. Malware uses this to prevent removal (the user must first revoke admin status before uninstalling).

**`BIND_ACCESSIBILITY_SERVICE`**: designed for screen readers but abused by banking trojans to auto-tap, read screen content, and perform actions on behalf of the user without their knowledge.

---

## 5. ADB Basics

ADB (Android Debug Bridge) is the primary command-line tool for communicating with Android devices and emulators. The device must have Developer Options and USB Debugging enabled.

### 5.1 Essential Commands

```bash
# List connected devices with model info
adb devices -l

# Run a shell command on a specific device
adb -s <serial> shell <command>

# Copy a file from device to local machine
adb -s <serial> pull /data/local/tmp/file.bin .

# Push a file from local machine to device
adb -s <serial> push myfile.txt /sdcard/

# Install an APK
adb -s <serial> install app.apk

# Show running processes
adb shell ps -A

# Show installed packages with paths
adb shell pm list packages -f

# Pull entire APK for an installed package
adb shell pm path com.example.app
# Then: adb pull /data/app/com.example.app-1/base.apk

# Read device properties
adb shell getprop ro.product.model
adb shell getprop ro.debuggable    # 1 = debug build (low trust)

# View network connections
adb shell netstat -tlnp
adb shell ss -tlnp

# Live logcat
adb logcat
adb logcat -s "ActivityManager" "PackageManager"
```

### 5.2 Root Indicators via ADB

```bash
# Check for su binary
adb shell which su
adb shell ls /system/xbin/su
adb shell ls /sbin/su

# Check for Magisk
adb shell ls /data/adb/magisk

# Check for busybox (often bundled with root)
adb shell which busybox

# Check USB config (tcpip mode = ADB over network enabled)
adb shell getprop persist.sys.usb.config
```

---

## 6. Static Analysis Without Decompilation

Before using jadx or apktool, you can extract significant intelligence using only stdlib tools:

### 6.1 String Extraction from DEX

The DEX string table contains all literal strings used in the app: URLs, filenames, class names, SQL queries, package names, error messages, and API keys. You do not need to decompile to read these. Parse the DEX header to find `string_ids_off`, then follow each offset to read `string_data_item` entries.

### 6.2 Smali Pattern Search

If you have smali output (from apktool), you can grep for patterns:
```bash
grep -r "invoke-virtual.*sendTextMessage" smali/
grep -r "getSystemService.*LOCATION" smali/
```
Without smali, search raw strings for sensitive class names like `android/telephony/SmsManager` or `android/location/LocationManager`.

### 6.3 Native Library Analysis

For `.so` files under `lib/`:
- Check the ELF header magic: `\x7fELF` at offset 0
- Byte at offset 4: `1` = 32-bit, `2` = 64-bit
- Byte at offset 5: `1` = little-endian, `2` = big-endian
- Bytes 18-19 (uint16 LE): machine type (`0x28` = ARM, `0xB7` = AArch64, `0x03` = x86, `0x3E` = x86-64)
- Run `strings` on the `.so` to find C-level URLs and command strings

### 6.4 Entropy Analysis of Assets

Encrypted or compressed payloads in `assets/` have high Shannon entropy (close to 8 bits/byte). Calculate entropy:

```python
import math, collections

def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total  = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())
```

Entropy > 7.5 on a non-media file in `assets/` is suspicious.

---

## 7. APK Signing

Every APK must be signed before distribution. The signature lives in `META-INF/`:
- `CERT.RSA` or `CERT.DSA` — DER-encoded PKCS#7 (CMS) `SignedData` structure containing the signer certificate and signature
- `CERT.SF` — list of file digests (SHA-256 hashes of each file in the APK)
- `MANIFEST.MF` — SHA-256 hashes of compressed file contents

The PKCS#7 DER structure begins with the sequence tag `0x30 0x82`. The embedded X.509 certificate can be parsed to extract:
- Subject DN (who claims to own this app)
- Issuer DN (who signed the cert; if same as subject = self-signed)
- Validity period (not-before, not-after)
- Public key

**Self-signed certificate** is the norm for Android apps — unlike HTTPS, there is no CA chain. What matters is consistency: if the same certificate signed all versions of an app from one developer, it is consistent. A certificate that claims to be Google but was not issued by Google is suspicious.

**Certificate fingerprint** (SHA-256 of the DER cert bytes) is how app stores track identity. A change in fingerprint between versions means someone repackaged the app (common in repackaged malware).

---

## 8. Key Takeaways

1. APKs are ZIP files — open with `zipfile.ZipFile`, no special tools needed.
2. `AndroidManifest.xml` is binary AXML — you must parse the binary format to read permissions.
3. DEX strings are accessible without decompilation by parsing the string ID table and ULEB128 lengths.
4. Dangerous permission combinations are the fastest malware signal before any code analysis.
5. ADB gives live insight into a running device: processes, network, files, logs.
6. Entropy analysis on `assets/` reveals encrypted payloads.
7. Self-signed certs are normal; mismatched fingerprints between versions are not.
