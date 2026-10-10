/*
 * Exercise 04 — Wi-Fi Saved Password (PSK) Extraction
 * Module 11: Credential Access
 *
 * Task: Enumerate all saved Wi-Fi profiles on the system and extract their
 * Pre-Shared Keys (PSKs) using the Native Wi-Fi API.
 *
 * IMPORTANT — ELEVATION REQUIRED:
 *   WlanGetProfile with the WLAN_PROFILE_GET_PLAINTEXT_KEY flag requires that
 *   the calling process is running as a local administrator (elevated).
 *   Without elevation the API returns the XML profile but the <keyMaterial>
 *   tag will contain an obfuscated (encrypted) value, not the plain PSK.
 *   Run this program from an elevated ("Run as Administrator") command prompt.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o ex04.exe exercise_04_wifi_psk.cpp -lwlanapi -lole32
 *
 * Usage:
 *   ex04.exe
 *
 * Key APIs:
 *   WlanOpenHandle       — open a handle to the WLAN service
 *   WlanEnumInterfaces   — list all wireless network interfaces
 *   WlanGetProfileList   — list all saved profiles on an interface
 *   WlanGetProfile       — retrieve a profile's XML including the key
 *   WlanFreeMemory       — release memory allocated by Wlan APIs
 *   WlanCloseHandle      — close the WLAN handle
 *
 * The returned profile is an XML string.  The PSK lives in:
 *   <WLANProfile>
 *     <MSM>
 *       <security>
 *         <sharedKey>
 *           <keyMaterial>YOUR_PSK_HERE</keyMaterial>
 *         </sharedKey>
 *       </security>
 *     </MSM>
 *   </WLANProfile>
 */

#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

// ----------------------------------------------------------------------------
// Helper: extract text between <tag> and </tag> from an XML string.
// Returns empty string if tag not found.
// ----------------------------------------------------------------------------
std::wstring ExtractXmlTag(const std::wstring& xml, const std::wstring& tag) {
    std::wstring openTag  = L"<"  + tag + L">";
    std::wstring closeTag = L"</" + tag + L">";

    size_t start = xml.find(openTag);
    if (start == std::wstring::npos) return L"";
    start += openTag.size();

    size_t end = xml.find(closeTag, start);
    if (end == std::wstring::npos) return L"";

    return xml.substr(start, end - start);
}

// =========================================================================
// TODO 1 — Open a handle to the WLAN service.
//
//   DWORD  dwNegotiatedVersion = 0;
//   HANDLE hClient = NULL;
//
//   DWORD result = WlanOpenHandle(
//       2,                      // dwClientVersion: 2 = Vista+
//       NULL,                   // pReserved
//       &dwNegotiatedVersion,   // receives actual negotiated version
//       &hClient                // receives the handle
//   );
//
//   Check result == ERROR_SUCCESS. On failure print the error code and return 1.
//   Print dwNegotiatedVersion to confirm the negotiated version.
// =========================================================================

// =========================================================================
// TODO 2 — Enumerate wireless interfaces.
//
//   PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
//
//   DWORD result = WlanEnumInterfaces(
//       hClient,   // handle from TODO 1
//       NULL,      // reserved
//       &pIfList   // receives pointer to interface list
//   );
//
//   Check result == ERROR_SUCCESS.
//   pIfList->dwNumberOfItems gives the interface count.
//   pIfList->InterfaceInfo[i] is a WLAN_INTERFACE_INFO with:
//     .InterfaceGuid   — GUID of the adapter
//     .strInterfaceDescription — friendly name (WCHAR)
//
//   Loop over each interface and proceed to TODO 3.
//   Free with WlanFreeMemory(pIfList) when done.
// =========================================================================

// =========================================================================
// TODO 3 — Get the list of saved profiles on each interface.
//
//   PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
//
//   DWORD result = WlanGetProfileList(
//       hClient,                            // WLAN handle
//       &pIfList->InterfaceInfo[i].InterfaceGuid, // interface GUID
//       NULL,                               // reserved
//       &pProfileList                       // receives profile list
//   );
//
//   pProfileList->dwNumberOfItems gives count.
//   pProfileList->ProfileInfo[j].strProfileName is the SSID/profile name (WCHAR).
//
//   For each profile, proceed to TODO 4.
//   Free with WlanFreeMemory(pProfileList) when done.
// =========================================================================

// =========================================================================
// TODO 4 — Retrieve each profile's XML including the plaintext key.
//
//   PWSTR  pProfileXml = NULL;
//   DWORD  dwFlags     = WLAN_PROFILE_GET_PLAINTEXT_KEY;
//   DWORD  dwGrantedAccess = 0;
//
//   DWORD result = WlanGetProfile(
//       hClient,
//       &pIfList->InterfaceInfo[i].InterfaceGuid,
//       pProfileList->ProfileInfo[j].strProfileName,
//       NULL,               // reserved
//       &pProfileXml,       // receives XML string (PWSTR)
//       &dwFlags,           // in/out flags
//       &dwGrantedAccess    // receives access flags
//   );
//
//   On ERROR_ACCESS_DENIED: print "[requires elevation]" and continue.
//   On ERROR_SUCCESS:
//     - Convert pProfileXml (PWSTR) to std::wstring
//     - Call ExtractXmlTag(xml, L"keyMaterial") to get the PSK
//     - If the tag is missing or empty, the profile may be open (no password)
//     - Print: SSID | PSK (or [OPEN] / [ENCRYPTED — not elevated])
//   Free pProfileXml with WlanFreeMemory(pProfileXml).
// =========================================================================

// =========================================================================
// TODO 5 — Clean up.
//   WlanFreeMemory(pProfileList) after processing each interface.
//   WlanFreeMemory(pIfList)      after processing all interfaces.
//   WlanCloseHandle(hClient, NULL) at the end.
// =========================================================================

int main() {
    printf("=== Exercise 04: Wi-Fi Saved PSK Extraction ===\n");
    printf("NOTE: Run as Administrator for plaintext keys.\n\n");

    HANDLE hClient             = NULL;
    DWORD  dwNegotiatedVersion = 0;

    // TODO 1: Open WLAN handle

    // TODO 2: Enumerate interfaces

    // TODO 3 + 4: For each interface, get profiles and extract PSKs

    // TODO 5: Cleanup

    printf("TODO: implement the steps above.\n");

    printf("\n[*] Done.\n");
    return 0;
}
