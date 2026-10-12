#pragma once
#ifndef RANSOMSIM_H
#define RANSOMSIM_H
#include "common.h"

namespace RansomSim {
    // Recursively encrypt every file in dir (skips already-.b4db4b3 files and files >50 MB).
    // Drops a _README.txt ransom note in each directory.
    // Detection: mass file extension change + shadow copy deletion pattern = T1486 Data Encrypted for Impact.
    // The whole chain (ransom encrypt → af vssdelete) fires every ransomware detection rule.
    std::string EncryptDir(const std::string& dir, const std::string& key);

    // Recursively decrypt all .b4db4b3 files and remove _README.txt notes.
    std::string DecryptDir(const std::string& dir, const std::string& key);
}

#endif
