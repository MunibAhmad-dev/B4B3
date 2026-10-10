/*
  Solution 02 — File Enumerator by Extension (complete)
*/
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <numeric>

namespace fs = std::filesystem;

struct FileEntry {
    fs::path    path;
    uintmax_t   size;
    std::string ext;
};

const std::vector<std::string> TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".jpg", ".jpeg", ".png",
    ".bmp", ".mp4", ".zip", ".7z", ".rar", ".sql",
    ".mdb", ".accdb", ".pst", ".ost"
};

std::vector<FileEntry> enumerateFiles(const std::string& rootPath,
                                       const std::vector<std::string>& targetExts) {
    std::vector<FileEntry> results;
    std::error_code ec;

    for (const auto& entry : fs::recursive_directory_iterator(rootPath,
             fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file(ec)) continue;

        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        bool match = std::find(targetExts.begin(), targetExts.end(), ext) != targetExts.end();
        if (!match) continue;

        uintmax_t sz = entry.file_size(ec);
        if (ec) sz = 0;

        results.push_back({entry.path(), sz, ext});
    }

    std::sort(results.begin(), results.end(),
              [](const FileEntry& a, const FileEntry& b){ return a.path < b.path; });
    return results;
}

std::string fileSizeHuman(uintmax_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    double kb = bytes / 1024.0;
    if (kb < 1024.0) {
        std::ostringstream ss; ss << std::fixed << std::setprecision(1) << kb << " KB";
        return ss.str();
    }
    double mb = kb / 1024.0;
    if (mb < 1024.0) {
        std::ostringstream ss; ss << std::fixed << std::setprecision(1) << mb << " MB";
        return ss.str();
    }
    double gb = mb / 1024.0;
    std::ostringstream ss; ss << std::fixed << std::setprecision(2) << gb << " GB";
    return ss.str();
}

int main() {
    const std::string TEST_DIR = "C:\\RansomwareSimTest";

    if (!fs::exists(TEST_DIR)) {
        printf("[-] Create %s and add test files first.\n", TEST_DIR.c_str());
        return 1;
    }

    auto files = enumerateFiles(TEST_DIR, TARGET_EXTENSIONS);

    printf("%-60s  %10s  %s\n", "Path", "Size", "Extension");
    printf("%s\n", std::string(80, '-').c_str());

    std::map<std::string, int> extCount;
    uintmax_t totalBytes = 0;

    for (const auto& f : files) {
        printf("%-60s  %10s  %s\n",
               f.path.string().c_str(),
               fileSizeHuman(f.size).c_str(),
               f.ext.c_str());
        extCount[f.ext]++;
        totalBytes += f.size;
    }

    printf("\n--- Total: %zu files, %s ---\n", files.size(), fileSizeHuman(totalBytes).c_str());
    printf("By extension:");
    for (const auto& kv : extCount) printf("  %s=%d", kv.first.c_str(), kv.second);
    printf("\n");

    return 0;
}
