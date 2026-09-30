/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/

#include "Requests.h"

// Parse "host:port" or plain "host" → fills host_out and returns port (default 80)
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
    return INTERNET_DEFAULT_HTTP_PORT;
}

std::string Requests::GetRequestPinned(const char* url, const char* useragent, const char* path, const char* /*expectedCN*/) {
    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    InternetSetOption(0, 42, NULL, 0);
    HINTERNET hSocket = InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { InternetCloseHandle(hSocket); return ""; }

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", path, NULL, NULL, 0,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 1);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hSocket); return ""; }

    std::string result;
    if (HttpSendRequestA(hReq, NULL, 0, NULL, 0)) {
        BYTE buf[1024]; DWORD nr = 0;
        while (InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
            result.append((char*)buf, nr);
    }
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hSocket);
    return result;
}

std::string Requests::PostFilePinned(const char* url, const char* useragent, const char* path,
                                      const char* /*expectedCN*/, const char* localFilePath) {
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

    const char* boundary    = "----C2UPLOAD";
    const char* contentType = "Content-Type: multipart/form-data; boundary=----C2UPLOAD";

    std::string fname(localFilePath);
    size_t slash = fname.find_last_of("/\\");
    if (slash != std::string::npos) fname = fname.substr(slash + 1);

    std::string head = "--" + std::string(boundary) + "\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"" + fname + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string tail = "\r\n--" + std::string(boundary) + "--\r\n";

    DWORD bodyLen = (DWORD)(head.size() + fileData.size() + tail.size());
    std::vector<BYTE> body(bodyLen);
    memcpy(body.data(),                          head.c_str(),      head.size());
    memcpy(body.data() + head.size(),            fileData.data(),   fileData.size());
    memcpy(body.data() + head.size() + fileSize, tail.c_str(),      tail.size());

    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    InternetSetOption(0, 42, NULL, 0);
    std::string result;
    HINTERNET hSocket = InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { InternetCloseHandle(hSocket); return ""; }

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", path, NULL, NULL, 0,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 1);
    if (hReq) {
        if (HttpSendRequestA(hReq, contentType, (DWORD)strlen(contentType), body.data(), bodyLen)) {
            BYTE buf[1024]; DWORD nr = 0;
            while (InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
                result.append((char*)buf, nr);
        }
        InternetCloseHandle(hReq);
    }
    InternetCloseHandle(hConn);
    InternetCloseHandle(hSocket);
    return result;
}

void Requests::PostJsonPinned(const char* url, const char* useragent, const char* path,
                              const char* /*expectedCN*/, const char* json_body) {
    if (!json_body || !json_body[0]) return;

    DWORD bodyLen = (DWORD)strlen(json_body);
    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    InternetSetOption(0, 42, NULL, 0);
    HINTERNET hSocket = InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return;

    HINTERNET hConn = InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { InternetCloseHandle(hSocket); return; }

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", path, NULL, NULL, 0,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 1);
    if (hReq) {
        const char* ct = "Content-Type: application/json";
        HttpSendRequestA(hReq, ct, (DWORD)strlen(ct), (LPVOID)json_body, bodyLen);
        InternetCloseHandle(hReq);
    }
    InternetCloseHandle(hConn);
    InternetCloseHandle(hSocket);
}

std::string Requests::GetRequest(const char* url, const char* useragent, const char* path, const char* ContentType) {
    char host[256] = {};
    INTERNET_PORT port = ParseHost(url, host, sizeof(host));

    InternetSetOption(0, 42, NULL, 0);
    HINTERNET hSocket = InternetOpenA(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
    if (!hSocket) return "";

    HINTERNET hConn = InternetConnectA(hSocket, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    if (!hConn) { InternetCloseHandle(hSocket); return ""; }

    const char* reqPath = (path && path[0]) ? path : NULL;
    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", reqPath, NULL, NULL, 0,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 1);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hSocket); return ""; }

    std::string result;
    const char* ct = (ContentType && ContentType[0]) ? ContentType : NULL;
    if (HttpSendRequestA(hReq, ct, ct ? (DWORD)strlen(ct) : 0, NULL, 0)) {
        BYTE buf[1024]; DWORD nr = 0;
        while (InternetReadFile(hReq, buf, sizeof(buf), &nr) && nr > 0)
            result.append((char*)buf, nr);
    }
    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hSocket);
    return result;
}
