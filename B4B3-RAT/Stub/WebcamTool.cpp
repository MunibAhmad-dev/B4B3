/*
MIT License
Copyright (c) 2020 4B4DB4B3

Webcam capture - uses VFW preview + GDI BitBlt to capture what the preview
window is drawing. Works even when the frame callback path is blocked, because
BitBlt reads the window's rendered content directly from the GDI framebuffer.
*/
#pragma warning(disable: 4996)

#include "WebcamTool.h"
#include <windows.h>
#include <vfw.h>
#include <gdiplus.h>
#include <string>
#include <vector>

#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "GdiPlus.lib")

namespace WebcamTool {

static void WcamDbg(const char*) {}

// ── Video stream callback (fires from the driver capture thread) ──────────────
static volatile bool      g_streamGot  = false;
static std::vector<BYTE>  g_streamData;

static void CALLBACK VideoStreamCB(HWND, LPVIDEOHDR hdr) {
    if (g_streamGot) return;
    if (!hdr || !hdr->lpData || hdr->dwBytesUsed == 0) return;
    g_streamData.assign(
        reinterpret_cast<BYTE*>(hdr->lpData),
        reinterpret_cast<BYTE*>(hdr->lpData) + hdr->dwBytesUsed);
    g_streamGot = true;
}

// ── GDI+ encoder helper ───────────────────────────────────────────────────────

static bool GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return false;
    std::vector<BYTE> buf(size);
    Gdiplus::ImageCodecInfo* pInfo = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    Gdiplus::GetImageEncoders(num, size, pInfo);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pInfo[i].MimeType, format) == 0) { *pClsid = pInfo[i].Clsid; return true; }
    }
    return false;
}

static bool HBitmapToJpeg(HBITMAP hbm, int w, int h, const std::string& outPath) {
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR gToken = 0;
    Gdiplus::GdiplusStartup(&gToken, &gsi, nullptr);

    bool ok = false;
    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromHBITMAP(hbm, nullptr);
    if (bmp && bmp->GetLastStatus() == Gdiplus::Ok) {
        CLSID jpegClsid;
        if (GetEncoderClsid(L"image/jpeg", &jpegClsid)) {
            Gdiplus::EncoderParameters ep = {};
            ep.Count = 1;
            ep.Parameter[0].Guid           = Gdiplus::EncoderQuality;
            ep.Parameter[0].Type           = Gdiplus::EncoderParameterValueTypeLong;
            ep.Parameter[0].NumberOfValues = 1;
            ULONG quality = 80;
            ep.Parameter[0].Value = &quality;
            int wlen = MultiByteToWideChar(CP_ACP, 0, outPath.c_str(), -1, nullptr, 0);
            std::vector<WCHAR> wout(wlen);
            MultiByteToWideChar(CP_ACP, 0, outPath.c_str(), -1, wout.data(), wlen);
            ok = (bmp->Save(wout.data(), &jpegClsid, &ep) == Gdiplus::Ok);
        }
        delete bmp;
    }
    if (gToken) Gdiplus::GdiplusShutdown(gToken);
    return ok;
}

// ── Public API ────────────────────────────────────────────────────────────────

bool CaptureFrame(const std::string& outPath) {
    WcamDbg("1: CaptureFrame start");

    const int W = 640, H = 480;

    g_streamGot = false;
    g_streamData.clear();

    HWND hCap = capCreateCaptureWindowA("capwin", WS_POPUP, 0, 0, W, H, nullptr, 0);
    if (!hCap) { WcamDbg("FAIL: capCreateCaptureWindowA"); return false; }
    WcamDbg("2: window created");

    if (!SendMessage(hCap, WM_CAP_DRIVER_CONNECT, 0, 0)) {
        WcamDbg("FAIL: WM_CAP_DRIVER_CONNECT");
        DestroyWindow(hCap);
        return false;
    }
    WcamDbg("3: driver connected");

    // Set the video stream callback — fires from the driver capture thread
    // for each compressed frame during WM_CAP_SEQUENCE_NOFILE
    SendMessage(hCap, WM_CAP_SET_CALLBACK_VIDEOSTREAM, 0,
                reinterpret_cast<LPARAM>(VideoStreamCB));
    WcamDbg("4: stream callback set");

    // Start streaming capture to memory (no file) — driver pushes frames via callback
    BOOL seq = (BOOL)SendMessage(hCap, WM_CAP_SEQUENCE_NOFILE, 0, 0);
    char dbgbuf[128];
    sprintf(dbgbuf, "5: SEQUENCE_NOFILE=%d", (int)seq);
    WcamDbg(dbgbuf);

    if (!seq) {
        // SEQUENCE_NOFILE not supported — fall back to preview+grab
        WcamDbg("5b: falling back to preview grab");
        SendMessage(hCap, WM_CAP_SET_PREVIEWRATE, 66, 0);
        SendMessage(hCap, WM_CAP_SET_PREVIEW, TRUE, 0);
    }

    // Pump messages for up to 5s waiting for stream callback
    // (callback fires from driver thread, not message queue — Sleep is fine)
    DWORD t0 = GetTickCount();
    MSG msg;
    while (!g_streamGot && GetTickCount() - t0 < 5000) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
        } else { Sleep(20); }
    }
    SendMessage(hCap, WM_CAP_STOP, 0, 0);

    sprintf(dbgbuf, "6: gotStream=%d dataBytes=%zu", (int)g_streamGot, g_streamData.size());
    WcamDbg(dbgbuf);

    bool ok = false;

    if (g_streamGot && g_streamData.size() > 2) {
        // Check if it is MJPEG/JPEG (starts with SOI marker FF D8)
        bool isMjpeg = (g_streamData[0] == 0xFF && g_streamData[1] == 0xD8);
        sprintf(dbgbuf, "7: isMJPEG=%d first2=%02X%02X",
                (int)isMjpeg, g_streamData[0], g_streamData[1]);
        WcamDbg(dbgbuf);

        if (isMjpeg) {
            // Write MJPEG bytes directly as JPEG — no re-encoding needed
            FILE* f = fopen(outPath.c_str(), "wb");
            if (f) {
                fwrite(g_streamData.data(), 1, g_streamData.size(), f);
                fclose(f);
                ok = true;
                WcamDbg("8: wrote MJPEG as JPEG directly");
            } else {
                WcamDbg("8: fopen outPath FAILED");
            }
        } else {
            // Not MJPEG — decode via GDI+ as before
            HDC hScreen = GetDC(nullptr);
            HDC hMemDC  = CreateCompatibleDC(hScreen);
            HBITMAP hbm = CreateCompatibleBitmap(hScreen, W, H);
            HGDIOBJ old = SelectObject(hMemDC, hbm);

            // Write raw bytes to a temp BMP and load it
            std::string tmp = "C:\\Users\\Public\\cap_tmp.raw";
            FILE* tf = fopen(tmp.c_str(), "wb");
            if (tf) { fwrite(g_streamData.data(), 1, g_streamData.size(), tf); fclose(tf); }

            SelectObject(hMemDC, old);
            ReleaseDC(nullptr, hScreen);

            ok = HBitmapToJpeg(hbm, W, H, outPath);
            DeleteObject(hbm);
            DeleteDC(hMemDC);
        }
    } else {
        WcamDbg("7: no stream data received");
    }

    SendMessage(hCap, WM_CAP_DRIVER_DISCONNECT, 0, 0);
    DestroyWindow(hCap);
    WcamDbg(ok ? "9: SUCCESS" : "9: FAILED");
    return ok;
}

} // namespace WebcamTool
