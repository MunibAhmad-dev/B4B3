/*
  Exercise 04 — Screenshot Capture
  ----------------------------------
  Capture the screen and encode to JPEG using GDI+.

  Tasks:
  1. Write: std::vector<uint8_t> CaptureScreenBmp()
     Captures the primary screen as a raw BMP buffer using:
       GetDC(nullptr), CreateCompatibleDC, CreateCompatibleBitmap,
       BitBlt (SRCCOPY), GetDIBits.
     Returns the raw pixel bytes (no header, just RGB).

  2. Write: std::vector<uint8_t> CaptureScreenJpeg(int quality = 75)
     Uses GDI+ (Gdiplus::Bitmap, Gdiplus::EncoderParameters) to encode
     the captured screen as JPEG and return the bytes.
     Steps:
       - GdiplusStartup
       - Capture to HBITMAP (as in task 1)
       - Wrap in Gdiplus::Bitmap::FromHBITMAP
       - Get JPEG encoder CLSID with GetEncoderClsid()
       - Save to IStream (CreateStreamOnHGlobal)
       - Read stream bytes back into vector
       - GdiplusShutdown

  3. Write: void SaveToFile(const std::vector<uint8_t>& data, const char* path)
     Writes a byte vector to a file using WriteFile.

  4. In main():
     Capture the screen as JPEG, save to "screenshot.jpg".
     Print the file size in KB.

  Compile:
    g++ -std=c++17 -Wall -o ex04.exe ex04_screenshot.cpp
        -lgdiplus -lkernel32 -luser32 -lgdi32 -lole32
*/

#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "gdiplus")

// Helper: get CLSID of a GDI+ image encoder by mime type
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    auto* pImgCodecInfo = (Gdiplus::ImageCodecInfo*)malloc(size);
    GetImageEncoders(num, size, pImgCodecInfo);
    for (UINT j = 0; j < num; j++) {
        if (wcscmp(pImgCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImgCodecInfo[j].Clsid;
            free(pImgCodecInfo);
            return j;
        }
    }
    free(pImgCodecInfo);
    return -1;
}

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE
    return 0;
}
