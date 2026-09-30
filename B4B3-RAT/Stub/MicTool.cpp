/*
MIT License
Copyright (c) 2020 4B4DB4B3

Microphone recording using the WinMM waveIn API.
- Opens the default recording device at 44100 Hz / 16-bit / stereo.
- Buffers audio for the requested number of seconds.
- Writes a standard PCM WAV file (RIFF header + raw samples).
*/
#pragma warning(disable: 4996)

#include "MicTool.h"
#include <windows.h>
#include <mmsystem.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "winmm.lib")

namespace MicTool {

// ── WAV file writer ───────────────────────────────────────────────────────────

static void WriteWav(const std::string& path,
                     const std::vector<BYTE>& pcm,
                     DWORD sampleRate, WORD channels, WORD bitsPerSample)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) return;

    DWORD dataSize   = static_cast<DWORD>(pcm.size());
    DWORD byteRate   = sampleRate * channels * (bitsPerSample / 8);
    WORD  blockAlign = channels * (bitsPerSample / 8);
    DWORD riffSize   = 36 + dataSize;

    // RIFF chunk
    f.write("RIFF", 4);
    f.write(reinterpret_cast<const char*>(&riffSize), 4);
    f.write("WAVE", 4);

    // fmt  sub-chunk
    f.write("fmt ", 4);
    DWORD fmtSize = 16;
    f.write(reinterpret_cast<const char*>(&fmtSize), 4);
    WORD audioFmt = 1; // PCM
    f.write(reinterpret_cast<const char*>(&audioFmt), 2);
    f.write(reinterpret_cast<const char*>(&channels), 2);
    f.write(reinterpret_cast<const char*>(&sampleRate), 4);
    f.write(reinterpret_cast<const char*>(&byteRate), 4);
    f.write(reinterpret_cast<const char*>(&blockAlign), 2);
    f.write(reinterpret_cast<const char*>(&bitsPerSample), 2);

    // data sub-chunk
    f.write("data", 4);
    f.write(reinterpret_cast<const char*>(&dataSize), 4);
    f.write(reinterpret_cast<const char*>(pcm.data()), dataSize);
}

// ── Public API ────────────────────────────────────────────────────────────────

bool Record(const std::string& outPath, int durationSec) {
    if (durationSec < 1)  durationSec = 1;
    if (durationSec > 60) durationSec = 60;  // cap at 60 s

    const DWORD SAMPLE_RATE  = 44100;
    const WORD  CHANNELS     = 1;       // mono — smaller file, still clear
    const WORD  BITS         = 16;
    const DWORD BLOCK_ALIGN  = CHANNELS * (BITS / 8);
    const DWORD BYTE_RATE    = SAMPLE_RATE * BLOCK_ALIGN;
    const DWORD TOTAL_BYTES  = BYTE_RATE * static_cast<DWORD>(durationSec);
    const DWORD BUF_SIZE     = BYTE_RATE;  // 1-second chunks

    WAVEFORMATEX wfx = {};
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = CHANNELS;
    wfx.nSamplesPerSec  = SAMPLE_RATE;
    wfx.wBitsPerSample  = BITS;
    wfx.nBlockAlign     = BLOCK_ALIGN;
    wfx.nAvgBytesPerSec = BYTE_RATE;

    HWAVEIN hWave = nullptr;
    if (waveInOpen(&hWave, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR)
        return false;

    // Prepare two alternating buffers (double-buffering)
    const int NUM_BUFS = 2;
    std::vector<std::vector<BYTE>> bufs(NUM_BUFS, std::vector<BYTE>(BUF_SIZE));
    WAVEHDR hdrs[NUM_BUFS] = {};
    for (int i = 0; i < NUM_BUFS; ++i) {
        hdrs[i].lpData         = reinterpret_cast<LPSTR>(bufs[i].data());
        hdrs[i].dwBufferLength = BUF_SIZE;
        waveInPrepareHeader(hWave, &hdrs[i], sizeof(WAVEHDR));
        waveInAddBuffer(hWave, &hdrs[i], sizeof(WAVEHDR));
    }

    std::vector<BYTE> recorded;
    recorded.reserve(TOTAL_BYTES);

    waveInStart(hWave);

    DWORD collected = 0;
    int   curBuf    = 0;

    while (collected < TOTAL_BYTES) {
        // Wait for current buffer to fill
        while (!(hdrs[curBuf].dwFlags & WHDR_DONE)) Sleep(10);

        DWORD got = hdrs[curBuf].dwBytesRecorded;
        DWORD take = std::min(got, TOTAL_BYTES - collected);
        recorded.insert(recorded.end(),
                        bufs[curBuf].begin(),
                        bufs[curBuf].begin() + take);
        collected += take;

        // Re-queue the buffer for next chunk (if more to record)
        if (collected < TOTAL_BYTES) {
            hdrs[curBuf].dwFlags = 0;
            hdrs[curBuf].dwBytesRecorded = 0;
            waveInPrepareHeader(hWave, &hdrs[curBuf], sizeof(WAVEHDR));
            waveInAddBuffer(hWave, &hdrs[curBuf], sizeof(WAVEHDR));
        }
        curBuf = (curBuf + 1) % NUM_BUFS;
    }

    waveInStop(hWave);
    waveInReset(hWave);

    for (int i = 0; i < NUM_BUFS; ++i)
        waveInUnprepareHeader(hWave, &hdrs[i], sizeof(WAVEHDR));

    waveInClose(hWave);

    if (recorded.empty()) return false;
    WriteWav(outPath, recorded, SAMPLE_RATE, CHANNELS, BITS);
    return true;
}

} // namespace MicTool
