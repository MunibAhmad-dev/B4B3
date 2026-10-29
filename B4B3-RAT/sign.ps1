# sign.ps1 — Authenticode sign one or more executables with a self-signed cert.
#
# Creates "Microsoft Corporation" cert on first run, exports to sign.pfx.
# On the test machine run once with -Install (as Admin) to put the cert in
# Trusted Root CA + Trusted Publishers — UAC then shows a BLUE shield and
# "Verified publisher: Microsoft Corporation" instead of the orange
# "Unknown publisher" warning.
#
# Usage:
#   .\sign.ps1 -Files path\to\a.exe, path\to\b.exe
#   .\sign.ps1 -Files a.exe -Install    # also trust the cert (run as Admin)
#   .\sign.ps1 -Subject "Adobe Systems Incorporated" -Files a.exe

param(
    [string[]]$Files   = @(),
    [string]  $Subject = "Microsoft Corporation",
    [string]  $PfxPath = "$PSScriptRoot\sign.pfx",
    [string]  $PfxPass = "RedTeam2026!",
    [switch]  $Install         # import to Trusted Root + TrustedPublisher (requires Admin)
)

$pw = ConvertTo-SecureString -String $PfxPass -Force -AsPlainText

# ── 1. Create or reload the cert ──────────────────────────────────────────────
if (-not (Test-Path $PfxPath)) {
    Write-Host "[sign] Generating code-signing certificate: CN=$Subject" -ForegroundColor Cyan

    # Use OpenSSL to create a portable PKCS12 PFX (no DPAPI, importable on any machine)
    $ssl = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    if (-not (Test-Path $ssl)) { $g = Get-Command openssl -ErrorAction SilentlyContinue; if ($g) { $ssl = $g.Source } }
    if (-not $ssl) { Write-Host "[sign] ERROR: openssl not found" -ForegroundColor Red; exit 1 }

    $tmp    = [System.IO.Path]::GetTempPath()
    $keyF   = "$tmp\sign_$([System.IO.Path]::GetRandomFileName()).key"
    $crtF   = "$tmp\sign_$([System.IO.Path]::GetRandomFileName()).crt"
    $subj   = "/CN=$Subject/O=$Subject/L=Redmond/ST=Washington/C=US"
    $extF   = "$tmp\sign_ext.cfg"
    "[codesign]`nextendedKeyUsage = codeSigning`nkeyUsage = digitalSignature" | Out-File $extF -Encoding ascii

    & $ssl genrsa   -out $keyF 2048 2>$null
    & $ssl req -new -key $keyF -x509 -days 1825 -out $crtF -subj $subj `
               -extfile $extF -extensions codesign 2>$null
    & $ssl pkcs12 -export -out $PfxPath -inkey $keyF -in $crtF -passout "pass:$PfxPass" 2>$null
    Remove-Item $keyF,$crtF,$extF -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $PfxPath)) {
        Write-Host "[sign] ERROR: failed to create PFX" -ForegroundColor Red; exit 1
    }

    # Import to CurrentUser\My
    $cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation "Cert:\CurrentUser\My" `
                -Password $pw -Exportable
    Write-Host "[sign] Certificate saved: $PfxPath" -ForegroundColor Green
} else {
    # PFX created with New-SelfSignedCertificate is DPAPI-protected — the private key
    # stays in CurrentUser\My; Import-PfxCertificate with a password won't re-import it
    # from a different session. Look for the cert in the store first, fall back to PFX.
    $cert = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert |
                Where-Object { $_.Subject -like "*$Subject*" } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1
    if (-not $cert) {
        # Try PFX import — OpenSSL-generated PFX is PKCS12 (no DPAPI), importable anywhere
        try {
            $cert = Import-PfxCertificate -FilePath $PfxPath `
                        -CertStoreLocation "Cert:\CurrentUser\My" `
                        -Password $pw -Exportable -ErrorAction Stop
        } catch {
            Write-Host "[sign] ERROR: cert not in store and PFX import failed." -ForegroundColor Red
            Write-Host "[sign] Run sign.ps1 without -PfxPath to generate a new cert." -ForegroundColor Yellow
            exit 1
        }
    }
    if (-not $cert) {
        Write-Host "[sign] ERROR: could not load certificate from store or PFX." -ForegroundColor Red
        exit 1
    }
    Write-Host "[sign] Loaded certificate: $($cert.Subject)"
}

# ── 2. Optionally install cert to Trusted Root CA + Trusted Publishers ─────────
# This step makes Windows trust the cert — UAC shows blue shield + verified publisher.
# Run once on each test machine (requires local Admin).
if ($Install) {
    Write-Host "[sign] Installing to Trusted Root CA and Trusted Publishers ..." -ForegroundColor Yellow
    $der = $cert.Export("Cert")
    $tmpCer = [System.IO.Path]::GetTempFileName() + ".cer"
    [System.IO.File]::WriteAllBytes($tmpCer, $der)
    Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root"        | Out-Null
    Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
    Remove-Item $tmpCer -Force
    Write-Host "[sign] Done. UAC will now show blue shield for this publisher." -ForegroundColor Green
}

# ── 3. Trust the cert in CurrentUser\Root so Set-AuthenticodeSignature accepts it ──
# CurrentUser\Root does NOT require Admin. The cert stays here — it's a test cert
# the operator controls, so keeping it in the personal root store is expected.
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$rootStore.Open("ReadWrite")
$alreadyTrusted = ($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }).Count -gt 0
if (-not $alreadyTrusted) {
    $rootStore.Add($cert)
    Write-Host "[sign] Added cert to CurrentUser\Root (required for Authenticode)" -ForegroundColor Cyan
}
$rootStore.Close()

# ── 4. Sign each file ──────────────────────────────────────────────────────────
if ($Files.Count -eq 0) {
    Write-Host "[sign] No files specified. Use -Files path\to\exe.exe"
    exit 0
}

$ok  = 0
$bad = 0
foreach ($f in $Files) {
    if (-not (Test-Path $f)) { Write-Warning "Not found: $f"; $bad++; continue }
    $result = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256
    if ($result.Status -eq "Valid") {
        $sz = [math]::Round((Get-Item $f).Length / 1024)
        Write-Host "[sign] SIGNED  $f  ($sz KB)" -ForegroundColor Green
        $ok++
    } else {
        Write-Host "[sign] FAILED  $f  [$($result.Status)] $($result.StatusMessage)" -ForegroundColor Red
        $bad++
    }
}

Write-Host ""
if ($bad -eq 0) {
    Write-Host "[sign] All $ok file(s) signed successfully." -ForegroundColor Green
} else {
    Write-Host "[sign] $ok signed, $bad failed." -ForegroundColor Yellow
}
