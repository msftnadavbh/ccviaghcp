param([Parameter(Mandatory=$true)][string]$CaFile)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') {
    throw 'Run as the actual target user, not SYSTEM (including default RunCommand).'
}
$homeDir = Join-Path $env:LOCALAPPDATA 'CCviaGHCP'
$publicCa = Get-Content -LiteralPath $CaFile -Raw
if ($publicCa -notmatch '\A\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*\z') {
    throw 'CA must contain exactly one public PEM certificate, never a private key.'
}
New-Item -ItemType Directory -Force $homeDir | Out-Null
Copy-Item -LiteralPath $CaFile -Destination (Join-Path $homeDir 'lab-ca.crt')
$bashPaths = @("$env:ProgramFiles\Git\bin\bash.exe", "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe")
if (-not ($bashPaths | Where-Object { Test-Path $_ })) {
    throw 'Git Bash missing. Follow windows/README.md to verify and manually install the pinned official Git installer, then rerun bootstrap as this user.'
}
# Official versioned native binary, no remote script execution. Pins fetched from
# https://downloads.claude.ai/claude-code-releases/2.1.284/manifest.json.
$base = 'https://downloads.claude.ai/claude-code-releases/2.1.284'
$manifestSha256 = '89d15995a702c15a37cbc986a33cba415aa93e9671114971e137592aad7b2bd1'
$binarySha256 = '0416631e846f743110da5282409776fa1313e65f33a588aae066eaf8db0fda7d'
$stage = Join-Path ([IO.Path]::GetTempPath()) ('ccviaghcp-install-' + [Guid]::NewGuid())
New-Item -ItemType Directory $stage | Out-Null
try {
    $manifestFile = Join-Path $stage 'manifest.json'
    Invoke-WebRequest "$base/manifest.json" -UseBasicParsing -OutFile $manifestFile
    if ((Get-FileHash $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifestSha256) { throw 'Manifest hash mismatch.' }
    $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json
    if ($manifest.version -ne '2.1.284' -or $manifest.platforms.'win32-x64'.checksum -ne $binarySha256) { throw 'Unexpected native release manifest.' }
    $binaryFile = Join-Path $stage 'claude.exe'
    Invoke-WebRequest "$base/win32-x64/claude.exe" -UseBasicParsing -OutFile $binaryFile
    if ((Get-FileHash $binaryFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $binarySha256) { throw 'Native binary hash mismatch.' }
    $bin = Join-Path $env:USERPROFILE '.local\bin'
    New-Item -ItemType Directory -Force $bin | Out-Null
    Copy-Item $binaryFile (Join-Path $bin 'claude.exe')
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
$claude = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
if (-not (Test-Path $claude)) { throw 'Native Claude binary missing in RDP user profile.' }
$version = & $claude --version
if ($version -notmatch '^2\.1\.284\b') { throw 'Unexpected Claude version.' }
Copy-Item (Join-Path $PSScriptRoot 'launch.ps1') $homeDir
Copy-Item (Join-Path $PSScriptRoot 'verify.ps1') $homeDir
Write-Host "Nonsecret bootstrap complete. Optional diagnostic: $homeDir\verify.ps1. Use $homeDir\launch.ps1 for manual native Claude acceptance in this user session."
