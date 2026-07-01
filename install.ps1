<#
install.ps1 — one-line installer for the secure-vibe CLI on Windows.

  irm https://raw.githubusercontent.com/ShieldNet-360/secure-vibe/main/install.ps1 | iex

Downloads the secure-vibe binary from the latest GitHub release, verifies its
SHA-256 against the release's SHA256SUMS.txt, installs it to
%LocalAppData%\secure-vibe\bin, fetches the library data tarball and extracts it
to the per-user data dir secure-vibe reads by default, and adds the bin dir to
your user PATH. Override with these environment variables:

  $env:SECURE_VIBE_BIN_DIR    install directory   (default: %LocalAppData%\secure-vibe\bin)
  $env:SECURE_VIBE_DATA_DIR   library data dir    (default: %LocalAppData%\secure-vibe)
  $env:SECURE_VIBE_VERSION    release tag         (default: latest)
  $env:SECURE_VIBE_BASE_URL   release base URL    (default: GitHub releases)

Prefer npm? `npm i -g @shieldnet360/secure-vibe` bundles the data. This script
is the no-Node path. Requires Windows 10 1803+ (ships `tar`).
#>
#Requires -Version 5
$ErrorActionPreference = 'Stop'

$Repo    = 'ShieldNet-360/secure-vibe'
$Bin     = 'secure-vibe.exe'
$BinDir  = if ($env:SECURE_VIBE_BIN_DIR)  { $env:SECURE_VIBE_BIN_DIR }  else { Join-Path $env:LOCALAPPDATA 'secure-vibe\bin' }
$DataDir = if ($env:SECURE_VIBE_DATA_DIR) { $env:SECURE_VIBE_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'secure-vibe' }
$Version = if ($env:SECURE_VIBE_VERSION)  { $env:SECURE_VIBE_VERSION }  else { 'latest' }

function Die($m) { Write-Host "install: error: $m" -ForegroundColor Red; exit 1 }

# Look up a filename's checksum in a sha256sum-style file.
function Get-Sum($sumsFile, $name) {
  foreach ($line in Get-Content $sumsFile) {
    $p = $line -split '\s+', 2
    if ($p.Count -eq 2 -and $p[1].TrimStart('*').Trim() -eq $name) { return $p[0].ToLower() }
  }
  return $null
}

# Windows release builds amd64 (runs on ARM64 Windows via x64 emulation).
$asset = 'secure-vibe-windows-amd64.exe'

# Resolve the release base URL / tag.
if ($env:SECURE_VIBE_BASE_URL) {
  $base = $env:SECURE_VIBE_BASE_URL
} elseif ($Version -eq 'latest') {
  try { $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'secure-vibe-install' } }
  catch { Die 'could not resolve the latest release (is a release published yet?)' }
  $base = "https://github.com/$Repo/releases/download/$($rel.tag_name)"
} else {
  $base = "https://github.com/$Repo/releases/download/$Version"
}

$tmp = Join-Path $env:TEMP ('sv-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  if (-not (Get-Command tar -ErrorAction SilentlyContinue)) { Die 'tar not found — needs Windows 10 1803+ (or use npm)' }

  $binTmp  = Join-Path $tmp $Bin
  $sumsTmp = Join-Path $tmp 'SHA256SUMS.txt'
  Write-Host "install: downloading $asset from $base"
  Invoke-WebRequest "$base/$asset" -OutFile $binTmp -UseBasicParsing

  # Verify the binary against SHA256SUMS.txt.
  try {
    Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumsTmp -UseBasicParsing
    $want = Get-Sum $sumsTmp $asset
    if ($want) {
      $got = (Get-FileHash $binTmp -Algorithm SHA256).Hash.ToLower()
      if ($want -ne $got) { Die "checksum mismatch for $asset (want $want, got $got)" }
      Write-Host 'install: checksum verified.'
    } else { Write-Warning "install: $asset not listed in SHA256SUMS.txt; skipping verification." }
  } catch { Write-Warning 'install: SHA256SUMS.txt unavailable; skipping checksum verification.' }

  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Move-Item -Force $binTmp (Join-Path $BinDir $Bin)
  Write-Host "install: installed secure-vibe -> $(Join-Path $BinDir $Bin)"

  # Fetch + extract the library data so init / status / scan / gate work with no checkout.
  $dataAsset = 'secure-vibe-data.tar.gz'
  $dataTmp   = Join-Path $tmp $dataAsset
  try {
    Invoke-WebRequest "$base/$dataAsset" -OutFile $dataTmp -UseBasicParsing
    if (Test-Path $sumsTmp) {
      $dw = Get-Sum $sumsTmp $dataAsset
      if ($dw -and ((Get-FileHash $dataTmp -Algorithm SHA256).Hash.ToLower() -ne $dw)) { Die "checksum mismatch for $dataAsset" }
    }
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    tar -xzf $dataTmp -C $DataDir
    if ($LASTEXITCODE -ne 0) { Die "failed to extract library data into $DataDir" }
    Write-Host "install: library data -> $DataDir"
  } catch { Write-Warning "install: $dataAsset unavailable; data-backed commands need ``secure-vibe update`` or --path." }

  # Add the bin dir to the user PATH if it is not already there.
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $BinDir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $BinDir), 'User')
    Write-Host "install: added $BinDir to your user PATH — open a new terminal to use secure-vibe."
  }

  & (Join-Path $BinDir $Bin) version
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
