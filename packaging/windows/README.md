# SecureVibe — Windows MSI installer

Build a Windows `.msi` for the `secure-vibe` CLI (part of **SecureVibe**)
using the [WiX Toolset](https://wixtoolset.org/) v4+.

## Prerequisites

1. Install the WiX Toolset: https://wixtoolset.org/docs/intro/
2. Build the CLI binary (from the repo root on a Windows machine or via
   cross-compilation):

   ```powershell
   $env:GOOS = "windows"
   $env:GOARCH = "amd64"
   go build -trimpath -ldflags "-s -w" -o secure-vibe.exe ./cmd/secure-vibe
   ```

## Build the MSI

```powershell
cd packaging\windows
wix build `
    -d BinaryPath=..\..\secure-vibe.exe `
    -d Version=2026.05.12.0 `
    -o build\secure-vibe.msi `
    secure-vibe.wxs
```

The resulting MSI is at `build\secure-vibe.msi`.

## What the installer does

- Installs `secure-vibe.exe` to `C:\Program Files\SecureVibe\`.
- Adds the install directory to the system `PATH`.
- Does **not** register a scheduled task; run
  `secure-vibe scheduler install` post-install for background updates.

## Signing (recommended)

Sign the MSI with `signtool` from the Windows SDK:

```powershell
signtool sign /f cert.pfx /p <password> /tr http://timestamp.digicert.com /td sha256 build\secure-vibe.msi
```
