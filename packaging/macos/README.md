# SecureVibe — macOS .pkg installer

Build a macOS installer package for the `secure-vibe` CLI (part of
**SecureVibe**) using `pkgbuild` + `productbuild` from Xcode Command
Line Tools.

## Quick Start

```bash
# Build the binary first (from the repo root):
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o secure-vibe ./cmd/secure-vibe

# Build the .pkg:
cd packaging/macos
make BINARY=../../secure-vibe VERSION=2026.05.12
```

The resulting `.pkg` is at `build/secure-vibe-2026.05.12.pkg`.

## What the installer does

- Copies `secure-vibe` to `/usr/local/bin/secure-vibe`.
- No launch daemons are installed; run `secure-vibe scheduler install` post-install
  if you want background updates.

## Code-signing (optional)

If you have a Developer ID Installer certificate:

```bash
productsign --sign "Developer ID Installer: Your Name" \
    build/secure-vibe-2026.05.12.pkg \
    build/secure-vibe-2026.05.12-signed.pkg
```

## Notarization (optional)

```bash
xcrun notarytool submit build/secure-vibe-2026.05.12-signed.pkg \
    --apple-id you@example.com \
    --team-id TEAMID \
    --password @keychain:AC_PASSWORD \
    --wait
```
