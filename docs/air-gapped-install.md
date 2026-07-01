# Air-gapped install

**SecureVibe** is designed to operate without any network access once the
release tarball is on disk. This guide is the procedure for installing and
keeping the library up to date on a machine that cannot reach the internet.

> Asset names (`secure-vibe`, `secure-vibe-data.tar.gz`) and release URLs
> reflect the stable Go module / binary identifiers and are not renamed when
> the project's brand changed to **SecureVibe**.

## 1. Download on the internet-connected build host

```bash
# Binary for the target OS / arch
curl -L -o secure-vibe \
  https://github.com/shieldnet-360/secure-vibe/releases/latest/download/secure-vibe-linux-amd64
curl -L -o checksums.txt \
  https://github.com/shieldnet-360/secure-vibe/releases/latest/download/checksums-linux-amd64.txt

# Library payload (manifest + skills + vulnerabilities + dictionaries + dist)
curl -L -o secure-vibe-data.tar.gz \
  https://github.com/shieldnet-360/secure-vibe/releases/latest/download/secure-vibe-data.tar.gz
```

## 2. Verify the binary

```bash
sha256sum -c checksums.txt --ignore-missing
```

The same `checksums-<goos>-<goarch>.txt` file is what `secure-vibe
self-update` uses to verify a downloaded binary.

## 3. Copy to the air-gapped machine

Use whatever transport policy your environment supports — USB stick, signed
SFTP drop, internal artifact server. Move both files.

## 4. Install

```bash
chmod +x secure-vibe && sudo mv secure-vibe /usr/local/bin/

# Apply the offline tarball as the update source
secure-vibe update --source /path/to/secure-vibe-data.tar.gz
```

The `updater` package walks the same code path it would for an HTTP
release: signature verification, per-file SHA-256 verification, atomic
writes. Only the transport differs.

## 5. Recurring updates

Repeat steps 1 – 4 whenever you want a refresh; nothing more is required.
The scheduler subsystem is OFF on air-gapped hosts (there is no network
to fetch from), so updates are operator-driven.

## Signature verification

`secure-vibe update --source ...` enforces the Ed25519 signature on
`manifest.json` before any file is written. See
[`SIGNING.md`](https://github.com/shieldnet-360/secure-vibe/blob/main/SIGNING.md) for the public key rotation policy and the
out-of-band signing procedure.
