# SecureVibe — Linux packaging

Builds Debian (`.deb`) and RPM (`.rpm`) packages of the `secure-vibe` CLI
(part of **SecureVibe**) using [nfpm](https://nfpm.goreleaser.com/).

## Prerequisites

- `nfpm` v2 or newer
- A pre-built `secure-vibe` Linux binary

## Build

```bash
make BINARY=../../dist-build/secure-vibe-linux-amd64 VERSION=2026.05.13
```

Outputs land in `build/`:

- `secure-vibe_<VERSION>_amd64.deb`
- `secure-vibe-<VERSION>.x86_64.rpm`

The packages install the binary to `/usr/local/bin/secure-vibe`. No system
dependencies are required because the binary is statically linked
(`CGO_ENABLED=0`).

## Configuration validation

```bash
make check
```

The Go test `cmd/secure-vibe/internal/compiler/packaging_test.go` asserts the
configuration is parseable and lists the binary at the expected path.
