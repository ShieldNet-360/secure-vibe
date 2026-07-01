# Manifest signing procedure

This document describes the out-of-band signing step required to authenticate
**SecureVibe** releases. The Ed25519 private key **never** enters CI; signing
happens offline on a hardware-backed device.

## Rationale

A compromise of the CI environment should not be sufficient to ship a
malicious update. By signing the manifest offline, we guarantee that a
supply-chain attacker who gains write access to the repository or CI runner
must *also* possess the physical signing device.

## Prerequisites

| Component | Notes |
|-----------|-------|
| **YubiKey 5** or similar hardware key | must hold an Ed25519 private key |
| `ykman` (YubiKey Manager CLI) | `brew install ykman` / `sudo apt install yubikey-manager` |
| `openssl` >= 3.0 | or Go's stdlib via a local helper script |
| Repository release tag | e.g. `v2026.05.12` |

## Workflow

The release pipeline is a four-stage **draft → sign → verify → publish**
flow. Releases never become public (i.e. consumable by `secure-vibe
update`) until CI has independently re-verified that the offline-signed
manifest is intact end-to-end.

1. **CI builds a DRAFT release.** Pushing a `v*` tag (or invoking
   `release.yml` via `workflow_dispatch`) cross-compiles every binary,
   computes the manifest checksums, bundles the data tarball, and
   uploads everything as a **draft** GitHub Release. The bundled
   `manifest.json` still has `"signature": "TBD"` at this point — the
   draft is not consumable by `secure-vibe update`, which follows the
   "latest" pointer.

2. **Release manager downloads the unsigned manifest.**

   ```bash
   gh release download v2026.05.12 -p manifest.json -D /tmp/release-staging/
   ```

3. **Sign offline.**

   ```bash
   # Option A — Go helper in this repo (recommended)
   go run ./cmd/secure-vibe dev manifest sign \
     --path /tmp/release-staging \
     --key /dev/stdin <(ykman piv keys export 9c -)

   # Option B — raw ed25519 seed file from a secure vault
   go run ./cmd/secure-vibe dev manifest sign \
     --path /tmp/release-staging \
     --key /path/to/ed25519.seed
   ```

   The command reads the private key, computes the canonical JSON (stripping
   the `signature` field), signs it with Ed25519, and writes the result back
   to `manifest.json` as `"ed25519:<base64>"`. Sanity-check locally:

   ```bash
   go run ./cmd/secure-vibe dev manifest verify \
     --path /tmp/release-staging \
     --public-key keys/secure-code-release-2026.pub
   ```

4. **Sign the per-platform binary checksum files (binary authenticity).**
   The `manifest.json` signature authenticates the *library data tree*, but
   the `secure-vibe update --self` path trusts the binary's SHA-256 from the
   `checksums-<goos>-<goarch>.txt` files. Sign each of those with the same
   offline key so the hash a self-update consumes is itself anchored to the
   release key rather than to whatever source served the binary:

   ```bash
   gh release download v2026.05.12 -p 'checksums-*.txt' -D /tmp/release-staging/
   for f in /tmp/release-staging/checksums-*.txt; do
     go run ./cmd/secure-vibe dev manifest sign-file --key /path/to/ed25519.seed "$f"
     # writes "$f.sig" = "ed25519:<base64>" over the checksum file bytes
   done
   # sanity-check one:
   go run ./cmd/secure-vibe dev manifest verify-file \
     --public-key keys/secure-code-release-2026.pub \
     /tmp/release-staging/checksums-linux-amd64.txt
   ```

   Then upload the `.sig` files alongside the checksum files:

   ```bash
   gh release upload v2026.05.12 /tmp/release-staging/checksums-*.txt.sig --clobber
   ```

   `secure-vibe update --self` fetches `checksums-<goos>-<goarch>.txt.sig`,
   verifies it against the embedded public key, and *then* trusts the
   SHA-256. Releases without these `.sig` files still self-update (with a
   warning) unless the user passes `--require-signature`; once a release
   ships signed checksum files, `--require-signature` becomes the
   recommended invocation and a future CLI version can make it the default.

5. **Re-upload the signed manifest to the same draft.**

   ```bash
   gh release upload v2026.05.12 /tmp/release-staging/manifest.json --clobber
   ```

6. **Run the publish-verification workflow.** From the GitHub Actions UI,
   trigger **Sign & publish** (`.github/workflows/sign-and-publish.yml`)
   with the release tag (e.g. `v2026.05.12`). The workflow:

   - Asserts the release for the supplied tag exists and is still a draft.
   - Downloads every asset attached to the draft.
   - Rejects the publish if `manifest.json.signature == "TBD"` (i.e. the
     offline-signing step was skipped or the wrong file was uploaded).
   - Extracts `secure-vibe-data.tar.gz` and re-runs
     `secure-vibe dev manifest verify --path .` against the extracted
     payload + the re-uploaded signed manifest. This re-checks both
     the Ed25519 signature (against the public key embedded in a
     freshly-built `secure-vibe` binary) **and** every per-file
     SHA-256 inside the tarball.
   - Cross-checks the tarball SHA-256 against the line in
     `SHA256SUMS.txt`. Note: `SHA256SUMS.txt` is generated by
     `release.yml` BEFORE the manifest is signed, so any
     standalone-`manifest.json` line inside it goes stale by
     design once the signed manifest is re-uploaded. The canonical
     integrity proof for `manifest.json` is the Ed25519 signature
     re-verified in the previous step; consumers should always use
     `secure-vibe dev manifest verify --path .` rather than
     `sha256sum -c SHA256SUMS.txt` to authenticate the manifest.
   - Only if every step passes does it call
     `gh release edit <tag> --draft=false`, flipping the release public.

   At this point the release is consumable by `secure-vibe update`
   and the signature can be re-verified by anyone via
   `secure-vibe dev manifest verify --path .`.

## Key Rotation

1. Generate a new Ed25519 keypair:
   ```bash
   go run ./cmd/secure-vibe dev manifest keygen   # future — currently manual
   # or: openssl genpkey -algorithm Ed25519 -out new.pem
   ```

2. Embed the new public key in the CLI binary by updating the build-time
   `-ldflags`:
   ```
   -X github.com/.../manifest.EmbeddedPublicKey=$(base64 -w0 < new.pub)
   -X github.com/.../manifest.EmbeddedPublicKeyID=secure-code-release-YYYY
   ```

3. Tag a new release with the updated binary. Older CLI versions will reject
   manifests signed with the new key — this is by design so that operators
   upgrade before trusting the new chain.

4. Revoke the old key by removing its `.pub` from the `keys/` directory in a
   subsequent commit.

## Emergency Revocation

If the signing key is compromised:

1. Generate a new key immediately.
2. Publish a new release signed with the new key.
3. Announce the compromised key's fingerprint and the safe replacement via
   GitHub Security Advisory.
4. Operators must upgrade their `secure-vibe` binary to one that trusts the
   new key.

## Public Key Listing

| Key ID | Fingerprint (SHA-256) | Status |
|--------|-----------------------|--------|
| `secure-code-release-2026` | *(populated at release time)* | active |
