# Install SecureVibe on macOS

The `secure-vibe` CLI runs natively on Intel and Apple Silicon. Pick whichever
install path matches how you manage other CLI tools.

## Homebrew (recommended)

```bash
brew tap shieldnet-360/tap
brew install secure-vibe
```

The tap formula lives at [`packaging/homebrew/secure-vibe.rb`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/homebrew/secure-vibe.rb).

## Go install

```bash
go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

## .pkg installer

Download the signed `.pkg` from the
[latest GitHub Release](https://github.com/shieldnet-360/secure-vibe/releases/latest)
and double-click to install. The package places the binary at
`/usr/local/bin/secure-vibe`.

Reproducible-build details and the signing model live in
[`SIGNING.md`](https://github.com/shieldnet-360/secure-vibe/blob/main/SIGNING.md) and
[`packaging/codesign/README.md`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/codesign/README.md).

## Verify

```bash
secure-vibe version
```

You should see the CLI version, the embedded public key ID, and the Go
version it was built with.

## Schedule background updates

```bash
secure-vibe dev scheduler install            # launchd, 6h interval
secure-vibe dev scheduler status             # check what's installed
```

The `secure-vibe init` command will also offer to set up the scheduled
update interactively on first run. Pass `--no-prompt` to skip the prompt
in CI scripts.
