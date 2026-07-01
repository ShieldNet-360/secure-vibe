# Install SecureVibe on Linux

The `secure-vibe` CLI is a statically linked Go binary with no runtime
dependencies, so any glibc or musl Linux distribution can run it.

> The CLI binary name (`secure-vibe`) and the hosted APT/YUM repository
> paths (under `shieldnet-360.github.io/secure-vibe/`) are stable technical
> identifiers and are not renamed when the project's brand changed to
> **SecureVibe**.

## APT (Debian / Ubuntu)

```bash
curl -fsSL https://shieldnet-360.github.io/secure-vibe/apt/pubkey.gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/secure-vibe.gpg
echo "deb [signed-by=/etc/apt/keyrings/secure-vibe.gpg] \
  https://shieldnet-360.github.io/secure-vibe/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/secure-vibe.list
sudo apt update && sudo apt install secure-vibe
```

## YUM / DNF (RHEL / Fedora)

```bash
sudo tee /etc/yum.repos.d/secure-vibe.repo <<'EOF'
[secure-vibe]
name=Skills Library
baseurl=https://shieldnet-360.github.io/secure-vibe/yum
enabled=1
gpgcheck=1
gpgkey=https://shieldnet-360.github.io/secure-vibe/yum/RPM-GPG-KEY-secure-vibe
EOF
sudo dnf install secure-vibe
```

## Standalone .deb / .rpm

Download from the [latest GitHub Release](https://github.com/shieldnet-360/secure-vibe/releases/latest):

```bash
sudo dpkg -i secure-vibe_*.deb     # Debian / Ubuntu
sudo rpm -i  secure-vibe-*.rpm      # RHEL / Fedora
```

Reproducible-build / packaging details live in
[`packaging/linux/README.md`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/linux/README.md).

## Go install

```bash
go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest
```

## Verify

```bash
secure-vibe version
```

## Schedule background updates

```bash
secure-vibe dev scheduler install      # systemd --user, 6h interval
secure-vibe dev scheduler status
```

`secure-vibe init` will also offer to install the scheduled update on
first run. Pass `--no-prompt` for CI usage.
