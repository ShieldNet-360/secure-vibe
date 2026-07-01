# SecureVibe — APT and YUM release repository

This directory holds the tooling that turns the per-release `.deb` and `.rpm`
artifacts (built by `packaging/linux/`) into APT and YUM repositories hosted on
GitHub Pages.

> Repository paths (`shieldnet-360.github.io/secure-vibe/{apt,yum}`),
> repository identifiers (`secure-vibe`), and the YUM `name=Skills
> Library` display label are stable hosting identifiers and are not renamed
> when the project's brand changed to **SecureVibe**.

Users install with:

```bash
# APT (Ubuntu / Debian)
curl -fsSL https://shieldnet-360.github.io/secure-vibe/apt/pubkey.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/secure-vibe.gpg
echo "deb [signed-by=/etc/apt/keyrings/secure-vibe.gpg] https://shieldnet-360.github.io/secure-vibe/apt stable main" | sudo tee /etc/apt/sources.list.d/secure-vibe.list
sudo apt update && sudo apt install secure-vibe

# YUM / DNF (RHEL / Fedora)
sudo tee /etc/yum.repos.d/secure-vibe.repo <<EOF
[secure-vibe]
name=Skills Library
baseurl=https://shieldnet-360.github.io/secure-vibe/yum
enabled=1
gpgcheck=1
gpgkey=https://shieldnet-360.github.io/secure-vibe/yum/RPM-GPG-KEY-secure-vibe
EOF
sudo dnf install secure-vibe
```

## How the repo is built

`reprepro` is used for the APT side and `createrepo_c` for the YUM side. The
`Makefile` in this directory expects the per-release `.deb` and `.rpm`
artifacts on disk and emits a `site/` tree ready to be pushed to GitHub
Pages.

```bash
make ARTIFACTS=../../release VERSION=2026.05.13 site
```

The signing key is the same GPG key referenced from [SIGNING.md](../../SIGNING.md);
the private half stays offline on the release manager's YubiKey. CI imports
the public half (`pubkey.gpg`) and signs the release files in the same job
that publishes the GitHub Pages branch.

## Layout produced by `make site`

```
site/
├── apt/
│   ├── pubkey.gpg
│   ├── dists/stable/{InRelease,Release,Release.gpg,main/binary-amd64/Packages*}
│   └── pool/main/s/secure-vibe/secure-vibe_<VERSION>_amd64.deb
└── yum/
    ├── RPM-GPG-KEY-secure-vibe
    ├── repodata/...
    └── packages/secure-vibe-<VERSION>.x86_64.rpm
```

## Reproducibility

The APT and YUM metadata is regenerated on every release; the `.deb` /
`.rpm` artifacts themselves are not rebuilt — they are copied verbatim from
the GitHub Release attachment. This keeps the package SHA-256 stable across
repo refreshes and lets `apt update` honour the same checksum a user would
get from `wget`'ing the release asset directly.
