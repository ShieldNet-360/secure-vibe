# Install SecureVibe on Windows

The `secure-vibe` CLI runs on Windows 10 and newer (x64). The CLI binary is
signed with Authenticode when the release secret is configured — see
[`packaging/codesign/README.md`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/codesign/README.md).

## MSI installer

Download the signed `.msi` from the
[latest GitHub Release](https://github.com/shieldnet-360/secure-vibe/releases/latest)
and double-click to install. The installer places the binary in
`%ProgramFiles%\Skills-Check\` and adds it to the system `PATH`.

## winget

```powershell
winget install shieldnet-360.secure-vibe
```

The manifest lives at
[`packaging/winget/shieldnet-360.secure-vibe.yaml`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/winget/shieldnet-360.secure-vibe.yaml).

## Scoop

```powershell
scoop bucket add shieldnet-360 https://github.com/shieldnet-360/scoop-bucket
scoop install secure-vibe
```

The bucket manifest lives at
[`packaging/scoop/secure-vibe.json`](https://github.com/shieldnet-360/secure-vibe/blob/main/packaging/scoop/secure-vibe.json).

## Go install

```powershell
go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest
```

Make sure `%USERPROFILE%\go\bin` is on your `PATH`.

## Verify

```powershell
secure-vibe version
```

## Schedule background updates

```powershell
secure-vibe dev scheduler install    # Task Scheduler, 6h interval
secure-vibe dev scheduler status
```

`secure-vibe init` will also offer to install the scheduled update on
first run; pass `--no-prompt` to skip in CI.
