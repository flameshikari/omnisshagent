# Development

OmniSSHAgent is a Windows-only Go 1.27.3 module. `internal/backend` defines the
SSH Agent contract and contains the external OpenSSH client and embedded
ephemeral keyring; `internal/interfaces` contains OpenSSH Named Pipe, Pageant,
and Cygwin adapters; `internal/app` owns state and lifecycle; and
`internal/tray` owns its Win32 message thread.

The tray implementation uses a hidden normal top-level owner window, legacy
notification callbacks, `SetForegroundWindow` before `TrackPopupMenu`, and
menu selection through `WM_COMMAND`. Settings and the modeless Manage Keys
window share that locked OS thread. Private keys and passphrases are never
persisted; the embedded backend keeps loaded keys in process memory.

The tray and executable use the original OmniSSHAgent icon salvaged from the
archived Wails build's `build/windows/icon.ico`. The exact ICO is embedded by
`internal/tray`, while the checked-in Windows COFF resource is regenerated with:

```powershell
go generate ./cmd/omnisshagent
```

Pageant startup conflicts are represented by the Degraded tooltip/menu state
and the log. The MVP does not also show a one-time balloon notification.

Build release and debug executables into `dist/`:

```powershell
./scripts/build-release.ps1
./scripts/build-debug.ps1
```

Use `-Architecture arm64` for ARM64. Release builds accept `-Version`, `-Commit`,
and `-BuildTime` for metadata.

`scripts/install.ps1` installs the matching release asset
(`OmniSSHAgent-windows-amd64.exe` or `OmniSSHAgent-windows-arm64.exe`) after
verifying its adjacent `.sha256` file.
`scripts/uninstall.ps1` removes the installed executable and shortcut while retaining
configuration and logs by default. Both scripts signal the application's
named shutdown event and wait for clean resource release before replacing or
removing a running executable. They use a path-restricted forced stop only for
an older binary that does not expose the event. Run their Windows PowerShell
integration test with:

```powershell
./scripts/test-installer.ps1
```

Pushing a `v*` tag runs `.github/workflows/release.yml`, injects the tag,
commit, and UTC build time, and publishes the amd64 and arm64 executables plus
checksums to GitHub Releases. The installer URL in the README becomes usable
after that tagged release succeeds.

Never log protocol payloads, private keys, passphrases, or signing data.
Windows E2E steps are in [testing.md](testing.md).

## Legacy baseline

The archived implementation under `legacy/` was checked on 2026-07-20. Its
package tests passed except for the root package, and both `go test ./...` and
`go build ./...` stopped at `main.go:28:12` because the archived
`build/appicon.png` embed input is absent. This is the recorded migration
baseline. The old ICO was recovered from repository history for visual
continuity, but the new MVP has no Wails runtime or build dependency.
