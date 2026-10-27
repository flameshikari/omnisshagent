# Configuration

The default file is `%APPDATA%\OmniSSHAgent\config.toml`. Unknown fields are
rejected. Valid changes apply automatically; invalid edits retain the previous configuration.

```toml
version = 1

[backend]
type = "windows-openssh"
pipe = "openssh-ssh-agent"
connect_timeout = "5s"

[interfaces.pageant]
enabled = true

[interfaces.cygwin]
enabled = true
socket_path = ""

[tray]
show_sign_notifications = false
fluent_icon = false

[logging]
enabled = true
level = "info"
```

- `version` must be `1`.
- `backend.type` accepts `windows-openssh` or `embedded`.
- With `windows-openssh`, `backend.pipe` accepts a short name or a full
  `\\.\pipe\...` path, and `backend.connect_timeout` must be a positive Go
  duration.
- With `embedded`, `backend.pipe` and `backend.connect_timeout` are ignored.
  They may remain in the file so switching back preserves the external backend
  settings. OmniSSHAgent exposes the fixed `\\.\pipe\openssh-ssh-agent` pipe.
- `interfaces.*.enabled` independently enables each compatibility interface.
- The Pageant and Cygwin/MSYS2 Boolean settings can also be changed from the
  Settings dialog. Changes apply automatically.
- `tray.show_sign_notifications` is reserved for a future feature and has no
  effect in the current release.
- An empty Cygwin path resolves to
  `%USERPROFILE%\.ssh\omnisshagent-cygwin.sock`; an override must be absolute.
- `tray.fluent_icon` enables the system-themed Fluent tray icon.
- `logging.enabled` switches logging on or off.
- `logging.level` accepts `debug`, `info`, `warn`, or `error`.

## Embedded backend

The minimal embedded configuration is:

```toml
[backend]
type = "embedded"
```

The embedded keyring is process-local and ephemeral:

- keys are never persisted or automatically reloaded;
- `ssh-add`, KeePassXC add/remove, Pageant, and Cygwin/MSYS2 requests use the
  same in-memory backend;
- lifetime constraints are supported;
- confirm-before-use (`ssh-add -c`) opens a signature confirmation dialog; and
- lock and unlock use the SSH agent keyring behavior.

Only one process can own the standard OpenSSH Named Pipe. OmniSSHAgent does not
stop or disable the Windows OpenSSH Authentication Agent. If another agent owns
the pipe, the OpenSSH interface reports a startup failure and the application
state becomes **Degraded** while unrelated enabled interfaces continue.

Diagnostic commands:

```powershell
.\dist\OmniSSHAgent-debug.exe version
.\dist\OmniSSHAgent-debug.exe config-path
.\dist\OmniSSHAgent-debug.exe check-config
.\dist\OmniSSHAgent-debug.exe check-config --config C:\path\to\config.toml
```

## KeePassXC unlock integration

Enable KeePassXC in **Settings → Middleware** to request database unlock on SSH
agent requests. In KeePassXC, enable **Browser integration** and **Request to
unlock the database if it is locked**. The matching `keepassxc-proxy.exe` must
be beside KeePassXC; no browser extension is needed.

Enable Start program and Executable to launch KeePassXC; Database applies only
at startup. Leave the path options unchecked to use the running process and its
current database.

```toml
[middleware]
enabled = true
program = 'keepassxc'

[middleware.programs.keepassxc]
unlock_on_request = true
start_on_request = false
use_executable = false
executable = ''
use_database = false
database = ''
```
