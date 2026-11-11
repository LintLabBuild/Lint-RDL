# Install

## Build

```sh
git clone <repo> && cd <repo>
go build -trimpath -o rdl ./cmd/rdl                     # Linux / macOS
GOOS=windows GOARCH=amd64 go build -trimpath -o rdl.exe ./cmd/rdl
```

Signed release binaries come in phase 6.

## Set up

```sh
rdl setup                 # uses ~/Downloads, or: rdl setup D:\Downloads
rdl roots add "D:\files\A_Project_folder"
rdl deny add "D:\files\A_Project_folder\secrets"
```

## Autostart

The background daemon and its Task Scheduler entry arrive in phase 2. Until then,
you can resume the queue at logon by creating a Task Scheduler task that runs
`rdl run` "At log on". On Linux, use a user systemd unit running
`systemd-inhibit --what=sleep rdl run`, which also keeps the PC awake.

## Uninstall

Delete `rdl.exe`, the config folder (`rdl config path`), the state folder
(`%LOCALAPPDATA%\rdl` or `~/.local/state/rdl`), and any `.rdl` folders left inside
your save folders (these hold unfinished downloads).
