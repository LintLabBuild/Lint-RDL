# rdl: resumable download manager

Downloads that survive network drops, crashes and shutdowns. You will be able to
control it from chat, a browser or an AI agent. It never runs, opens or sends out
what it downloads.

> **Status: Phase 1 (core) is built.** The engine, `probe`, the URL and path
> policies, the disk guard, the journal, Mark of the Web, the CLI, the test server
> and the test suite are done. The background daemon, web UI, Telegram, MCP and
> power actions are later phases (see [Roadmap](#roadmap)). The full design is in
> [`docs/SPEC.md`](docs/SPEC.md).

## Why

On a train, I wanted my home PC to download about 30 GB of AI models. An AI agent
did it, but most of its effort went into babysitting: restarting a script after
network drops, checking sizes and polling progress. With rdl the same job takes
3 to 5 commands (probe, add, wait, verify), and it works from Telegram or a
browser without any AI.

## Quick start

```sh
rdl setup                                   # creates config, uses ~/Downloads (or %USERPROFILE%\Downloads) as the save folder
rdl probe https://huggingface.co/.../model.safetensors
rdl get   https://huggingface.co/.../model.safetensors --to models/vae
```

Kill it, pull the network cable or reboot, then run the same `rdl get` again. It
picks up where it stopped and checks the SHA-256 at the end.

To queue jobs and run them separately:

```sh
rdl add <url> --to models --sha256 <hash>
rdl hf Comfy-Org/Wan_2.2_ComfyUI_Repackaged split_files/vae/wan2.2_vae.safetensors --to models/vae
rdl run --exit-when-done
```

## What it tells you first

`rdl probe <url>` (and `rdl get`, before it starts) shows what a link really is:

- **The real file type**, read from the first bytes, not from the name. A
  `.jpg` that is really a program gets a warning.
- **What is inside**, like a torrent client would show:
  - the files in a ZIP (read from the archive's directory with a few small
    range requests, without downloading it);
  - the tensor count, parameters and dtypes of a `.safetensors` model;
  - the files and subfolders of a web folder ("Index of /...", downloaded
    with `--all`);
  - the file list of a GitHub repository.
- Size, whether resume will work, the checksum, and the file name.

In a terminal, `rdl get` then asks where to save. It offers your save folders
**and the folders you pinned in Windows File Explorer (Quick access) or in your
Linux file manager (GNOME Files, Nautilus, Nemo, Thunar, Dolphin)**. System
folders, drive roots, your home folder itself and hidden folders are never
offered.

## Git repositories

If Git is installed, a repository link such as
`https://github.com/comfyanonymous/ComfyUI` is cloned with your Git, into a
folder named after the repository. A "view file" link (`.../blob/main/x`) is
downloaded as that single raw file, and release and archive links are ordinary
file downloads. Without Git, rdl says how to get it.

## No piracy, no stream ripping

Streaming and DRM sites (YouTube, Netflix, Prime Video, Hotstar, Spotify,
SoundCloud, Twitch, TikTok, Instagram, Vimeo...) are refused, and so are
HLS/DASH stream playlists (`.m3u8`, `.mpd`) and client-side encrypted shares
(MEGA). rdl downloads files that are offered for download, nothing else. The
built-in list can't be switched off; `blocked_sites` adds more.

## What it guarantees

- **Resume or restart, never corrupt.** Data is fsynced and journaled every 8 MB,
  together with the SHA-256 state. rdl only treats a resume as valid if the server
  answers `206` with a matching `Content-Range` and the ETag (or Last-Modified)
  hasn't changed. Anything else restarts from zero, with a notice saying why.
- **Public internet only.** Private, loopback, link-local, CGNAT and metadata
  addresses are blocked in every spelling (`2130706433`, `0x7f.1`,
  `::ffff:127.0.0.1`, NAT64...). The check runs on the actual socket address, so
  DNS rebinding doesn't get past it, and it runs again on every redirect hop.
- **Writes only inside your save folders.** Symlinks and junctions are resolved
  first, the folder is checked again right before the final rename, and file
  names are cleaned (no `..`, no `:`, no reserved names, no bidi tricks). An
  existing file is never overwritten.
- **Never executes anything it downloads.** On Windows, every finished file
  gets the Mark of the Web. The only programs rdl starts are your installed Git
  (for repository links), PowerShell (to read Explorer's pinned folders) and
  `systemd-inhibit` / `caffeinate` (to keep the PC awake), each with fixed
  arguments.

Works the same on **Windows and Linux** (macOS builds too).

How each threat is blocked, and which test proves it: [`docs/THREATS.md`](docs/THREATS.md).

## Build

Requires Go 1.24+. No third-party dependencies.

```sh
go build -trimpath -o rdl ./cmd/rdl            # Linux
GOOS=windows go build -trimpath -o rdl.exe ./cmd/rdl
go test -race ./...
```

## Docs

| | |
|---|---|
| [INSTALL](docs/INSTALL.md) | Build, setup, autostart, uninstall |
| [USAGE](docs/USAGE.md) | Every command |
| [CONFIG](docs/CONFIG.md) | Every config key |
| [THREATS](docs/THREATS.md) | Threat model, with the test for each threat |
| [SECURITY](docs/SECURITY.md) | Reporting vulnerabilities |
| [TUNNELS](docs/TUNNELS.md) | Remote access (phase 2) |
| [ADAPTERS](docs/ADAPTERS.md) | Writing an adapter |
| [SPEC](docs/SPEC.md) | Full design spec |

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 1. Core | Engine, probe, get/add/run, journal, URL/path policy, disk guard, MOTW, CLI, test server, tests | **done** |
| 2. Daemon + web UI | Background daemon, autostart, power actions, web UI with login | next |
| 3. Telegram | Pairing, folder picker, progress edits | |
| 4. MCP | `rdl mcp` with `wait` | |
| 5. More adapters | Discord, Slack, Matrix, WhatsApp Cloud API | |
| 6. Extras | Release builds, ESP8266 `/wake`, Linux service | |

## License

MIT
