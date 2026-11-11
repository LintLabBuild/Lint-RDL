# rdl

**A download manager for people who outgrew theirs.**

Downloads that survive network drops, crashes and reboots, check themselves
when they finish, and can be started from the terminal, a browser, your phone
or an AI agent. Built for Windows and Linux.

---

## Why it exists

I'm a power user. Every download manager I tried was missing something I
needed: resume that actually works, a checksum check, remote control, or
handling for Git and Hugging Face links.

The breaking point was a train ride. I wanted my home PC to fetch about 30 GB of
AI models. Nothing I had could do that from my phone, so I asked an AI agent.
It worked, but the agent spent most of its effort babysitting: restarting
scripts after drops, checking file sizes, polling progress.

rdl is the tool I wanted instead: **one download manager that replaces the
rest**, and that I can trust with a 30 GB file on a bad connection.

## What you get

| | |
|---|---|
| **Resume that never corrupts** | Survives Wi-Fi drops, power cuts and reboots. Resumes only when the server proves the file is unchanged; otherwise it restarts and tells you why. |
| **Knows what a link is before downloading** | The real file type, the size, whether resume will work, and what's inside: ZIP contents, model tensors, web-folder files, repository files. It warns about a `.jpg` that is really a program. |
| **Verified files** | Checks the SHA-256 automatically (Hugging Face hashes are looked up for you). |
| **Saves where you want** | Your save folders plus the folders you pinned in **File Explorer** or your **Linux file manager**. |
| **Git links** | Paste a GitHub, GitLab or Codeberg repository link: it's cloned with your Git, if installed. |
| **Hugging Face helper** | `rdl hf <repo> <files>` fetches models with sizes and hashes. |
| **Safe by default** | Never runs what it downloads. Never fetches from your private network. Never writes outside your chosen folders. |
| **Same on Windows and Linux** | One small binary with no dependencies. Keeps the PC awake while downloading. |

## Quick start

```sh
rdl setup                          # creates the config, uses your Downloads folder
rdl probe <url>                    # what is this link?
rdl get <url>                      # show it, pick a folder, download
```

Interrupted? Run the same `rdl get` again and it carries on where it stopped.

```sh
rdl get https://github.com/comfyanonymous/ComfyUI               # clone a repository
rdl get https://example.com/files/ --all --to "@AI Models"      # every file in a web folder
rdl hf Comfy-Org/Wan_2.2_ComfyUI_Repackaged split_files/vae/wan2.2_vae.safetensors --to models/vae
rdl add <url> && rdl run           # queue now, download later
```

All commands: [docs/USAGE.md](docs/USAGE.md)

## What it downloads

**If a browser would save it as a file, rdl can download it.** rdl is not built
for piracy:

- **Streaming services** (YouTube, Netflix, Spotify, Hotstar...) and stream
  playlists (`.m3u8`, `.mpd`) are refused. They offer playback, not files.
- **Web pages** (login pages, social posts) are refused as "not a file". Use the
  direct file link.
- **MEGA** is not supported yet: its files are encrypted on the server and only
  your browser can decrypt them.

## Roadmap

| | Status |
|---|---|
| Core: engine, probe, CLI, safety policies, Git, favorites, inspection | ✅ done |
| Background service, web UI, phone access over Tailscale, sleep/shutdown when done | next |
| Browser extension: send downloads from Chrome, Edge or Firefox to rdl | [#1](https://github.com/LintLabBuild/Lint-RDL/issues/1) |
| Faster downloads: parallel connections, Wi-Fi + Ethernet + hotspot together, mirrors | [#2](https://github.com/LintLabBuild/Lint-RDL/issues/2) |
| Telegram bot, AI agent tools (MCP), more chat apps | planned |

## Build

Go 1.24+, standard library only.

```sh
go build -trimpath -o rdl ./cmd/rdl                              # Linux
GOOS=windows go build -trimpath -o rdl.exe ./cmd/rdl             # Windows
go test -race ./...
```

## Docs

[Install](docs/INSTALL.md) ·
[Usage](docs/USAGE.md) ·
[Config](docs/CONFIG.md) ·
[Security model](docs/THREATS.md) ·
[Reporting vulnerabilities](docs/SECURITY.md) ·
[Remote access](docs/TUNNELS.md) ·
[Writing adapters](docs/ADAPTERS.md) ·
[Full design spec](docs/SPEC.md)

## License

MIT
