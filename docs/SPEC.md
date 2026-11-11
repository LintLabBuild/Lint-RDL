# rdl: a resumable download manager you control from chat, a browser, or an AI agent

**Status:** design spec, ready to build. Hand this whole file to whoever builds it.
**Owner:** Vaibhav Bansal (github.com/VaibhavBansa1)
**Repo:** to be created by the owner (suggested name `rdl` or `resumable-dl`, public, MIT license)
**Target:** Windows 10/11 first. Linux works too, since it's the same code. macOS is a later goal.
**Language:** Go (single `.exe`, no runtime to install)

> Implementation notes (phase 1) are collected at the end of this file, in
> "Decisions taken while building".

---

## 1. Why this exists

On a train, I wanted my home PC to download about 30 GB of video and image generation models and libraries. No app I had could do it from my phone, so I asked an AI agent to do it. It worked, but most of the agent's effort (and my token budget) went into babysitting: writing a download script, restarting it after network drops, checking file sizes, polling progress.

With rdl, the same job takes 3 to 5 commands from the agent (probe, add, wait, verify), about 5% of the effort. I can also do it from Telegram or a browser without any AI.

**In one line:** downloads that survive network drops and shutdowns, controlled from anywhere, which never run, open or send out what they download.

### Who uses it

| User | Typical job |
|---|---|
| Me, on my phone (Telegram or web UI over Tailscale) | "Download these 6 model files into `ai influencer\models`, then shut down the PC" |
| An AI agent (through MCP) | Probe a list of links, queue them, wait, confirm the checksums |
| Me, at the PC (CLI) | `rdl get <url>` as a better `curl` |
| Anyone with bad internet | Big downloads that survive drops and power cuts |

### Goals
1. Every download resumes after a network drop, crash, reboot or power cut, and never silently produces a corrupt file.
2. Before downloading, tell the user whether the link can resume at all (`probe`).
3. One set of commands that works the same in the CLI, the web UI, Telegram, and MCP.
4. Secure by default: safe to expose through a tunnel, safe to give to an AI agent.
5. Easy: one file, one `rdl setup`, sensible defaults.

### Non-goals (never build these)
- Running, opening, extracting or installing anything it downloads.
- Sending file content out of the PC (no file preview, no "send me this file", no file server).
- Torrents or peer-to-peer (maybe a separate plug-in, much later).
- Scraping websites or bypassing logins, paywalls or captchas.
- Unofficial WhatsApp libraries (they break WhatsApp's terms and can get the number banned).

---

## 2. Keywords

| Word | Full form / meaning |
|---|---|
| Range request | HTTP feature that lets a client ask for "bytes 5,000,000 onward". It makes resuming possible. |
| 206 Partial Content | The server's reply when it honours a range request. A `200` means it ignored the range and is sending the whole file. |
| ETag / Last-Modified | Server's "version stamp" for a file. If it changes, the partial file is stale and must restart. |
| If-Range | Header that says "send the range only if the file is still this version, otherwise send all of it". |
| SHA-256 | Secure Hash Algorithm, 256-bit. A fingerprint of the file, used to prove the download is complete and unchanged. |
| SSRF | Server-Side Request Forgery. Tricking a program into fetching something on your private network, like your router's admin page. |
| DNS rebinding | A domain that answers with a public IP when checked and a private IP when used. |
| MCP | Model Context Protocol. The standard way AI agents call tools. |
| MOTW | Mark of the Web. The `Zone.Identifier` tag Windows puts on downloaded files so it warns before opening them. |
| ADS | Alternate Data Stream. A hidden extra stream inside an NTFS file (`file.txt:hidden`). |
| CSRF | Cross-Site Request Forgery. A malicious website making your browser send commands to rdl. |
| Daemon | The background process that does the downloading. |
| Adapter | A plug-in that connects one interface (Telegram, web UI, MCP) to the daemon. |

---

## 3. Architecture

```
 Phone: Telegram / Discord / Slack       Browser (via Tailscale,          AI agent
        │ bot connects OUT                Cloudflare Tunnel or ngrok)     │ MCP over stdio
        ▼                                        ▼                        ▼  (local only)
 ┌──────────────────────────── rdl daemon (one process) ─────────────────────────────┐
 │  Adapters: cli · web · telegram · mcp · discord · slack · matrix · whatsapp-cloud │
 │                    │  every adapter produces the same Command struct              │
 │                    ▼                                                              │
 │  Command checker:  who is asking? allowed? (identity + role + rate limit)         │
 │                    ▼                                                              │
 │  Policy:  URL rules (network)  ·  path rules (filesystem)  ·  disk guard          │
 │                    ▼                                                              │
 │  Engine:  probe · queue · workers · resume · verify · move into place             │
 │                    ▼                                                              │
 │  State:   journal (SQLite or bbolt) · audit log · .part files                      │
 │                    ▼                                                              │
 │  Power:   keep awake while downloading · sleep / hibernate / shut down when done  │
 └───────────────────────────────────────────────────────────────────────────────────┘
```

**Rules of the architecture**
- Adapters never touch the disk or the network directly. They only build a `Command` and display a `Result`.
- Policy runs in one place, so a bug fix in it protects every adapter at once.
- Config can only be changed at the PC (CLI or config file), never from chat, the web UI or MCP. Remote users can't loosen the security rules.
- Data flows one way: internet → disk. No code path reads a downloaded file's content and returns it to any adapter. Only names, sizes, progress and hashes leave.

### Suggested repo layout
```
rdl/
  cmd/rdl/              main.go: CLI entry
  internal/engine/      probe, download, resume, verify, queue
  internal/policy/      urlpolicy.go, pathpolicy.go, diskguard.go
  internal/state/       journal, audit log
  internal/power/       windows.go, linux.go (build tags)
  internal/winsec/      MOTW writer, Credential Manager, reserved names
  internal/adapters/    cli/, web/, telegram/, mcp/, discord/, slack/, matrix/
  internal/command/     Command and Result types, the shared command set
  web/                  embedded static UI (go:embed), no CDN at runtime
  testserver/           fake HTTP server that misbehaves on purpose
  docs/                 README, INSTALL, SECURITY, THREATS, TUNNELS, ADAPTERS
```

---

## 4. The shared command set

Every interface supports the same commands. In Telegram they are slash commands plus buttons; in MCP they are tools; in the web UI they are buttons plus a chat box.

| Command | What it does |
|---|---|
| `probe <url>` | Report without downloading (see §5) |
| `add <url> [--to <folder>] [--name <file>] [--sha256 <hash>]` | Queue a download |
| `add-batch <manifest>` | Queue many (YAML or JSON list of url, folder, name, sha256) |
| `hf <repo> <path...>` | Hugging Face helper: looks up size and SHA-256 from the HF API, then queues (see §5.3) |
| `list` | All jobs with state and progress |
| `status <id>` | One job in detail |
| `wait [<id>...] [--timeout 30m]` | Blocks until jobs finish or the timeout; returns one summary. Built for AI agents so they don't poll. |
| `pause / resume / cancel <id>` | Job control |
| `retry <id>` | Retry a failed job |
| `verify <id>` | Recompute SHA-256 of a finished file |
| `folders` / `ls [path]` / `cd <path>` | Browse allowed save folders (folder names only by default) |
| `mkdir <name>` | Create a folder inside an allowed save folder |
| `when-done <sleep\|hibernate\|shutdown\|nothing>` | Power action after the queue empties |
| `power <sleep\|hibernate\|shutdown> --confirm` | Power action now, with countdown |
| `cancel-power` | Stop a pending countdown |
| `limit <speed>` | Global speed cap (e.g. `5MB/s`, `off`) |
| `disk` | Free space on each save folder's drive |
| `whoami` | Show the caller's identity and role |

**CLI-only (at the PC):** `setup`, `config`, `pair`, `unpair`, `roots add/remove`, `allow-private add/remove`, `daemon start/stop/install`, `audit`.

---

## 5. The download engine

### 5.1 `probe`: tells you before you download

Output example:
```
URL         https://huggingface.co/Comfy-Org/.../wan2.2_ti2v_5B_fp16.safetensors
Final URL   https://cas-bridge.xethub.hf.co/... (2 redirects, signed, expires in ~1h)
Size        9.31 GB
Resumable   YES  (server answered 206 to a test range)
Version     ETag "a1b2..."  Last-Modified 2025-07-28
Checksum    SHA-256 known (from X-Linked-ETag / HF API)
Filename    wan2.2_ti2v_5B_fp16.safetensors (from URL; Content-Disposition agrees)
Encoding    none (safe to resume)
Verdict     Safe to download. Resume will work. Signed URL: rdl will re-request the original link after expiry.
```

How it decides "Resumable":
1. Send `HEAD` (fallback: `GET` with `Range: bytes=0-0` if HEAD is blocked or lies).
2. Send `GET` with `Range: bytes=1-1`. **Only a real `206` with a matching `Content-Range` counts.** `Accept-Ranges: bytes` alone is not trusted; many servers claim it and ignore ranges.
3. Report one of: `YES`, `NO (server ignores ranges)`, `NO (size unknown / streamed)`, `RISKY (compressed transfer, no ETag, or file changes often)`.

### 5.2 How a download runs
1. Policy check on URL and destination (§6, §7).
2. Disk guard: needs `remaining size + safety margin (default 10 GB)` free. If unknown size, keep checking every 256 MB.
3. Write to `<save folder>\.rdl\<id>.part`, with a journal entry: URL, final URL, ETag, Last-Modified, expected size, expected SHA-256, bytes written.
4. Request with `Range: bytes=<written>-` and `If-Range: <ETag or Last-Modified>`.
5. Stream to disk; every 8 MB (configurable): `fsync`, then update journal. A crash loses at most the last chunk, which is simply downloaded again.
6. Hash while writing, so a finished file doesn't need a second full read. On resume, re-hash the existing part first (or keep the hash state in the journal).
7. On finish: check size, check SHA-256 if known, then atomically rename into the final place. Never overwrite: `name (1).ext` if taken.
8. Write the MOTW `Zone.Identifier` stream on Windows (ZoneId=3, ReferrerUrl, HostUrl).
9. Delete the journal entry; log to audit.

Optional: split large files into 4 to 8 parallel ranges when the server allows it (off by default; some hosts throttle or ban it).

### 5.3 Hugging Face helper (the origin use case)
`rdl hf Comfy-Org/Wan_2.2_ComfyUI_Repackaged split_files/vae/wan2.2_vae.safetensors --to "D:\...\ComfyUI\models\vae"`
- Reads size and `lfs.oid` (SHA-256) from `GET https://huggingface.co/api/models/{repo}/tree/{rev}/{folder}`.
- Downloads from `https://huggingface.co/{repo}/resolve/{rev}/{path}`.
- Optional HF token from Credential Manager for gated models.
- Supports `--rev` (branch or commit). Pinning a commit is recommended so files don't change mid-download.

### 5.4 Edge cases the engine must handle (each one gets a test in §11)

**Server behaviour**
| Case | Correct behaviour |
|---|---|
| Server ignores `Range` and returns `200` | Detect it; restart from 0 (don't append the whole file to the partial one!) |
| `206` but `Content-Range` start ≠ requested start | Treat as broken; restart or fail loudly |
| ETag or Last-Modified changed between runs | Discard the partial file, restart, tell the user "file changed on server" |
| No ETag, no Last-Modified | Resume only if size matches; mark `RISKY`; rely on SHA-256 at the end |
| `Content-Encoding: gzip` on the transfer | Ranges are on compressed bytes; request `Accept-Encoding: identity`; if still compressed, don't resume |
| No `Content-Length` (chunked / streamed) | Download works, resume not possible; say so in probe |
| `416 Range Not Satisfiable` | Either already complete (verify) or the file shrank (restart) |
| `429` or `503` with `Retry-After` | Wait exactly that long (cap it), then continue |
| `403` after some hours | Signed URL expired: request the **original** URL again to get a fresh signed one, then resume |
| Redirect chain (S3, CDN, HF xet bridge) | Follow up to 10; re-check policy on every hop; remember the original URL |
| Server sends HTML error page with `200` | Detect wrong `Content-Type` / size mismatch; fail, don't save it as the model file |
| Multipart byteranges reply | Not supported; treat as non-resumable |
| Stalled connection (0 bytes for 2 min) | Abort that request and resume; never hang forever |
| Very slow speed | Configurable low-speed limit, then reconnect |

**Network and machine**
| Case | Correct behaviour |
|---|---|
| Wi-Fi drop, mobile hotspot switch | Retry with backoff: 5s, 15s, 30s, 1m, then every 5m, forever unless cancelled |
| PC sleeps during download | Prevent it: `SetThreadExecutionState(ES_CONTINUOUS \| ES_SYSTEM_REQUIRED)` while jobs run; release after |
| Power cut / crash | On next start, read the journal, re-hash the part file, resume |
| Reboot | Daemon auto-starts (Task Scheduler at logon, or a Windows service); queue resumes |
| Two rdl processes | Single-instance lock (named mutex on Windows, lock file on Linux) |
| Clock jumps | Use monotonic time for timeouts |

**Disk**
| Case | Correct behaviour |
|---|---|
| Disk nearly full | Pause all jobs on that drive, notify, resume when space returns |
| Disk full mid-write | Catch the error, truncate to last good chunk, pause |
| FAT32 drive and file > 4 GB | Refuse up front with a clear message |
| Path > 260 characters | Use `\\?\` long paths internally; warn the user |
| File locked by antivirus or another app | Retry the rename a few times, then report |
| Save folder deleted or drive unplugged | Pause job, notify, don't recreate folders silently outside roots |
| Same URL added twice | Detect; ask: skip, or save as copy |

---

## 6. Network safety rules (URL policy)

The download source must be the public internet. This stops anyone using rdl to copy a private resource into a folder they can reach.

1. **Schemes:** only `http` and `https`. Reject `file:`, `ftp:`, `smb:`, `data:`, `javascript:`, UNC paths (`\\server\share`), anything else.
2. **Credentials in URLs** (`https://user:pass@host`): rejected (they leak into logs).
3. **Resolve, check, then connect to that exact IP.** Use a custom `net.Dialer` `Control` hook so the check happens on the actual socket address. This defeats DNS rebinding.
4. **Blocked ranges (default):**
   - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (Tailscale and CGNAT), `127.0.0.0/8`, `169.254.0.0/16` (link-local, cloud metadata), `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`
   - IPv6: `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`, `ff00::/8`, and IPv4-mapped or IPv4-compatible forms of all of the above (`::ffff:127.0.0.1`), NAT64 `64:ff9b::/96` with a private embedded IPv4
5. **Odd IP spellings** (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) are normalised by the resolver path before checking. Test every one.
6. **Every redirect hop** goes through rules 1 to 5 again.
7. **System proxy settings are ignored** unless the owner sets a proxy in rdl's own config (otherwise a proxy could route around the check).
8. **Allowing a private address** (e.g. a NAS on `192.168.1.50`) is possible only with `rdl allow-private add 192.168.1.50` typed at the PC. Never from chat, web or MCP.
9. **Optional allowlist mode:** only listed domains (e.g. `huggingface.co`, `github.com`) can be downloaded from.

---

## 7. Filesystem safety rules (path policy)

1. **Save roots:** downloads may only be written inside folders the owner lists at the PC (e.g. `D:\Downloads`, `D:\files\A_Project_folder`). rdl never reads files for content anywhere.
2. **Default save folder** is the first root, typically `Downloads`.
3. **Resolve, then check.** Clean the path, resolve symlinks, junctions and `.lnk` targets, then confirm the real path is inside a root. Check again right before writing and before the final rename (prevents swap-the-folder races).
4. **Always-forbidden, even inside a root:** rdl's own install, config, state and log folders; Windows Startup folders (user and all users); `C:\Windows`; `Program Files`; `ProgramData\Microsoft\Windows\Start Menu`; any folder the owner adds to `deny`.
5. **Never overwrite.** Existing name → `name (1).ext`. An owner-only config flag can allow overwrite inside one root.
6. **Filename cleaning** (filenames come from URLs and `Content-Disposition`, both attacker-controlled):
   - strip directories (`..\`, `../`, `C:\`, `\\?\`)
   - remove `:` (blocks ADS like `file.txt:hidden`), `<>"|?*`, control characters
   - reject Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with any extension)
   - strip trailing dots and spaces
   - remove bidirectional-override characters (U+202E etc.) so `photo‮gpj.exe` can't pretend to be a `.jpg`
   - normalise Unicode (NFC); cap length
   - empty result → `download-<id>`
7. **Folder browsing** (`ls`, `cd`, web folder picker): limited to roots; `cd ..` stops at the root; shows folders only by default (owner can turn on filenames); never shows file content.
8. **`mkdir`** only inside roots, cleaned like filenames, no nesting deeper than a set limit.
9. **Never execute:** no `exec`, no shell, no "open when done", no auto-extract. Write MOTW on every finished file. Optional: extension blocklist (`.exe`, `.msi`, `.bat`, `.ps1`, `.lnk`, `.scr`...) or warn-only.

---

## 8. Who can give commands (identity and access)

| Interface | How identity is proven |
|---|---|
| CLI at the PC | The logged-in Windows user. Full owner rights. |
| Telegram / Discord / Slack / Matrix | Platform user ID on an allowlist. Added with a pairing code: run `rdl pair telegram` at the PC → it shows a 6-digit code valid for 5 minutes → send `/pair 123456` to the bot. Group chats ignored unless allowed. |
| Web UI | Password (hashed with Argon2id) → session cookie (`HttpOnly`, `Secure` behind HTTPS, `SameSite=Strict`), idle timeout. Optional TOTP. |
| MCP | Runs locally over stdio, started by the agent on the same PC. Separate `agent` role (below). |

**Roles**
| Role | Can |
|---|---|
| owner | Everything remote is allowed to do, including power actions |
| user | Probe, add, list, wait, pause or cancel own jobs, browse folders |
| agent (MCP) | Same as user, plus `wait`; **no power actions unless the owner turns it on**; per-agent max total size per day |

**Limits:** rate limit per identity (commands per minute, failed logins), max concurrent jobs, max size per job and per day, all configurable.

**Secrets** (bot tokens, HF token, web password hash) are stored in Windows Credential Manager (Linux: Secret Service or a `0600` file). Never in the config file, never in logs.

**Audit log:** every command with time, identity, interface, URL, destination, result. Append-only file with rotation. Viewable with `rdl audit` at the PC.

---

## 9. Interfaces

### 9.1 CLI
Normal flags, plus `--json` output for scripts. Progress bar in the terminal. `rdl get <url>` runs in the foreground; `rdl add` hands the job to the daemon.

### 9.2 Web UI
- Binds to `127.0.0.1` only by default. Can bind to the Tailscale address (`100.x`) instead. Never `0.0.0.0` unless forced at the PC, with a warning.
- **Refuses to start without a password** if it detects any non-local bind or a tunnel header (`CF-Connecting-IP`, `X-Forwarded-For`, `Tailscale-User-Login`, ngrok headers).
- Checks `Host` header against an allowlist (blocks DNS-rebinding attacks on the UI itself), checks `Origin` on every state-changing request, CSRF token, strict CSP, no inline scripts, all assets embedded (`go:embed`), no CDNs.
- Pages: queue with live progress (Server-Sent Events), add-link box that shows the probe result first, folder picker (browse like a file explorer, "Save here"), power panel with countdown, a small chat box that accepts the same commands as Telegram.
- No file preview, no file download. Ever.

**Tunnel guide (docs/TUNNELS.md)**
| Option | Setup | Note |
|---|---|---|
| Tailscale (recommended) | `tailscale serve` to `127.0.0.1:<port>` | Private to your devices. **Do not use `tailscale funnel`** (makes it public). |
| Cloudflare Tunnel | `cloudflared` + Cloudflare Access (email one-time code) in front | Strangers never reach rdl |
| ngrok | ngrok with OAuth or basic auth enabled | A random URL alone is not protection |

### 9.3 Telegram (first chat adapter)
- Long polling (outbound only, no webhook, no open port).
- `/add <url>` → shows probe result → buttons: **Save to Downloads** · **Choose folder…** · **Cancel**
- Choose folder → buttons for each root → tap a folder to open it → **Save here** · **Back** · **New folder**. Text `ls` and `cd` also work.
- One progress message per job, edited every 10 to 30 seconds (respects Telegram rate limits), not a new message each time.
- `/whendone shutdown` → "Shut down after 3 jobs finish? [Confirm] [Cancel]" → countdown message with **Cancel** button.
- Notifications: job finished (with SHA-256 OK), failed, paused for disk space, PC about to sleep.

### 9.4 MCP server (for AI agents)
Run as `rdl mcp` (stdio). Tools: `probe`, `add`, `add_batch`, `hf_add`, `list`, `status`, `wait`, `pause`, `resume`, `cancel`, `verify`, `folders`, `ls`, `disk`.
- **Token-cheap by design:** compact JSON results; `wait` blocks server-side and returns one short summary, so the agent doesn't poll and burn tokens. Example: 6 files queued → one `add_batch` + one `wait` + one `list` ≈ 3 calls.
- Tool descriptions state the limits clearly (no reading files, public URLs only), so the agent doesn't try workarounds.

### 9.5 Later adapters
| Adapter | Cost | Note |
|---|---|---|
| Discord | Free | Gateway (outbound websocket) |
| Slack | Free tier | Socket Mode (outbound, no public URL) |
| Matrix | Free, open source | Good for privacy |
| WhatsApp | Meta WhatsApp Cloud API; needs a Meta business account and a webhook (use the tunnel); charges after a free allowance | Official API only |
| SMS via Twilio | Paid | Example of a paid channel |
| ESP8266 `/wake` (separate firmware) | Free | The ESP8266 that already powers the PC on via Blynk also listens to the same Telegram bot for `/wake`. Then: wake → "rdl online" → add links → "done, shutting down", all in one chat. |

Adapter interface (Go):
```go
type Adapter interface {
    Name() string
    Start(ctx context.Context, d Dispatcher) error // turns platform messages into Commands
    Notify(ctx context.Context, to Identity, ev Event) error
}
```

---

## 10. Power control (Windows)
- **Keep awake** while any job runs (`SetThreadExecutionState`); release when idle.
- **Sleep / hibernate:** `SetSuspendState` (check hibernate is enabled with `powercfg /a`; report if not).
- **Shut down:** `InitiateSystemShutdownEx` or `shutdown /s /t <n>` with a reason.
- Every power action: confirmation → countdown (default 60 s) → notifies all paired chats → cancel button works until zero.
- `when-done` waits for the queue **and** final verification, then runs the action.
- If the PC is woken by ESP8266/Wake-on-LAN, rdl resumes its queue at logon.

---

## 11. Testing

`testserver/` is a fake HTTP server with switches to misbehave. Each edge case in §5.4, §6 and §7 gets an automated test.

- **Resume tests:** kill the download at random points (including mid-`fsync`), restart, compare the SHA-256.
- **Server lies:** ignores Range; wrong `Content-Range`; ETag changes; gzip; no length; 416; 429 with Retry-After; signed URL that expires after N bytes; HTML error page with 200; stalls.
- **SSRF tests:** every blocked range, every odd IP spelling, redirect to private IP, DNS rebinding (custom resolver that answers public then private), IPv6-mapped forms, `file://`, UNC, credentials in URL.
- **Path tests:** `..\`, absolute paths, ADS `:`, reserved names, trailing dots, bidi characters, symlink and junction escape, folder swapped between check and write, Startup folder inside a root, overwrite attempts.
- **Web tests:** no password + tunnel header → refuses; bad Host; missing Origin; missing CSRF; brute-force rate limit.
- **Adapter tests:** unpaired Telegram user ignored; pairing code expiry; agent role can't power off.
- **Fuzzing:** Go's built-in fuzzing on filename cleaning and URL parsing.
- CI: GitHub Actions on Windows and Linux; `go vet`, `staticcheck`, `govulncheck`, race detector.

---

## 12. Documentation (in `docs/`)
| File | Contents |
|---|---|
| README.md | What it is, the train story, 3-command quick start, screenshots |
| INSTALL.md | Download, `rdl setup`, autostart, uninstall |
| USAGE.md | Every command, in each interface |
| SECURITY.md | How to report a vulnerability; supported versions |
| THREATS.md | Every threat in §6–§8, how it is blocked, which test proves it. The starting point for finding and fixing holes. |
| TUNNELS.md | Tailscale, Cloudflare Tunnel + Access, ngrok, with the warnings |
| ADAPTERS.md | How to write a new adapter |
| CONFIG.md | Every config key with its default |

Example config (`%ProgramData%\rdl\config.yaml` or `%APPDATA%\rdl\config.yaml`):
```yaml
roots:
  - D:\Downloads
  - D:\files\A_Project_folder
deny:
  - D:\files\A_Project_folder\secrets
default_root: D:\Downloads
disk_min_free_gb: 10
max_parallel_jobs: 3
segments_per_file: 1          # >1 = parallel ranges
speed_limit: off
browse_show_files: false
block_extensions: warn        # off | warn | block
allow_private: []             # only editable at the PC
domain_allowlist: []          # empty = any public domain
web:
  enabled: true
  bind: 127.0.0.1:8765
telegram:
  enabled: true               # token lives in Credential Manager
power:
  countdown_seconds: 60
  agent_can_power: false
```

---

## 13. Build phases and "done" checks

| Phase | Build | Done when |
|---|---|---|
| 1. Core | Engine, `probe`, `get`, `add`, queue, journal, URL and path policy, disk guard, MOTW, CLI, test server, all §11 engine/SSRF/path tests | A 10 GB file survives 20 random kills and a reboot with a matching SHA-256; every SSRF and path test passes |
| 2. Daemon + web UI | Background daemon, autostart, keep-awake, power actions, web UI with login, TUNNELS.md | I can add a link from my phone over Tailscale and watch it finish, then the PC sleeps |
| 3. Telegram | Pairing, folder picker buttons, progress edits, power with countdown | Same as phase 2, from Telegram only |
| 4. MCP | `rdl mcp` with all tools and `wait` | An agent downloads the 15-file AI model set in ≤ 5 tool calls |
| 5. More adapters | Discord, Slack, Matrix, WhatsApp Cloud API | Each passes the adapter tests |
| 6. Extras | HF helper polish, batch manifests, ESP8266 `/wake` firmware, Linux service, release builds | Signed release on GitHub |

Releases: GitHub Actions builds `rdl.exe` (Windows amd64/arm64) and Linux binaries with SHA-256 checksums; reproducible builds (`-trimpath`).

---

## 14. Open questions (decide while building)
1. SQLite vs bbolt for the journal (bbolt = pure Go, no CGO; leaning bbolt).
2. Windows service vs Task Scheduler at logon (service survives logoff, but power actions and Credential Manager are easier per-user; leaning Task Scheduler first).
3. Parallel segments on by default for Hugging Face? (Faster, but check HF's limits.)
4. Should `agent` role get per-domain allowlists by default (e.g. only huggingface.co, github.com)?

---

## Decisions taken while building (phase 1)

| Topic | Decision | Why |
|---|---|---|
| Journal (open question 1) | One JSON file per job, written atomically (temp file → fsync → rename). Neither SQLite nor bbolt. | Zero dependencies, survives power cuts, human-readable for debugging. Job counts are small. Can move to bbolt later behind the same `state.Journal` API. |
| Dependencies | Standard library only | Single small binary, easy audit. Config uses a strict YAML subset parser (`internal/config/yaml.go`); unknown keys are errors. |
| Hash state | SHA-256 internal state is saved in the journal at every checkpoint, so a resume never re-reads the part file (falls back to re-hashing if missing). | §5.2 step 6. |
| Journal entry after finish (§5.2 step 9) | Finished jobs are **kept** (without hash state) so `list`, `status`, `verify` work; `rdl remove <id>` forgets them. | Users and agents need to see "done + SHA-256 OK". |
| Back-off | 5s, 15s, 30s, 1m, then 5m; the counter resets whenever an attempt made progress. | Without the reset a flaky link that drops every few MB would quickly wait 5 minutes between chunks. |
| Signed URLs | Every attempt requests the **original** URL and follows redirects again. | Always gets a fresh signature; no special casing. |
| 401/403/410 | Retried (fresh signed link) up to 5 times in a row, then failed. | A permanent 403 shouldn't retry forever. |
| HTML on 200 | Fails when `Content-Type` is `text/html` and the file name isn't `.html/.htm`. | §5.4. |
| Weak ETags | Not used in `If-Range` (not allowed by HTTP); Last-Modified is used instead. | RFC 9110. |
| Phase-1 "daemon" | `rdl run` processes the queue in a window and picks up jobs added with `rdl add` (rescan every 3 s). Commands that change running jobs need the lock. | Daemon with live control is phase 2. |
| HF token | `RDL_HF_TOKEN` environment variable, sent only to `huggingface.co` (Go drops it on cross-host redirects). | Credential Manager integration is phase 2. |
| Unicode NFC | **Not yet done** (needs `golang.org/x/text`). Bidi, zero-width and other format characters are removed. | Tracked in THREATS.md. |
| Linux keep-awake | No-op; run under `systemd-inhibit`. | Windows is the target. |

## Additions requested after phase 1

| Request | Design |
|---|---|
| Linux is a first-class target, not just "same code" | CI runs on Linux and Windows; keep-awake uses `systemd-inhibit` on Linux and `caffeinate` on macOS; Linux file-manager bookmarks are read; Linux system folders and hidden folders are protected |
| Folders pinned in File Explorer are offered as save locations | `internal/favorites` reads Quick access (Windows) and GTK/KDE bookmarks (Linux). Valid ones become save folders (`favorite_folders: true`). System folders, drive roots, home and its parents, and hidden folders are skipped. Pickers list roots first, then favorites. `--to @Label` selects one by name. |
| Git links download if Git is installed | `internal/gitdl` detects repository links on `git_hosts` and clones with the user's Git under strict `-c` options (see THREATS.md). Blob links become raw file downloads. Not built in: without Git, a clear message. |
| No piracy, no links that hide their content | Built-in streaming and DRM site list, HLS/DASH playlist refusal, MEGA refused |
| Tell the user what a link is first, torrent-style | `internal/inspect`: type from magic bytes, mismatch warnings, ZIP listing via range requests, safetensors summary, web folder listing (`--all` to download), GitHub repository file list. `rdl get` shows this before downloading and asks in a terminal. |
