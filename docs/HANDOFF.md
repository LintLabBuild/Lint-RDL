# Handoff: continuing rdl on your own PC

Written from the cloud session that built phase 1. **Read this first** if you
(or a local Claude Code session) are picking the project up on a real Windows
or Linux machine.

## Why the work moves to the PC

The cloud sandbox can't do the next steps:

- **No Windows.** All Windows-only code compiles, but none of it has run.
- **No real downloads.** The network allows only a few hosts, so no real
  Hugging Face, Google Drive or Nexus files.
- **One network adapter**, so #2 (several networks at once) can't be tested.
- **No screen**, so no UI work.
- **Go module downloads are blocked**, which is why everything so far uses only
  Go's standard library.

## Where things stand (24 Nov 2026)

| Thing | State |
|---|---|
| `main` | Phase 1 core + favorites + Git links + link inspection + site policy + README |
| **PR #5** `feature/resume-modes` | Resume modes (ratchet / missing-only / restart), `rdl relink`, issue templates. **Open: review, check CI, merge.** Closes #3. |
| Old branch `claude/rdl-download-manager-spec-mtqr3w` | Same as `main` at the time; delete it once the repo default branch is `main` |
| Issues | #1 extension · #2 multi-network · #4 torrents (bring your own client) · #6 smart destinations · #7 editions (core vs desktop) · **#8 ideas & roadmap (start here, pin it)** |

Design docs: `docs/SPEC.md` (the full spec plus decisions taken while
building), `docs/THREATS.md` (each threat, its defence, and the test that
proves it), `docs/USAGE.md`, `docs/CONFIG.md`.

### Code map

| Package | What it does |
|---|---|
| `cmd/rdl` | CLI, interactive picker, progress line |
| `internal/engine` | Probe, queue, download/resume/ratchet, Git jobs, verify |
| `internal/policy` | URL rules (SSRF, streaming sites), path rules (roots, favorites, forbidden folders), file-name cleaning, disk guard |
| `internal/inspect` | File type from magic bytes, ZIP listing over ranges, safetensors, web-folder listing |
| `internal/gitdl` | Repository link detection, locked-down `git clone` |
| `internal/favorites` | Explorer Quick access (PowerShell) and GTK/KDE bookmarks |
| `internal/state` | Journal (one JSON file per job), audit log, single-instance lock |
| `internal/command` | Shared command set + roles: the layer every adapter (web, Telegram, MCP) will use |
| `internal/config` | `config.yaml` (strict YAML subset) |
| `internal/winsec`, `internal/power` | Mark of the Web; keep-awake (Windows API, `systemd-inhibit`, `caffeinate`) |
| `testserver` | Fake HTTP server that misbehaves on purpose (cuts, ignores ranges, changes files...) |

## Conventions (keep these)

- **Commits are authored as you:** `git config user.name VaibhavBansa1`,
  `git config user.email vaibhavbansalgwl@gmail.com` in this repo.
- **Small fixes go straight to `main`.** Features go on `feature/<name>`, then a
  PR that mentions @VaibhavBansa1. No random branch names.
- **Every bug or edge case gets a test.** Security changes get a row in
  `THREATS.md`.
- **rdl never runs, opens or sends out what it downloads.** It is not built for
  stream ripping (see the README section "What it downloads").

## Step 1 on the PC: verify what was never run

```sh
git clone https://github.com/LintLabBuild/Lint-RDL && cd Lint-RDL
go version                      # needs 1.24+
go test -race ./...             # on Windows AND Linux
go build -o rdl ./cmd/rdl       # rdl.exe on Windows
```

Then check these by hand on **Windows**, and fix or open issues for anything
broken:

- [ ] `rdl setup`, then `rdl folders`: are your **Quick access pinned folders**
  listed? (PowerShell reader in `internal/favorites/favorites_windows.go`; it
  might miss them on a non-English Windows)
- [ ] Download a file, then check `Get-Content <file> -Stream Zone.Identifier`:
  the **Mark of the Web** should be there
- [ ] **Junction escape:** `mklink /J <save folder>\link C:\Windows`, then
  `rdl get <url> --to link` must be refused
- [ ] **Single instance:** run two `rdl run` at once; the second must refuse
- [ ] The PC **doesn't sleep** during a long download (`powercfg /requests`
  shows rdl)
- [ ] **Long paths** (>260 characters) and a **FAT32 USB stick** with a file
  >4 GB (must be refused up front)
- [ ] Real **kill test**: a 5–10 GB Hugging Face model, killed with Task Manager
  10+ times and one reboot, then `rdl get` again. The SHA-256 must match. This
  is the spec's phase 1 "done" check.
- [ ] `rdl probe https://github.com/<repo>`: the GitHub file list (the API was
  blocked in the cloud, so this is untested)
- [ ] `rdl hf ...` on a real repo, plus a gated model with `RDL_HF_TOKEN`

On **Linux:** the same, plus a GNOME Files / Dolphin bookmark showing up in
`rdl folders`, and `systemd-inhibit --list` while downloading.

### Known gaps to expect

- **Google Drive:** large files first show a "can't scan for viruses" HTML
  page, which rdl refuses. Needs a small Drive handler (follow the confirm
  link). Folder downloads arrive as ZIP files.
- **Nexus Mods:** downloads need a login, and free accounts go through a
  countdown page. The real fix is the browser extension (#1), which hands rdl
  the final file link.
- **Audit log and journal store full URLs.** A pre-signed URL's query string
  can be a secret. Redact known signature parameters
  (`X-Amz-Signature`, `token`, `sig`, ...) in the audit log; the journal needs
  the full URL to resume, so keep it in the user-only state folder.
- Unicode NFC normalisation of file names (needs `golang.org/x/text`).

## Step 2: build #6 smart destinations (trimmed v1)

**The pain:** downloading shouldn't cost thinking about where files go.

**The picker:** at most 5 choices plus "Other…", each with a short reason;
Enter accepts the best guess.

**Rules that keep it simple:**
- **Keys are opaque.** rdl never needs to understand names or spellings.
  - It remembers *the key from the link* → *the folder you chose*.
  - Keys: the site (`nexusmods.com`), the first segment of the link's path
    (`skyrimspecialedition`), and the file's category (image, pdf, archive,
    model...).
  - If you name your folder "Skyrm Mods" with a typo, it doesn't matter: rdl
    stores the folder you clicked, not its name.
  - Different game editions are different keys
    (`skyrim` vs `skyrimspecialedition`). The first time, rdl asks; your other
    mod folders still show up through the site key.
- **Children collapse into the parent:** three different `Projects\X` choices
  show as one `Projects ▸ (last: X)`. Opening it lists subfolders **newest
  first**, plus "New folder".
- **Choices fade:** a place not picked in ~60 days drops off.
- **No AI model.** Ranking is counting with recency (see #6 for why). File
  name word matching (`DBMS_unit4.pdf`) is v2.
- **Not in v1:** choice log/replay, tracking moved folders by file ID,
  per-device profiles, auto-save.

**Storage:** `places.json` in the state folder, written atomically.

**Acceptance tests (unit tests with fake URLs):**

| Download | First suggestion |
|---|---|
| `nexusmods.com/cyberpunk2077/...` after one Cyberpunk choice | `Games\Cyberpunk 2077\Mods` |
| `nexusmods.com/skyrimspecialedition/...` (never seen) | Other mod folders from nexusmods.com, plus `Games ▸` |
| A PDF from `drive.google.com` after PDFs went to `College\Sem 5\DBMS` | `College ▸ (last: DBMS)` |
| A PNG from `pinterest.com` after one choice | `YouTube\Thumbnails` |
| Three projects under `Projects\` | One entry `Projects ▸`, with the newest project first inside |

## Step 3: the background service + desktop (#7)

Decisions made in the cloud session. Re-check them; they're not sacred.

**Shape:** the Go **core is the backend** (`rdl serve`). Every UI is a client:
the desktop window, the website on a phone, Telegram, MCP and the CLI. Remote
devices reach it through Tailscale (recommended), Cloudflare Tunnel + Access,
or ngrok.

**UI technology: a web UI** (HTML/CSS) served by the core. It's the only
codebase that reaches the phone too. On the PC it goes in a light window with
**Wails** (Go) or **Tauri**, both using the OS's built-in WebView (WebView2 on
Windows 10/11, WebKitGTK on Linux).
- Rejected: a rewrite in Rust + GPUI (what Discord's Project Phoenix uses). It
  has no phone or web support, and would throw away the working core.

**Who owns the tray:** the **desktop client**, not the core. The core can run
with no tray at all (home server).

**Exit semantics:**
- Closing the window **hides it to the tray**.
- Tray → **Exit**: if downloads are active, ask *"Keep downloading in the
  background / Stop everything"*. Remember the choice
  (`desktop.exit_stops_service`).
- A headless install has no tray; stop it with `rdl serve --stop` or the OS
  service manager.
- If the core restarts (update, crash), clients reconnect by themselves, and
  downloads resume from the journal.

**Other programs talking to the core:**
- Local clients use **IPC that only your user account can open**: a Unix
  socket with `0600` permissions on Linux, a named pipe with a user-only ACL on
  Windows. No open TCP port by default.
- Each client also presents a **token** from a user-only file. Remote clients
  use **pairing** (a code or QR shown once). MCP runs as `rdl mcp` over stdio,
  started by the user's agent.
- The web UI listens on a TCP port **only when enabled**, with a password,
  Host/Origin checks and CSRF protection (spec section 9.2).
- Every request carries an identity and role and goes to the audit log.
- **Honest limit:** a program already running *as your user* can read the same
  files as you. The OS user account is the real boundary. That's true for
  every app.

**Logs and state:**
- They live in `%LOCALAPPDATA%\rdl` or `~/.local/state/rdl`. On Linux these are
  created `0700`/`0600` already; on Windows that folder is user-only by default.
- **No secrets in logs:** tokens and passwords go in Windows Credential Manager
  or Linux Secret Service. Signed-URL redaction is listed under "Known gaps".

**Updates:**
- GitHub Releases carry **SHA-256 checksums + a signature** (minisign or
  cosign; Authenticode on Windows later).
- `rdl update` **checks and asks; it never updates silently by default**. It
  downloads the new build with rdl's own engine and verifies the hash and
  signature.
  - On Windows a running `.exe` can't be overwritten, so: rename to
    `rdl.old.exe`, move the new one in, restart the service.
  - Downloads in progress simply resume after the restart (journal).
- Later: winget / Scoop on Windows; `.deb` / AUR on Linux.

**Libraries worth adding on the PC** (keep them few, pinned, and checked with
`govulncheck` in CI):
- `golang.org/x/sys`: cleaner Windows APIs (named pipes, services, ACLs)
- `golang.org/x/text`: NFC file names
- `github.com/wailsapp/wails/v2` *or* Tauri: the desktop window
- a systray library: the tray
- (maybe) `go.etcd.io/bbolt`, if the JSON journal ever gets slow

## UI rules (from Vaibhav)

- **No gradient buttons**, no "gradient black" look. A soft gradient is OK only
  *around* a box.
- **One accent colour** used across the app:
  - by default from the system (Windows accent colour; GNOME/KDE accent on
    Linux);
  - the user can change it.
- **Subtle depth:** thin borders, very light shadows, nothing "cheap".
- Light and dark follow the system.
- **Comfortable spacing**, not huge.
- **No clipping:** long names end with "…" plus a tooltip. Test at 100%, 125%,
  150% and 200% display scaling.
- **Features must explain themselves**, because people don't read docs:
  - an empty state that looks familiar;
  - one-line hints the first time a feature acts ("rdl remembered this for
    pinterest.com images");
  - `rdl why <id>` for any decision.

## Open decisions

1. Windows service vs Task Scheduler at logon (spec open question 2). Leaning
   Task Scheduler for the desktop edition; a real service for headless.
2. Wails vs Tauri for the desktop window: build a tiny prototype of each and
   compare RAM, binary size and how the tray feels.
3. Video sites: only as a separate, opt-in plug-in repo that uses the user's
   own yt-dlp, if ever (see #8).
4. The first public release (v0.1): which binaries, and where to announce it
   (r/LocalLLaMA, r/StableDiffusion, ComfyUI).
