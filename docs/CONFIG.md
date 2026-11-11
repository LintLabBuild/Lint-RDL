# Config

Location: `%APPDATA%\rdl\config.yaml` on Windows, `$XDG_CONFIG_HOME/rdl/config.yaml`
(usually `~/.config/rdl/config.yaml`) elsewhere. Override it with `RDL_CONFIG`.
`rdl config path` prints the path in use.

The file uses a strict YAML subset: `key: value`, lists (`- item` or `[a, b]`),
and one level of sections. Unknown keys are errors. Only edit it at the PC; no
remote interface can change it.

| Key | Default | Meaning |
|---|---|---|
| `roots` | `[]` | Save folders (absolute). Downloads can only be written inside these. |
| `deny` | `[]` | Folders forbidden even inside a root |
| `default_root` | first root | Where `--to` is relative to, and the default destination |
| `disk_min_free_gb` | `10` | Safety margin that must stay free on the drive |
| `max_parallel_jobs` | `3` | Concurrent downloads (1–32) |
| `segments_per_file` | `1` | Reserved for parallel ranges (not used yet) |
| `speed_limit` | `off` | Global cap, e.g. `5MB/s` |
| `browse_show_files` | `false` | Whether remote `ls` shows file names (the CLI always does) |
| `block_extensions` | `warn` | `off` / `warn` / `block` for executable types (`.exe`, `.msi`, `.ps1`, `.lnk`, ...) |
| `allow_private` | `[]` | Private IPs or CIDRs allowed as download sources |
| `domain_allowlist` | `[]` | If non-empty, only these domains (and their subdomains) |
| `blocked_sites` | `[]` | Extra sites to refuse. Streaming services are always refused (`policy.StreamingSites`). |
| `favorite_folders` | `true` | Offer folders pinned in Windows File Explorer Quick access, or in GTK (GNOME Files, Nautilus, Nemo, Thunar) or KDE (Dolphin) bookmarks, as save folders. Drive roots, the home folder and its parents, hidden folders and system folders are skipped. |
| `git_hosts` | `[github.com, gitlab.com, codeberg.org, bitbucket.org, git.sr.ht, gitea.com]` | Hosts whose repository links are cloned with Git |
| `git_full_history` | `false` | `false`: shallow clone (latest commit). `true`: full history. |
| `proxy` | `''` | rdl's own HTTP(S) proxy. System proxy settings are always ignored. |
| `resume_mode` | `auto` | What to do when a server can't resume: `auto` (= `ratchet`), `ratchet`, `missing-only`, `restart`. See [USAGE](USAGE.md#when-the-server-cant-resume). |
| `chunk_mb` | `8` | fsync and journal interval |
| `stall_seconds` | `120` | Reconnect after this long without data |
| `low_speed_bytes` / `low_speed_seconds` | `0` / `60` | Reconnect if slower than this for that long (0 = off) |
| `max_mkdir_depth` | `8` | Folder depth limit for `mkdir` |
| `retry_after_cap_seconds` | `3600` | Upper bound for a server's `Retry-After` |
| `web.enabled`, `web.bind` | `false`, `127.0.0.1:8765` | Phase 2 |
| `telegram.enabled` | `false` | Phase 3 (the token lives in the credential store) |
| `power.countdown_seconds`, `power.agent_can_power` | `60`, `false` | Phase 2 |

State (journal, audit log, lock) lives in `%LOCALAPPDATA%\rdl` or
`~/.local/state/rdl`; `RDL_STATE_DIR` overrides it. Partial files live in a
hidden `.rdl` folder inside each save folder.
