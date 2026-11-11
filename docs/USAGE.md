# Usage

Phase 1 ships the CLI. The same commands will exist in the web UI, Telegram and
MCP (see [SPEC.md §4](SPEC.md#4-the-shared-command-set)).

## Downloading

| Command | What it does |
|---|---|
| `rdl probe <url> [--json]` | Shows the final URL, redirects, size, resumability (from a real 1-byte range test), ETag/Last-Modified, a known SHA-256, the file name and a verdict |
| `rdl get <url>... [--to dir] [--name file] [--sha256 hash] [--dup copy] [--json]` | Downloads now in this window. Ctrl+C, a crash or a reboot are fine: run the same command again and it resumes. |
| `rdl add <url>... [same flags]` | Queues jobs without starting them |
| `rdl add-batch manifest.json` | Queues many. The manifest is `[{"url": "...", "to": "models/vae", "name": "...", "sha256": "...", "size": 123}]` |
| `rdl hf <owner/repo> <path>... [--rev <commit>] [--to dir] [--get]` | Looks up the size and SHA-256 from the Hugging Face API, then queues (or, with `--get`, downloads now). Gated models: set `RDL_HF_TOKEN`. |
| `rdl run [--exit-when-done]` | Processes the queue; picks up jobs added meanwhile with `rdl add` |
| `rdl list [--json]` / `rdl status <id>` | Show jobs |
| `rdl wait [<id>...] [--timeout 30m]` | Runs the queue and blocks until the jobs settle, then prints one summary line |
| `rdl pause|resume|cancel|retry <id>` | Job control (while no other rdl is running; live control arrives with the daemon) |
| `rdl verify <id>` | Recomputes the SHA-256 of the finished file |
| `rdl remove <id>` | Forgets a finished, failed or cancelled job (the file stays) |

`--to` takes an absolute folder inside a save folder, or a path relative to the
default save folder. The folder must already exist; create it with `rdl mkdir`.

Exit codes: `0` everything done, `1` a job failed or there was an error, `2` usage
error, `130` interrupted.

## Folders

| Command | |
|---|---|
| `rdl folders` | Lists the save folders |
| `rdl ls [path]` | Lists folders (and files) inside a save folder |
| `rdl mkdir <name> [--in path]` | Creates a folder inside a save folder |
| `rdl disk` | Shows free space per save folder |

## At the PC only

| Command | |
|---|---|
| `rdl setup [folder]` | Creates the config with `~/Downloads` (or `folder`) as the first save folder |
| `rdl config [show|path|set <key> <value>]` | e.g. `rdl config set max_parallel_jobs 2`, `rdl config set power.countdown_seconds 30` |
| `rdl roots [list|add|remove] <folder>` | Save folders |
| `rdl deny [list|add|remove] <folder>` | Forbidden folders inside save folders |
| `rdl allow-private [list|add|remove] <ip or cidr>` | Allows a private download source, e.g. a NAS |
| `rdl limit <5MB/s|off>` | Speed cap |
| `rdl audit [-n 50]` | Shows the audit log |

## Environment variables

| Variable | |
|---|---|
| `RDL_CONFIG` | Config file path |
| `RDL_CONFIG_DIR` / `RDL_STATE_DIR` | Override the config and state folders |
| `RDL_HF_TOKEN` | Hugging Face token, sent only to huggingface.co |

## Testing locally

`go run ./cmd/rdl-testserver -size 200MB -cut 10MB` serves a file that drops the
connection every 10 MB. Allow it with `rdl allow-private add 127.0.0.1` (and
remove that afterwards).
