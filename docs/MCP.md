# rdl for AI agents (MCP)

`rdl mcp` is an [MCP](https://modelcontextprotocol.io) server. An AI agent
(Claude Code, Claude Desktop, or any MCP client) can then download files onto
this PC in a few tool calls, with resume, verification and the same safety
rules as everywhere else.

## Set up

```sh
rdl setup                 # once: creates the config and the save folder
rdl mcp --print-config    # prints the snippet for your agent
```

- **Claude Code:** `claude mcp add rdl -- /path/to/rdl mcp`
- **Claude Desktop and other clients**, add this to the MCP config:

```json
{ "mcpServers": { "rdl": { "command": "/path/to/rdl", "args": ["mcp"] } } }
```

## Tools

| Tool | What it does |
|---|---|
| `probe` | What a link is, without downloading: type, size, resumable, SHA-256, file name, what's inside |
| `add` | Queue one download; `all: true` queues every file in a web folder |
| `add_batch` | Queue up to 100 downloads in one call (each may set its own folder and SHA-256) |
| `hf_add` | Hugging Face: looks up sizes and SHA-256 hashes, then queues |
| `wait` | Blocks until the jobs finish (or timeout), then returns one summary. **No polling needed.** |
| `list`, `status` | Compact job rows |
| `pause`, `resume`, `cancel`, `retry`, `relink` | Job control; `relink` continues from a new link |
| `verify` | Recomputes a finished file's SHA-256 (returns only the hash) |
| `folders`, `ls`, `disk` | Where files can go, and free space |

A typical session is three calls:
`add_batch` (15 model files) → `wait` → `list`. The test suite checks exactly
this: 15 files over flaky links, every file SHA-256 verified, ≤ 5 tool calls.

## What an agent can't do

- Read, open or upload file contents. Results only contain names, sizes,
  progress and hashes.
- Download from the private network (router, NAS, cloud metadata), or from
  streaming services.
- Write outside your save folders and favorites, or create folders except
  through the path rules.
- **Power actions** (sleep, shutdown), unless you set
  `power.agent_can_power: true`.
- Change config: roots, allow-private, site rules.
- See or control jobs it didn't add. Each agent is `mcp:<client name>` with the
  `agent` role.

Every call goes through the same command layer as the CLI and the chat apps:
roles, rate limit, and audit log (`rdl audit` shows what the agent did).

## How it runs today

Until the background service exists (#7), `rdl mcp` runs the download engine
itself:
- downloads run while the agent keeps it open;
- unfinished ones resume later with `rdl run`;
- `rdl run` and `rdl mcp` can't run at the same time (single-instance lock).

When the service arrives, `rdl mcp` will connect to it instead, and downloads
will continue after the agent closes.
