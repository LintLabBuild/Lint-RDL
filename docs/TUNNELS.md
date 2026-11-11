# Reaching rdl from your phone (phase 2)

The web UI arrives in phase 2. It binds to `127.0.0.1` by default and refuses to
start without a password if it sees a non-local bind or tunnel headers. Planned
setups:

| Option | Setup | Warning |
|---|---|---|
| **Tailscale (recommended)** | `tailscale serve` to `127.0.0.1:8765` | Private to your devices. **Never use `tailscale funnel`**, which makes it public. |
| Cloudflare Tunnel | `cloudflared` with Cloudflare Access (email one-time code) in front | Without Access, anyone with the URL reaches the login page |
| ngrok | ngrok with OAuth or basic auth enabled | A random URL alone is not protection |

Telegram (phase 3) needs no tunnel: the bot connects out with long polling.
