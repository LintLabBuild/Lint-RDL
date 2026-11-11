# Writing an adapter

An adapter connects one interface (Telegram, web, MCP...) to rdl. It must never
touch the disk or the network for downloads itself. It only:

1. works out **who** is asking (platform user ID on the pairing allowlist, web
   session, local MCP process) and builds a `command.Identity` with a role;
2. turns the message into a `command.Command`;
3. calls `Dispatcher.Dispatch(ctx, cmd)` and shows the `command.Result`;
4. shows engine events (`engine.Event`: progress, done, failed, notices).

```go
type Adapter interface {
    Name() string
    Start(ctx context.Context, d *command.Dispatcher) error
    Notify(ctx context.Context, to command.Identity, ev engine.Event) error
}
```

Rules:

- Roles, job ownership and rate limits are enforced in `command.Dispatcher`.
  Don't re-implement them, and don't bypass them by calling the engine directly.
- Config changes are not commands. An adapter can never change roots,
  `allow-private` or other config.
- Never send file content: `Result.Data` holds jobs, names, sizes and hashes only.
- Keep messages small (MCP: token-cheap JSON; Telegram: edit one progress
  message rather than sending new ones).

Every adapter needs tests showing that an unpaired or unknown identity is ignored
and that the `agent` role can't run power commands
(see `internal/command/command_test.go`).
