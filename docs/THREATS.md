# Threat model

This is the starting point for finding and fixing holes. Each row names the
threat, how rdl blocks it, and the test that proves it. If you find a gap, add a
failing test first ([SECURITY.md](SECURITY.md)).

Assets to protect: the files on the PC, the private network around it (router,
NAS, cloud metadata), and the PC itself (nothing downloaded is ever run).

## Network (URL policy, `internal/policy/urlpolicy.go`)

| Threat | Defence | Test |
|---|---|---|
| `file:`, `ftp:`, `smb:`, `data:`, `javascript:`, UNC or scheme-relative URLs | Only `http`/`https` are accepted, and UNC (`\\`) and `//` are rejected before parsing | `TestCheckRawURL` |
| Credentials in a URL leak into logs | Any userinfo is rejected | `TestCheckRawURL` |
| Private, loopback, link-local, CGNAT/Tailscale or multicast targets (SSRF) | Default blocked list from spec §6.4, plus TEST-NETs, `fec0::/10`, `100::/64`, `2001:db8::/32` | `TestCheckIPBlocked` |
| IPv4 hidden inside IPv6 (`::ffff:`, `::a.b.c.d`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4, Teredo) | Embedded IPv4 is extracted and checked too | `TestCheckIPBlocked` |
| Odd spellings: `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, trailing dot | `ParseHostIP` reads them the way inet_aton does and checks the result | `TestOddIPSpellings`, `TestCheckRawURL` |
| `localhost`, `*.localhost` | Treated as 127.0.0.1 | `TestCheckRawURL` |
| DNS rebinding | `net.Dialer.Control` checks the actual socket address of every connection | `TestDialControlBlocksRebinding` |
| Redirect to a private address or another scheme | `CheckRedirect` and the transport re-check every hop, up to 10 hops | `TestRedirectToPrivateBlocked`, `TestRedirectLimit` |
| System proxy routes around the dial check | `Transport.Proxy = nil`. With rdl's own `proxy:` set, the target name is resolved and checked first. | `TestSystemProxyIgnored`, `TestProxyPrecheck` |
| A remote user loosens the rules | `allow-private`, `domain_allowlist` and `proxy` are changed only by the CLI at the PC; the command dispatcher has no config commands | `TestRolesAndOwnership` (config command unreachable) |
| Parser confusion | Fuzzing: every URL the policy accepts is http(s), has no userinfo, and is not a private literal | `FuzzCheckRawURL` |

**Known gaps**
- With `proxy:` configured, the check uses rdl's own DNS answer. The proxy
  resolves the name again, so a rebinding attacker could win that race. Only use a
  proxy you trust.
- A *public* host that proxies to private resources (an open redirector you
  control on the internet) can't be detected. This is out of scope.

## Filesystem (path policy, `internal/policy/pathpolicy.go`, `filename.go`)

| Threat | Defence | Test |
|---|---|---|
| `..`, absolute paths, drive-relative paths escaping the save folders | The path is cleaned and resolved, then must lie inside a resolved root | `TestResolveDir` |
| Symlink or junction escape | `RealPath` (EvalSymlinks; on Windows `GetFinalPathNameByHandleW`, which also resolves junctions) runs before the check | `TestSymlinkEscape` |
| Folder swapped for a link between the check and the write | `CheckFinalPath` re-resolves the folder before the part file opens and before the rename, and refuses if the real path changed | `TestSwapFolderRace` |
| Writing into Startup, Windows, Program Files, Start Menu, rdl's own folders, or the owner's `deny` list | Always-forbidden list (`DefaultForbidden`) plus `deny`, applied even inside a root. `rdl roots add` also refuses roots that overlap them. | `TestResolveDir` |
| Creating folders silently | `ResolveDir` never creates; `mkdir` is explicit, cleaned and depth-limited | `TestResolveDir`, `TestMkdirAndList`, `TestSaveFolderVanishes` |
| Overwriting an existing file | `ReserveUniqueName` reserves a name with `O_EXCL` (`name (1).ext`) and the rename goes onto that placeholder | `TestNeverOverwrite`, `TestReserveUniqueName` |
| Hostile names from the URL or `Content-Disposition`: directories, `:` (ADS), `<>"|?*`, control characters, reserved names, trailing dots and spaces, bidi overrides, zero-width characters, overlong names | `SanitizeFilename` | `TestSanitizeFilename`, `FuzzSanitizeFilename`, `TestContentDispositionNameIsSanitized` |
| A crafted file executed by rdl | rdl has no exec, shell, "open when done" or extraction anywhere. On Windows the MOTW `Zone.Identifier` (ZoneId=3) is written. `block_extensions: block` refuses executable types. | code review; `TestBlockedExtension` |
| A file's content leaks out | No code path returns file content; `verify` returns only the hash, and `ls` shows names only (and file names only if `browse_show_files`) | `TestMkdirAndList` |

**Known gaps**
- Unicode NFC normalisation isn't done yet (it needs `golang.org/x/text`). Visually
  confusable names in different normalisation forms are possible. Bidi and format
  characters *are* removed.
- `.lnk` targets are not followed. rdl never treats a `.lnk` as a folder, so this
  is safe, but the spec mentions it.
- The final rename re-check narrows the race window but doesn't close it. Closing
  it fully needs handle-relative APIs (openat / `NtCreateFile` with a root
  handle), which is planned.

## Integrity (engine)

| Threat | Defence | Test |
|---|---|---|
| Server ignores Range, so the whole file gets appended to the partial | A `200` to a ranged request truncates to 0 first | `TestServerIgnoresRangeRestartsFromZero` |
| Wrong `Content-Range` start | Partial is discarded, resume turned off for the job | `TestWrongContentRangeNoCuts` |
| File changed on the server mid-download | `If-Range` plus an ETag/Last-Modified/total-size comparison, then restart with a notice | `TestFileChangedOnServer` |
| Compressed transfer | `Accept-Encoding: identity`. If gzip is sent anyway, it is decoded and the job is marked non-resumable. | `TestGzipTransfer` |
| Multipart byteranges | Treated as non-resumable | `TestMultipartNotResumed` |
| HTML error or login page saved as the file | `text/html` for a non-HTML name fails the job | `TestHTMLErrorPageFails` |
| Truncated or extended data | Expected size is enforced; extra bytes cause a restart | `TestResumeAfterCuts` |
| Wrong file (tampered, or the wrong link) | Expected SHA-256 from the user, Hugging Face (`lfs.oid`) or a manifest. A mismatch discards the data and the file is never moved into place. | `TestChecksumMismatchFails` |
| Crash or power cut | fsync, then a journal write with hash state; on start, truncate to the checkpoint | `TestCrashRecovery` (20 kills plus garbage after the checkpoint) |
| Stalls, slow links | Stall watchdog (default 2 min), low-speed limit | `TestStallReconnects` |
| Expired signed URL | The original URL is requested again on every attempt | `TestSignedURLExpiry` |

## Access (command layer, `internal/command`)

| Threat | Defence | Test |
|---|---|---|
| One remote user controls another's jobs | Non-owners see and control only their own jobs | `TestRolesAndOwnership` |
| An AI agent powers off the PC | Power commands are denied to `agent` unless `power.agent_can_power` is set | `TestRolesAndOwnership` |
| Command flooding | Per-identity token bucket (`CommandsPerMinute`) | `TestRateLimit` |
| No accountability | Every state-changing command and every finished or failed download goes to the append-only audit log, with rotation | `rdl audit` |

Pairing, web login, CSRF and Host checks arrive with phases 2 and 3; their
tests will be added here.
