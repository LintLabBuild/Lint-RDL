# Security policy

## Reporting a vulnerability

Please report privately through GitHub's "Report a vulnerability" (Security
advisories) on this repository; don't open a public issue. Include steps to
reproduce, and ideally a failing test.

You can expect an acknowledgement within 7 days. Fixes land with a test, and the
threat gets a row in [THREATS.md](THREATS.md).

## Supported versions

Until 1.0, only the latest commit on the default branch is supported.

## Scope

Particularly interesting: anything that makes rdl write outside its save
folders, fetch from a non-public address without `allow-private`, execute or
expose downloaded content, keep a corrupted file as finished, or let a non-owner
do owner things.
