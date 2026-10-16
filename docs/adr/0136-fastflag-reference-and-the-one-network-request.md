<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0136 — The FastFlag reference and the program's one network request

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0. Amends AGENTS.md hard rule 1 and ADR 0003.

## Context

Comparing observed flag values needs a reference. The owner chose
`MaximumADHD/Roblox-FFlag-Tracker/PCDesktopClient.json` (about 23 000 entries; the values Roblox's
servers deliver to the Windows client on the live channel) and asked for it to stay current
automatically, to work offline from the last valid copy, and to be updated by hand from the interface.

## Decision

**One request, in one place.** The only network call is `bope_host_windows::https_get::get`: WinHTTP,
HTTPS on port 443, TLS 1.2/1.3, no redirect followed, no cookie, a fixed `User-Agent`, to
`api.github.com` or `raw.githubusercontent.com` only. The `WinHttp*` functions are banned everywhere else
in `clippy.toml`; the HTTP-client crates stay banned in `deny.toml`. The request carries the address and,
at most, an `If-None-Match` tag the same server gave earlier — nothing about the PC, the scan or the
person.

**No scan touches the network.** A scan receives the copy on disk through `ScanContext::flag_reference`
(CLI: `fflags` store; desktop: same folder), or none, and says which.

**Sync** (`bope-reference`): ask the commits API for the newest commit touching the file (conditional, so
an unchanged answer costs no rate limit); new commit → download the file at that commit; API refused →
download from `main` conditionally and name the copy by content hash. Validate (status 200, not HTML, a JSON
object of at least 1 000 scalar entries) and replace atomically (new file, one metadata rename, old file
removed). Every attempt is recorded in `sync-state.json`; the copy held is never replaced by anything that
did not validate. Automatic attempts at most every six hours, manual at most every minute. A file can be
imported by hand with the same validation (`fflags import`).

**When.** CLI: only `bope-scanner-cli fflags sync`. Desktop: the "Atualizar agora" button, and an automatic
check at start-up the person can turn off on the Roblox page (stored in the window's local storage).

**Comparison.** `equal`, `differs` or `not_in_reference` (never a difference), with the reference value,
key and revision. The reference row states the client version the commit names, the installed client's
version (read from the player's version resource) and the correspondence: `exact` only when they match;
otherwise indicative.

## Consequences

"No network code" becomes "no network code except this one request, in this one function". Reviewers
check `https_get.rs` and the `clippy.toml` ban when either changes.
