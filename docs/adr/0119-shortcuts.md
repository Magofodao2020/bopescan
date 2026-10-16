<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0119 — Shortcuts and where they point

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`shortcuts` parses `.lnk` files (`bope_parsers::lnk`, MS-SHLLINK header, LinkInfo local/network path,
relative path and working dir; arguments are detected but never returned) on the Desktop (account,
OneDrive, Public), Start menu (account and all users, three levels), pinned taskbar and `Recent`.
Kept: catalog matches anywhere; outside `Recent`, shortcuts to `.exe` targets in user-writable folders.
`target_exists` is a check of the target path today. The shortcut's saved target times go on the
timeline. Shell item ID lists are not parsed.
