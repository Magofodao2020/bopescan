<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0110 — Downloaded and user files (advanced scan)

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

Full tier only. Lists (does not open) Downloads, Desktop and Documents one level deep plus one level of
subfolders: programs, archives, Lua scripts and automation scripts (`.ahk`, `.py`, `.ps1`). For programs
it hashes and checks the signature, and reads the `Zone.Identifier` stream (Mark of the Web): zone and,
only if the person opts in, the download host. `HostUrl`/`ReferrerUrl` are never kept.
