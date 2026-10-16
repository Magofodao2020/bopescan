<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0113 — Explorer recent lists (advanced scan)

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

Full tier only. `shell_mru` reads RunMRU (programs only, never arguments), TypedPaths, RecentDocs for a
fixed set of extensions (`.exe`, `.dll`, `.lua`, `.luau`, `.ahk`, `.zip`, `.rar`, `.7z`) and
LastVisitedPidlMRU program names. ShellBags and OpenSavePidlMRU are not implemented (shell item parsing,
see capacidades.md).
