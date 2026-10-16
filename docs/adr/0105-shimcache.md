<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0105 — AppCompatCache (ShimCache)

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`shimcache` decodes `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\
AppCompatCache` for Windows 8/8.1 (`00ts`/`10ts`, header 0x80) and 10/11 (`10ts`, header 0x30/0x34).
Order is kept (most recent first). An unknown header is `Unsupported`; a truncated entry stops the walk
and records `partial`. Presence in ShimCache does **not** prove execution on Windows 10+; the
last-modified time is the file's, not a run time. The cache is only written at shutdown.
