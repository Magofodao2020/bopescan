<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0111 — Installed programs by category

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`installed_programs` reads the Uninstall keys (HKLM, WOW6432Node, HKCU): display name, publisher,
version, install date and location. Categories: memory tools (Cheat Engine…), macro/automation
(AutoHotkey, TinyTask, peripheral suites), VPN/proxy, cleaners, virtualization, debuggers. Most are
`info`; a category is context, not evidence.
