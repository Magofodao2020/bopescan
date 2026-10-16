<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0109 — Browser extensions (advanced scan)

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

Full tier only. Reads Chromium-family `Extensions\*\*\manifest.json` and Firefox `extensions.json`:
id, name, version, permissions, host permissions and content-script matches. Derived booleans:
`roblox_access`, `all_sites`, `user_scripts` (Tampermonkey-style), `debugger`. Never reads cookies,
history, storage, passwords or extension data folders.
