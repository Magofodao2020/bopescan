<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0107 — The Roblox installation

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`roblox` reads `%LOCALAPPDATA%\Roblox\Versions\version-*` (and Program Files installs): the player's
signature and signer, binaries beside it whose names are Windows DLL names (proxy-DLL pattern),
`ClientSettings\ClientAppSettings.json` (flag names only, count, size), log folder size and newest time
(log text is never read), and third-party bootstrappers (Bloxstrap, Fishstrap, Voidstrap) as `info`.
FFlag editing via a bootstrapper is legitimate and labelled as such.
