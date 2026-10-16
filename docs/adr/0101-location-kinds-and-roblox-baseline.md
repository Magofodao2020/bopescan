<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0101 — Where a program ran from, and a Roblox reference PC

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`bope-collectors::location` classifies a path into `windows`, `program_files`, `program_data`,
`user_downloads`, `user_desktop`, `user_documents`, `user_temp`, `user_appdata`, `removable`, `other`,
after stripping NT prefixes (`\??\`, `\Device\HarddiskVolumeN`). Rules use the kind, not the user name.

`fixtures/hosts/baseline-roblox-win11` models an ordinary Roblox player's PC (Roblox, Discord, Chrome
with ordinary extensions, a gaming-peripheral suite, Defender). `check-baseline` requires every rule to
stay quiet there; rules that cannot be confronted are listed with a reason in `rules/unconfronted.csv`.
