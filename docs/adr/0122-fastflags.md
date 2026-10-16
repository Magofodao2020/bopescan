<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0122 — FastFlag files

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`fastflags` reads `ClientSettings\ClientAppSettings.json` in every Roblox version folder (Roblox's own,
Program Files, and launchers' `Versions`), launchers' own settings folders (three levels, JSON files
named like FastFlag settings) and FastFlag tools' folders (two levels, any JSON, backups included).
A version folder holding `RobloxPlayerBeta.exe` is `applies_to_player`; the newest one is
`active_version`. Keys are recognised as flags by their `[D|S]F{Flag,Int,String,Log}` prefix and
grouped by name into network/physics, frame rate, rendering, debug and other. Network/physics flag
**names** (≤ 25) are kept; values never. There is no trusted reference file and no comparison against
one. Found vs used: the active version's file is what the player reads; a launcher's copy is configured
and applied only when Roblox starts through it.
