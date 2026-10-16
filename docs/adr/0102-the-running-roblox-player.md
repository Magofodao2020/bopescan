<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0102 — The running Roblox player: modules and executable memory

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`roblox_process` looks at running `RobloxPlayerBeta.exe` processes with `PROCESS_QUERY_INFORMATION |
PROCESS_VM_READ` only: the module list (`EnumProcessModulesEx`) and a `VirtualQueryEx` walk that counts
executable regions by type (private, mapped, image). It never reads memory contents, never writes,
never injects, never suspends and never opens a handle with more rights.

Observations: `roblox_process` (parent, signature, location), `roblox_module` (modules outside Windows,
Program Files and the Roblox version folder), `roblox_memory` (counts of executable private/mapped
regions), `user_location_process` (any process running from Downloads/Desktop/Temp).

Hyperion commonly denies the open; that is `access_denied` as a place gap, never a finding. A JIT or
overlay (Discord, GPU tools) can create executable private memory, so memory rules are `warn` and say so.
Budget: 25 s.
