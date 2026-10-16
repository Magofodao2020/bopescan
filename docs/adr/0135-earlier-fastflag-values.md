<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0135 — Earlier FastFlag values: other copies and crash dumps

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0

## Context

A flag set and then put back leaves the active file looking ordinary. Only records the PC still holds can
say otherwise, and no history may be invented.

## Decision

`roblox_flags` reports, besides the current values (ADR 0136):

- `change`: a flag whose value in another copy on the PC (backup, older version folder, bootstrapper copy)
  differs from the active file, with both values, both paths and both files' modification times, and a
  `finding` that says whether the other copy held a non-reference value the active file no longer has.
- `dump` / `dump_value`: Roblox crash dumps (`%LOCALAPPDATA%\CrashDumps\RobloxPlayerBeta.exe.*.dmp` and
  `*.dmp` under `%LOCALAPPDATA%\Roblox\logs`, newest twelve) parsed with `bope_parsers::minidump`
  (header, module list, misc info, memory list and 64-bit memory list); JSON flag assignments in their
  captured memory, with the time the dump was written.
- Monitoring sessions (ADR 0137) add changes seen over time.

When there is no such record there is no row; nothing is inferred between two times.
