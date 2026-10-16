<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0108 — Executor footprint and Lua markers

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`executor_footprint` looks in the folders executors use (`%LOCALAPPDATA%`, `%APPDATA%`, Downloads,
Desktop, Documents) for the **layout** shared by Roblox executors: a folder with `autoexec` and
`workspace` (and often `scripts`, `bin`). It never decides by a product name alone; known public names
only label an already-matched layout.

Scripts (`.lua`, `.luau`, `.txt` in autoexec/scripts, ≤ 1 MiB) are scanned by
`bope_parsers::lua_markers` for functions that exist only in executor environments (`getgenv`,
`hookfunction`, `getrawmetatable`, `setreadonly`, `fireclickdetector`, `loadstring(game:HttpGet(...))`,
…). Only the **set of marker names** and counts leave the parser; the text is never stored or shown.
`request` alone is weak and cannot match by itself.
