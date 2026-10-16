<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0118 — A catalog of Roblox tools, and looking for their names

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

Communities asked to find Bloxstrap, FastFlag managers, FPS unlockers, executors and injectors, also
when renamed, moved or deleted, and to match name variants (`blox strap`, `fflag-manager`). Upstream
forbids keyword-only accusations (ADR 0100 keeps that).

## Decision

1. `bope-collectors::catalog` is the one table of tool names. Each entry has a kind (bootstrapper,
   FastFlag manager, FPS unlocker, client utility, executor, injector, generic term), distinctive
   aliases (substring match on the compact form), ambiguous aliases (whole-token only), and whether it
   is commonly legitimate. Names normalise by lowercasing, dropping extensions and Prefetch's hash, and
   removing separators. `strap`/`trap` are a weak partial, with an exclusion list of ordinary words.
   Only publicly known names are listed; nothing is invented.
2. `roblox_files` walks bounded places (AppData two levels, Downloads/Desktop/Documents two levels,
   Temp two levels, ProgramData and Program Files one level) and keeps **only matching names**, so a
   standard scan does not list a person's files. Matching programs are hashed and signature-checked.
   Inside Roblox's or a legitimate launcher's own folder, generic terms are not rows.
3. `.zip` archives that match, or sit in Downloads/Desktop/Temp, are opened to the central directory
   only (`bope_parsers::zip_names`): names, no extraction, ≤ 32 MiB, ≤ 25 archives. RAR/7z are not read.
4. The account's own `$Recycle.Bin\<SID>` `$I` files (`bope_parsers::recycle`) give original path and
   deletion time; only catalog matches are kept.

## Consequences

A renamed tool is not found by name; it is found by layout, scripts, modules or correlation. Every
name row says how it matched (`known_tool`, `ambiguous_alias`, `generic_term`, `weak_partial`).
