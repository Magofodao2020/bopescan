<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0120 — Amcache from shadow copies that already exist

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

`Amcache.hve` is held open by Windows without sharing. Ways to read it: a raw-volume parser, the
backup privilege with a registry load, or a copy. Creating a shadow copy or loading a hive changes the
machine.

## Decision

Try the live file once (it normally fails); then probe existing
`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\AppCompat\Programs\Amcache.hve`,
N = 256 down to 1, and read the newest. Parse with a small read-only `regf` reader
(`bope_parsers::regf`): nk/vk cells, lf/lh/li/ri lists, inline and single-cell data; big data and
transaction logs are not applied (`dirty` is reported). Read `Root\InventoryApplicationFile` and
`Root\InventoryApplicationShortcut`. Keep rows for catalog matches, Roblox paths and user-writable
locations; count the rest. No shadow copy: `source_absent`; not admin: `not_admin`.

## Consequences

Machines without restore points/shadow copies report Amcache unmeasured. The snapshot's age bounds what
it can show (`hive_written`). An entry is inventory, not execution.
