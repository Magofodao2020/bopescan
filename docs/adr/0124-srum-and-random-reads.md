<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0124 — SRUM through a bounded ESE reader, and random-access reads

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Context

`%SystemRoot%\System32\sru\SRUDB.dat` (System Resource Usage Monitor) records, per hour, which programs
used CPU and network. It is an ESE ("Jet Blue") database held open by the Diagnostic Policy Service and
often larger than the 64 MiB a host reads in one piece (ADR 0019). The Rust ESE crates on crates.io were
0.1.x releases with no track record; libesedb is C.

## Decision

- A new host trait, `RandomReadSource` (`file_size`, `read_file_at`, `read_volume_at`), reads at an
  offset, at most `MAX_READ_AT_BYTES` (1 MiB) per call, opening with every share mode and for reading only.
  The live host uses `std::fs` only (no `unsafe`).
- `bope_parsers::ese`: a bounded reader written from the public format description (libyal/libesedb)
  and checked against dissect.esedb's record reading: file header, 4–32 KiB pages, page tags, branch and
  leaf pages, the catalog, fixed/variable/tagged columns, 7-bit and XPRESS compression. It does **not**
  replay transaction logs, follow the long-value tree, read multi-values or verify checksums; a limit on
  pages, records and depth ends every walk and is reported.
- `bope_parsers::srum` reads `SruDbIdMapTable` (IdType 0–2 only; user SIDs are never read), the
  application resource usage table (TimeStamp, AppId, foreground/background cycle time), the application
  timeline table (EndTime, DurationMS) and the network usage table (bytes sent/received totals only).
- The `srum` collector reads the live file once, then the newest **existing** shadow copy, like
  `amcache` (ADR 0120). It lists apps matching the catalog, naming Roblox or in user-writable folders.
- Correlation: a SRUM app row with CPU time is class `resource_usage`, which `roblox_trace` counts as
  execution; one without is `reference`. Family `srum`.

## Consequences

Without a shadow copy and administrator rights SRUM is `not_admin`/`source_absent`. A copied database is
usually in "dirty shutdown": the last hour(s) still in the logs are missing. Times are hours, not starts.
The ESE reader was tested on synthetic databases only; a real SRUDB.dat must be validated on Windows
(docs/bope/validacao-windows.md).
