<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0137 — Monitoring mode

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0

## Decision

An explicit, visible, read-only mode that samples the Roblox player at an interval the person chooses
(at least 5 s): modules, private executable regions, unlisted images, JSON flag values in private memory
(at most 256 MiB, 20 s per sample) and the settings files' hashes and values. `monitor::Session::record`
keeps what changed between samples, each change with the times of the two samples around it, and
`flag_value_restored` when a value returns to one it had earlier in the session.

- **Desktop**: Start / Stop on the Roblox page, a notice while it runs, live events; kept in memory only,
  ends with the window, and goes into the next report (`ScanContext::monitor`). "Esquecer esta sessão"
  drops it.
- **CLI**: `bope-scanner-cli monitor --interval S --duration S --out FILE` prints each change and appends
  it to a new file the person names; `scan --monitor-log FILE` puts the session in the report.
- `roblox_monitor` reports the session, or is unmeasured `source_absent` when none was run.

Nothing is installed or scheduled, nothing starts with Windows, nothing is sent, no memory is written
and no flag is changed. A change made and undone between two samples is not seen, and the report says
only what the samples saw.
