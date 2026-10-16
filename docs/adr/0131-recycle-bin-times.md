<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0131 — The Recycle Bin and its times

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0 (interface rework)

## Decision

A `recycle_bin` collector lists `<SystemDrive>\$Recycle.Bin\<SID>` of the account running the scan once,
reads each `$I` file (a few hundred bytes of metadata) and never opens a `$R` file: its presence, size and
times come from the listing. Nothing is restored, moved, deleted or changed; the SID is used to find the
folder and is not kept.

- `scope: bin` (no name in it): the folder's own creation and last-write times, `$I`/`$R` counts, entries
  without a partner, unreadable `$I`, newest and oldest deletion recorded, and
  `last_artifact_change` = the newest of the folder's write time and its entries' times, with
  `last_artifact_change_source` (`folder` or `entry`).
- `scope: item`: `deleted_at` from inside the `$I`, the `$I` entry's own times, whether the `$R` is there
  and its times, and the catalog match when the name matches one.

"When was the Recycle Bin modified?" is answered as **"Última modificação observada no artefato"**, never
as a global time: emptying the bin removes entries and writes the folder, so a folder time newer than every
entry is consistent with an emptying and with anything else that wrote it. A missing item is never read as
a deliberate deletion. The `$R` last-write time is the artifact's (usually kept from the file when moved on
the same volume, but settable), not the file's history.

SS mode shows the `bin` summary and only items whose name matches the tool catalog, redacted like evidence
(`bope-core::view`). The existing `roblox_files` `scope: recycled` observations and their rules are
unchanged. Correlation with USN/MFT/Amcache is left to `roblox_trace` by name, as before; no new
correlation was added.
