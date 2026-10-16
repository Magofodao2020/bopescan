<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0125 — Master File Table metadata, read raw and read-only

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Context

Freed `$MFT` records keep the name, parent folder and times of deleted files until NTFS reuses them. The
change journal (ADR 0121) sees only a short window.

## Decision

- `RandomReadSource::read_volume_at` opens `\\.\C:` with `GENERIC_READ` and every share mode (no lock, no
  dismount, no write; needs administrator rights) and aligns reads to 4 KiB.
- `bope_parsers::ntfs`: boot sector, update-sequence fixups, FILE records (`$STANDARD_INFORMATION`,
  `$FILE_NAME`, unnamed `$DATA` size and data runs). No file content is ever read.
- The `mft` collector (**full scan**) reads `$MFT` in 1 MiB pieces following record 0's data runs, up to
  6 000 000 records and 90 s; keeps only names matching the catalog as a distinctive or ambiguous alias,
  rebuilds paths from parent records (checking sequence numbers) and reports `in_use`,
  `si_created_before_fn` and the times. Torn records are counted.
- Correlation: a freed record is class `deleted` (family `mft`); an in-use record is `current_file`
  and counts as the same family as the folder listing, so the same file never corroborates itself.

## Consequences

"Not in use" is metadata of a deleted entry, never recovered content. `$ATTRIBUTE_LIST`-extended records
and names only in extension records are not resolved. Only the system volume is read. Tested on
synthetic volume images; real-volume behaviour must be validated on Windows.
