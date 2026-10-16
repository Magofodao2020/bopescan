<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0121 — Catalog names in the NTFS change journal

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

ADR 0047 kept the journal name-free: counts per watched folder only.

## Decision (amends ADR 0047)

`bope_parsers::usn::named_records` decodes each record's name only to hand it to a caller predicate.
The `usn` collector keeps names that match the catalog (any kind but a weak partial), at most 300
distinct names, with counts of records, creations, deletions, renames and first/last times
(`location: named`). Every other name is dropped after comparison. The journal names a file, not its
folder; the same name may be unrelated files.
