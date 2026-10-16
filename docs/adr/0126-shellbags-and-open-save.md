<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0126 — ShellBags and OpenSavePidlMRU, narrowed to the catalog

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Decision

`bope_parsers::shell_items` decodes item ID lists (root class ids, volumes, file entries with the
`0xBEEF0004` extension: long name, FAT times, NTFS reference; network locations). The `shellbags`
collector (**full scan**, like `shell_mru`, ADR 0113) walks `BagMRU` under `UsrClass.dat` and `NTUSER.DAT`
(at most 20 000 nodes) and every `ComDlg32\OpenSavePidlMRU` list, and keeps only paths with a segment
matching the catalog or naming Roblox. Registry key times are not read; item times are the folder's own
FAT times. Class `reference`, family `shellbags`. Opening a folder is never execution.
