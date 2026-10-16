<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0133 — Drive inventory and image integrity classes

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0

## Context

Earlier collectors look in places a tool is known to use. A DLL or executable dropped anywhere else was
not seen, and a file's state was one word (signature valid or not).

## Decision

**`file_inventory` (full tier).** Walks every accessible fixed and removable drive
(`VolumeSource`: `GetLogicalDrives`, `GetDriveTypeW`, `GetVolumeInformationW`), user folders and
Program Files first, `WinSxS` last. Reparse points are never followed (`DirEntryInfo::is_link`); a
folder is listed once (case-folded path); depth, file count and time are bounded; the run is cancellable
(`CollectContext`) and says what it is reading. The summary counts files and folders listed, folders not
accessible, links skipped, depth-limited folders, images found / assessed / counted only / not assessed,
disguised images and each class. A walk that stopped is `complete: false` with `stopped_by`, and the
`file` place becomes a discriminator gap (`budget_spent`, or `read_failed` when nothing was listed), so
no rule can say "not found" about files nobody looked at.

**Integrity classes** (`integrity.rs`): `verified_reference` (embedded or catalog signature that
verifies, signer and certificate known), `valid_signature`, `unknown`, `suspicious`,
`integrity_compromised`, `malicious_corroborated`, `not_verified`, `inconclusive`. Each row carries the
reasons and the limitations (for example `revocation_not_checked`: verification is offline). The inputs
are SHA-256, the Authenticode signature with its signing time, the Windows catalog
(`CryptCATAdminAcquireContext2` SHA-256 then legacy, `WinVerifyTrust` with `WTD_CHOICE_CATALOG`, offline),
and the PE structure (`bope_parsers::pe`): machine, sections and their permissions and entropy, imports
(delay-loaded included), exports, TLS callbacks, version resource, checksum, overlay, anomalies.
`malicious_corroborated` needs two independent facts: a catalogued cheat-capable tool name **and** the
imports used to write into other processes. A name or a path alone never decides a class, and no class is
allowed by name.

**Nothing is executed.** Files are read; no file is loaded as a module, mapped as an image or run.

## Consequences

Only rows a reader needs are listed (classes other than signed, and unknown files in user-writable places
or on other drives); the rest are counted. A full scan takes longer; the budget is 25 minutes.
