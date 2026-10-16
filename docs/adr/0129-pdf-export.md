<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0129 — Native PDF export without a dependency

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Decision

`bope_core::pdf` writes PDF 1.4 by hand: A4 pages, the standard Courier and Helvetica-Bold fonts with
`WinAnsiEncoding` (no font embedded), an exact cross-reference table, deterministic bytes (no random id or
current time; dates come from the report). `export::Format::Pdf` renders the text report — version,
UTC time, coverage, Roblox tools, sources, evidence with states, timeline, limitations and false
positives — and adds the SHA-256 of the JSON export of the same view. Like every format it is built from
the view (SS redaction applies) and gets its own SHA-256.

## Consequences

Characters outside Windows-1252 print as `?` (Thai: use HTML). No printing engine, WebView or external
service is involved.
