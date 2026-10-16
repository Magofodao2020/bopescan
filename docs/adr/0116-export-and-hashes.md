<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0116 — Saved reports and hashes

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`bope-core::export` writes JSON (the view), HTML (static, no scripts, no external resources, escaped) and
TXT, named `bope-report-<stamp>-<mode>.<ext>`, each with a `.sha256` file. Each report includes the
program version, rule-bundle version and the report's own hash line. SS-mode reports are redacted
exactly like the screen. Files are written only to the folder the person picked; PDF is not offered
(it would need a large renderer — print the HTML instead).
