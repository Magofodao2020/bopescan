<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0138 — The screenshare mode is removed

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0. Supersedes the screenshare view and redaction decisions.

## Decision

The SS (screenshare) mode is removed end to end: the `Mode` and `SsOptions` types, masking and the
hidden counts in `bope-core::view`, the CLI `--mode`/`--yes` options and consent prompt, the desktop
mode choice, routes, states and filters, the locale keys and the screenshare guides. The view is built by
`view::for_report` alone; the report schema version is 2 (`header.profiles_directory` removed). No other
capture or automatic sharing mechanism replaces it: a report is read by the person who ran the scan and
whoever they choose to give it to.
