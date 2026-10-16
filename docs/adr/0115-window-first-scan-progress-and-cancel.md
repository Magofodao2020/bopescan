<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0115 — Window first: consent, progress and cancel

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

Upstream ADR 0001 scanned before showing a window. Communities asked to see what will be read first,
and to watch and stop the scan.

## Decision

The hardened window opens first. Nothing is read until the person picks mode/tier and consents.
`scan::run_with_progress` runs the same collectors as `scan::run`, one at a time, on a worker thread,
reporting `Progress {step, total, collector, state, found_rules}` and checking a cancel flag between
collectors. A cancelled scan produces no report. The UI polls `scan_status`; it cannot alter results.
