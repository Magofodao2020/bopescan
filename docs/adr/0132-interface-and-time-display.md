<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0132 — Interface rework and one way of showing times

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0 (interface rework)

## Decision

**Identity.** The B.O.P.E badge (`apps/desktop/src/assets/bope-logo.png`, also the app icons) sets the
palette: black field, red ring, gold, white. Tokens in `styles.css`; no gradient, glow or emoji; every
state is a word, a shape and a colour (`ui/Badge.tsx`). A stopped service is never coloured as a finding.

**Navigation.** A side navigation over one scan flow: Visão geral, Scanner, Evidências, Serviços do
Windows, Lixeira, Linha do tempo, Relatórios, Configurações e sobre. Result pages are disabled until a report
exists, so no page is ever empty for want of a scan. Evidence details open in a side panel; raw JSON is
folded. Long lists are paginated.

**Progress.** `scan::Progress::next` names the collector that runs after each one; the desktop status
reports `current` and `cancel_requested`. The window shows the module running, read / not read / advanced
only / pending counts and the elapsed time since `started_at`. The bar is the share of modules finished,
never a time estimate.

**Times.** Rust stores each time once, RFC 3339 UTC. `src/time.ts` (and `bope_core::report_time` for the
exports, with the same cases tested on both sides) parses only that text, so a value is converted once;
anything else is shown as received and marked. A time is shown as `DD/MM/AAAA HH:mm:ss` in the local zone
with its offset at that instant, UTC below it (or UTC first, a display setting), the value received on
hover and in `<time datetime>`. Each time carries its kind (created, modified, accessed, execution, event,
service event, deletion, collection, scan, range bound…) from the collector and field, and a certainty
(exact, approximate, uncertain for file times any program can set). The timeline orders entries by instant,
then source, field, place and subject, never merges two entries, and filters by source, kind, certainty,
text and date in the shown zone. `time_fields` tells the window which fields are times; it never guesses
from a value's shape.

**Exports.** HTML, TXT and PDF write each time in UTC and in the zone the window shows (passed by the
desktop; the CLI uses the system zone), with kind and certainty in the timeline, and services and Recycle
Bin sections. JSON keeps every value as recorded and names the zone.

**Notices.** The `UNOFFICIAL BUILD` banner across the window is removed at the owner's request. NOTICE
section 7(c) requires the program to keep showing that indication, so it stays in About (Configurações e
sobre), in the report facts on the overview and in every export, with the credits and licences.
