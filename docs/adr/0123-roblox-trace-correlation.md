<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0123 — Correlating Roblox tool traces

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

Each collector sees one kind of artifact. A reviewer needs: what points at which tool, from which
independent sources, whether anything shows it ran or touched the Roblox player, and what could not be
read.

## Decision

`roblox_trace` runs after every other collector over their observations (it reads no artifact):

1. **Hits**: each row whose name, path or parent folder matches the catalog — or that lies inside an
   executor layout (attributed to the layout's tool, or to `unnamed_executor`) — with an evidence
   class fixed by its source: execution (Prefetch, BAM, PCA, UserAssist, FeatureUsage), inventory
   (ShimCache, Amcache), reference (shortcuts, MRU, MuiCache), file history / deleted (USN, Recycle
   Bin), current file, archive content, executor layout/scripts, installation, persistence, running,
   process interaction (module in the Roblox player), client configuration. History paths are checked
   for existence today (`exists`), never reported as deleted.
2. **Tools**: hits grouped by tool, with independent families (the assessment's `source_family`), the
   classes, first/last time and a status: `info` (legitimate tool, generic term, partial or ambiguous
   name without Roblox context), `suspected` (executor/injector name with context, nothing showing it
   ran), `detected` (execution, layout, executor scripts or module), `corroborated` (detected and two or
   more families). A name seen with context lends it to the same file name elsewhere.
3. **Sources**: each source's state — measured, not_measured (with reason), not_applicable
   (full-scan source in a standard scan) or error.

Rules give `corroborated`/`detected` level flag, `suspected` warn, the rest info. For the assessment, a
rule over `roblox_trace` counts as the families named in its rows, not as a new family, so one record
is never counted twice. The view carries the rows in `roblox_tools` (SS mode: tools, hits of
suspected-or-stronger tools, sources; paths redacted).

## Consequences

States map to the brief's vocabulary: INFO, SUSPECTED, DETECTED, CORROBORATED; NOT_MEASURED,
ERROR and NOT_APPLICABLE are source states. No status is a verdict.
