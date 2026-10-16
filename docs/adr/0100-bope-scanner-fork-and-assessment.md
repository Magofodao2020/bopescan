<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0100 — B.O.P.E Scanner: the fork, and an assessment layer beside the evidence

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Context

B.O.P.E Scanner is a modified version of aeterna-rongroi 0.9.0, aimed at Roblox screenshares (FiveM checks
stay). The base was chosen after reading the source of three candidates (docs/bope/auditoria.md). The
GPL-3.0 NOTICE §7 terms apply: SPDX headers and NOTICE are kept, the upstream names do not identify this
version, every build says `UNOFFICIAL BUILD`, and the upstream official-build marker is never set.

Communities asked for a per-category state (OK / INFO / WARN / FLAG / NOT CHECKED) and an overall
conclusion. Upstream hard rule 3 forbids a score or a "clean" flag on evidence.

## Decision

1. Evidence stays as it was: `Found` / `NotFound` / `Unmeasured` per rule. Nothing in the report model
   changes meaning.
2. A separate, derived **assessment** (`bope-core::assessment`) is computed from the frozen report and the
   bundle and is never fed back into it. It has:
   - a `level` per rule (`info`/`warn`/`flag`, defaulting from the rule's strength) and a `category`
     (13 categories, defaulting from the collector);
   - a state per category: `NotChecked` when every collector of that category was unmeasured, otherwise
     the highest level found, otherwise `Ok`;
   - **source families**: rules over the same underlying source (e.g. `prefetch` and `bam` executions of
     the same file) count once, so one event is never double-counted;
   - **temporal proximity**: found timestamps from different families within 2 hours are listed;
   - a conclusion: `NoSuspiciousEvidence` (only "in the sources examined"), `Inconclusive` (key sources
     unmeasured), `ManualReview`, `MultipleCorroborated` (≥2 independent families at warn+),
     `HighConfidence` (≥2 independent families at flag, or flag + proximity).
3. No conclusion says "clean", "innocent" or "guilty". Every presentation carries the caveats (what
   software inside Windows cannot see).
4. Name-only collectors (`bam`, `feature_usage`, `pca`, `prefetch`, `shimcache`, `userassist`) may match
   names only through timeline selectors, never by a free keyword, so a file named like a cheat is not
   an accusation by itself.

## Consequences

AGENTS.md hard rule 3 is amended to allow this layer and nothing else. Tests pin that an ordinary
reference PC yields `NoSuspiciousEvidence` and that a single source cannot reach `HighConfidence`.
