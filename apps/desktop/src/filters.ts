// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Search, filters and ordering of the result panel (B.O.P.E, ADR 0100). Presentation only: which
// evidence a view lists is decided in `bope-core::view`, and nothing here hides a row the view lists
// unless the person asked for it with a filter they can see and clear.

import { parseInstant } from "./time";
import type { Evidence, Level, RuleMeta, RuleText } from "./types";

export type LevelFilter = "all" | Level;
export type SortOrder = "category" | "severity" | "time";

export interface Filters {
  search: string;
  level: LevelFilter;
  category: string | null;
}

export const NO_FILTERS: Filters = { search: "", level: "all", category: null };

const LEVEL_RANK: Record<Level, number> = { flag: 0, warn: 1, info: 2 };
const STATE_RANK: Record<Evidence["state"], number> = { found: 0, unmeasured: 1, not_found: 2 };

/** Every text a row can be found by: its title, rule id, collector and observed values. */
function haystack(item: Evidence, text: RuleText | undefined): string {
  const parts: string[] = [item.rule_id, item.collector, text?.title ?? ""];
  if (item.state === "found") {
    for (const observation of item.observations) {
      for (const value of Object.values(observation.fields)) {
        parts.push(String(value));
      }
    }
  }
  return parts.join("\n").toLowerCase();
}

/** The rows the person's filters keep, in the view's order. */
export function filterEvidence(
  evidence: Evidence[],
  filters: Filters,
  meta: Record<string, RuleMeta>,
  texts: Record<string, RuleText>,
): Evidence[] {
  const needle = filters.search.trim().toLowerCase();
  return evidence.filter((item) => {
    const info = meta[item.rule_id];
    if (filters.category && info?.category !== filters.category) {
      return false;
    }
    if (filters.level !== "all" && (item.state !== "found" || info?.level !== filters.level)) {
      return false;
    }
    if (needle && !haystack(item, texts[item.rule_id]).includes(needle)) {
      return false;
    }
    return true;
  });
}

/** The earliest RFC 3339 time a found row's observations carry, as milliseconds, or `null`. */
export function earliestTime(item: Evidence): number | null {
  if (item.state !== "found") {
    return null;
  }
  let best: number | null = null;
  for (const observation of item.observations) {
    for (const value of Object.values(observation.fields)) {
      const instant = typeof value === "string" ? parseInstant(value) : null;
      if (instant && (best === null || instant.getTime() < best)) {
        best = instant.getTime();
      }
    }
  }
  return best;
}

/** Rows ordered by severity (flag, warn, info, then unmeasured, then not found) or by time. */
export function sortEvidence(
  evidence: Evidence[],
  order: SortOrder,
  meta: Record<string, RuleMeta>,
): Evidence[] {
  const rows = [...evidence];
  if (order === "severity") {
    const rank = (item: Evidence) =>
      STATE_RANK[item.state] * 10 +
      (item.state === "found" ? LEVEL_RANK[meta[item.rule_id]?.level ?? "info"] : 0);
    return rows.sort((a, b) => rank(a) - rank(b));
  }
  if (order === "time") {
    return rows.sort((a, b) => {
      const ta = earliestTime(a);
      const tb = earliestTime(b);
      if (ta === null && tb === null) {
        return STATE_RANK[a.state] - STATE_RANK[b.state];
      }
      if (ta === null) {
        return 1;
      }
      if (tb === null) {
        return -1;
      }
      return ta - tb;
    });
  }
  return rows;
}
