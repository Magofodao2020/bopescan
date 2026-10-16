// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

import { describe, expect, it } from "vitest";
import { earliestTime, filterEvidence, NO_FILTERS, sortEvidence } from "./filters";
import type { Evidence, RuleMeta } from "./types";

const found = (id: string, fields: Record<string, unknown>): Evidence => ({
  rule_id: id,
  collector: "roblox",
  strength: "presence",
  state: "found",
  observations: [{ collector: "roblox", fields }],
});

const rows: Evidence[] = [
  found("a", { path: "C:\\Users\\x\\Downloads\\tool\\x.exe", created: "2026-10-14T21:00:00Z" }),
  { rule_id: "b", collector: "usn", strength: "tamper", state: "not_found", retention: "x" },
  found("c", { name: "Bloxstrap", modified: "2026-10-13T08:00:00Z" }),
  {
    rule_id: "d",
    collector: "evtx",
    strength: "tamper",
    state: "unmeasured",
    reason: "not_admin",
    expected: true,
  },
];

const meta: Record<string, RuleMeta> = {
  a: { level: "flag", category: "roblox", collector: "executor_footprint", selector: false },
  b: { level: "warn", category: "files", collector: "usn", selector: false },
  c: { level: "info", category: "roblox", collector: "roblox", selector: false },
  d: { level: "warn", category: "system_logs", collector: "evtx", selector: false },
};

describe("filters", () => {
  it("keeps everything with no filter", () => {
    expect(filterEvidence(rows, NO_FILTERS, meta, {})).toHaveLength(4);
  });

  it("searches titles, ids and observed values without case", () => {
    const kept = filterEvidence(rows, { ...NO_FILTERS, search: "downloads" }, meta, {});
    expect(kept.map((r) => r.rule_id)).toEqual(["a"]);
    const byTitle = filterEvidence(rows, { ...NO_FILTERS, search: "launcher" }, meta, {
      c: { title: "Third-party launcher", description: "", falsepositives: [], retention: "" },
    } as never);
    expect(byTitle.map((r) => r.rule_id)).toEqual(["c"]);
  });

  it("a level filter keeps found rows of that level only", () => {
    expect(filterEvidence(rows, { ...NO_FILTERS, level: "warn" }, meta, {})).toHaveLength(0);
    expect(filterEvidence(rows, { ...NO_FILTERS, level: "flag" }, meta, {})[0]?.rule_id).toBe("a");
  });

  it("a category filter keeps that category's rows in every state", () => {
    expect(filterEvidence(rows, { ...NO_FILTERS, category: "roblox" }, meta, {})).toHaveLength(2);
  });

  it("orders by severity and by time", () => {
    expect(sortEvidence(rows, "severity", meta).map((r) => r.rule_id)).toEqual([
      "a",
      "c",
      "d",
      "b",
    ]);
    expect(sortEvidence(rows, "time", meta).map((r) => r.rule_id)).toEqual(["c", "a", "d", "b"]);
    expect(earliestTime(rows[1] as Evidence)).toBeNull();
  });
});
