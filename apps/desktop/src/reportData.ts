// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Everything the result pages read, asked for once per finished scan and shared by every page, so
// that each page shows the same frozen report and no page asks Rust again on its own.

import { useEffect, useState } from "react";
import { ageTexts, codeLinks, reportView, ruleMeta, ruleTexts, timeFields } from "./api";
import type { AgeText, CodeLinks, ReportView, RuleMeta, RuleText } from "./types";

/** One finished scan; a new object for each, so the pages read its report afresh. */
export interface ScanResult {
  startedAt: string | null;
}

export interface ReportData {
  view: ReportView | null;
  /** The view could not be read. */
  failed: string | null;
  texts: Record<string, RuleText>;
  ages: Record<string, AgeText>;
  meta: Record<string, RuleMeta>;
  /** `null` while unknown — in flight or failed — never a guess about the build (carried fix b). */
  links: CodeLinks | null;
  /** The fields each collector declares as times; empty until known. */
  timeFields: Record<string, string[]>;
}

export function useReportData(result: ScanResult | null, lang: string): ReportData {
  const [view, setView] = useState<ReportView | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [texts, setTexts] = useState<Record<string, RuleText>>({});
  const [ages, setAges] = useState<Record<string, AgeText>>({});
  const [meta, setMeta] = useState<Record<string, RuleMeta>>({});
  const [links, setLinks] = useState<CodeLinks | null>(null);
  const [times, setTimes] = useState<Record<string, string[]>>({});

  useEffect(() => {
    setView(null);
    setFailed(null);
    if (!result) {
      return;
    }
    let alive = true;
    void reportView()
      .then((next) => alive && setView(next))
      .catch((reason: unknown) => alive && setFailed(String(reason)));
    return () => {
      alive = false;
    };
  }, [result]);

  useEffect(() => {
    // Without levels and categories the evidence page falls back to grouping by collector.
    void ruleMeta()
      .then(setMeta)
      .catch(() => {});
    void codeLinks()
      .then(setLinks)
      .catch(() => {});
    void timeFields()
      .then(setTimes)
      .catch(() => {});
  }, []);

  useEffect(() => {
    void ruleTexts(lang)
      .then(setTexts)
      .catch(() => {});
    // A failed call leaves the retention texts out; the rows themselves still show (ADR 0061).
    void ageTexts(lang)
      .then(setAges)
      .catch(() => {});
  }, [lang]);

  return { view, failed, texts, ages, meta, links, timeFields: times };
}

/** A field of an observation as text; `""` when it is absent. */
export function fieldText(fields: Record<string, unknown>, name: string): string {
  const value = fields[name];
  if (value === undefined || value === null) {
    return "";
  }
  return typeof value === "string" ? value : String(value);
}
