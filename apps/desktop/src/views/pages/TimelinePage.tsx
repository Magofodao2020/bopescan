// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The timeline (ADR 0051, B.O.P.E ADR 0132). Which times reach it is decided in `bope-core::view`;
// this page orders them the same way every time (instant, then source, field, place and subject),
// labels each with what it says happened and how certain that is, filters them, and shows them a page
// at a time. Two entries are never merged, even at the same second: each keeps its own source.

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  compareInstants,
  parseInstant,
  type TimeCertainty,
  type TimeKind,
  timeCertainty,
  timeKind,
  wallClock,
} from "../../time";
import type { AgeText, ReportView, RuleText, TimelineEntry } from "../../types";
import { Pager, usePage } from "../../ui/Paging";
import { Empty } from "../../ui/States";
import { TimeValue, useTimeSettings } from "../../ui/TimeValue";
import { CrossSource, TraceAges } from "../TraceAges";

interface Props {
  view: ReportView;
  texts: Record<string, RuleText>;
  ages: Record<string, AgeText>;
}

interface Row {
  entry: TimelineEntry;
  index: number;
  kind: TimeKind;
  certainty: TimeCertainty;
}

/** The deterministic order of two entries: instant, then source, field, place, subject, then input. */
export function compareEntries(a: Row, b: Row): number {
  return (
    compareInstants(a.entry.at, b.entry.at) ||
    (a.entry.collector ?? "").localeCompare(b.entry.collector ?? "") ||
    a.entry.field.localeCompare(b.entry.field) ||
    (a.entry.place ?? "").localeCompare(b.entry.place ?? "") ||
    (a.entry.subject ?? "").localeCompare(b.entry.subject ?? "") ||
    a.index - b.index
  );
}

/** `YYYY-MM-DD` of `at` in `zone`, for the date filters; `null` when `at` is not a time. */
export function dayOf(at: string, zone: string): string | null {
  const date = parseInstant(at);
  if (!date) {
    return null;
  }
  const [day = "", month = "", rest = ""] = wallClock(date, zone).split("/");
  return `${rest.slice(0, 4)}-${month}-${day}`;
}

export function TimelinePage({ view, texts, ages }: Props) {
  const { t } = useTranslation("report");
  const { zone, display } = useTimeSettings();
  const shownZone = display === "utc" ? "UTC" : zone;
  const timeline = view.timeline;
  const [collector, setCollector] = useState("");
  const [kind, setKind] = useState("");
  const [certainty, setCertainty] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [search, setSearch] = useState("");

  const rows: Row[] = useMemo(
    () =>
      timeline.entries
        .map((entry, index) => ({
          entry,
          index,
          kind: timeKind(entry.collector, entry.field),
          certainty: timeCertainty(entry.collector, entry.field),
        }))
        .sort(compareEntries),
    [timeline],
  );
  const collectors = [
    ...new Set(rows.flatMap((r) => (r.entry.collector ? [r.entry.collector] : []))),
  ];
  const kinds = [...new Set(rows.map((r) => r.kind))];
  const collectorName = (id: string) => t(`collector.${id}`, { defaultValue: id });
  const from_ = (entry: TimelineEntry) =>
    entry.source.kind === "evidence"
      ? (texts[entry.source.rule_id]?.title ?? entry.source.rule_id)
      : entry.source.kind === "selector"
        ? (texts[entry.source.selector_id]?.title ?? entry.source.selector_id)
        : entry.source.kind === "observation"
          ? t("timeline.unmatched")
          : "";

  const needle = search.trim().toLowerCase();
  const shown = rows.filter(({ entry, kind: k, certainty: c }) => {
    // Anchors stay whatever the filter: they are what the other times are read against.
    if (entry.collector === null) {
      return true;
    }
    if (collector && entry.collector !== collector) {
      return false;
    }
    if (kind && k !== kind) {
      return false;
    }
    if (certainty === "not_exact" && c === "exact") {
      return false;
    }
    if (certainty && certainty !== "not_exact" && c !== certainty) {
      return false;
    }
    const day = dayOf(entry.at, shownZone);
    if ((from && (!day || day < from)) || (to && (!day || day > to))) {
      return false;
    }
    if (
      needle &&
      ![entry.place, entry.subject, entry.field, entry.collector, from_(entry)]
        .join(" ")
        .toLowerCase()
        .includes(needle)
    ) {
      return false;
    }
    return true;
  });
  const paged = usePage(shown, 200);
  const selectors = [
    ...new Set(
      shown.flatMap(({ entry }) =>
        entry.source.kind === "selector" ? [entry.source.selector_id] : [],
      ),
    ),
  ];

  return (
    <div className="page-stack">
      <section className="panel timeline" aria-labelledby="timeline-title">
        <h3 id="timeline-title">{t("timeline.title")}</h3>
        {/* What the timeline never says, said above it (ADR 0051 decision 6). */}
        <p className="scope">{t("timeline.note")}</p>
        <p className="small muted">
          {t("common:ui.timeline.zone_note", {
            zone: display === "utc" ? "UTC" : zone,
          })}
        </p>

        {timeline.bands.length > 0 && (
          <details>
            <summary>{t("timeline.coverage_note")}</summary>
            <ul className="bands">
              {timeline.bands.map((band) => (
                <li key={`${band.collector}:${band.place ?? ""}:${band.subject ?? ""}`}>
                  {[collectorName(band.collector), band.place, band.subject]
                    .filter(Boolean)
                    .join(" · ")}
                  : <TimeValue value={band.from} compact /> → <TimeValue value={band.to} compact />
                </li>
              ))}
            </ul>
          </details>
        )}

        {timeline.unmeasured.length > 0 && (
          <details>
            <summary>
              {t("common:ui.timeline.unread", { count: timeline.unmeasured.length })}
            </summary>
            <ul className="unmeasured-sources">
              {timeline.unmeasured.map((source) => (
                <li key={`${source.collector}:${source.place ?? ""}`}>
                  {t("timeline.not_measured", {
                    source: [collectorName(source.collector), source.place]
                      .filter(Boolean)
                      .join(" · "),
                    reason: t(`reason.${source.reason}`),
                  })}
                </li>
              ))}
            </ul>
          </details>
        )}

        <div className="filters">
          <label className="search">
            {t("finder.search")}
            <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
          </label>
          {collectors.length > 1 && (
            <label>
              {t("timeline.filter")}
              <select value={collector} onChange={(event) => setCollector(event.target.value)}>
                <option value="">{t("timeline.all")}</option>
                {collectors.map((id) => (
                  <option key={id} value={id}>
                    {collectorName(id)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label>
            {t("common:ui.timeline.kind")}
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">{t("common:ui.all")}</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {t(`common:ui.time.kind.${k}`)}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t("common:ui.timeline.certainty")}
            <select value={certainty} onChange={(e) => setCertainty(e.target.value)}>
              <option value="">{t("common:ui.all")}</option>
              <option value="exact">{t("common:ui.time.certainty.exact")}</option>
              <option value="not_exact">{t("common:ui.timeline.not_exact")}</option>
              <option value="approximate">{t("common:ui.time.certainty.approximate")}</option>
              <option value="uncertain">{t("common:ui.time.certainty.uncertain")}</option>
            </select>
          </label>
          <label>
            {t("common:ui.timeline.from")}
            <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label>
            {t("common:ui.timeline.to")}
            <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
          </label>
        </div>

        <p className="muted">{t("timeline.count", { count: shown.length })}</p>
        {shown.length === 0 ? (
          <Empty title={t("common:ui.timeline.none")} />
        ) : (
          <ol className="timeline-list entries">
            {paged.rows.map((row, position) => {
              const previous = paged.rows[position - 1];
              const day = dayOf(row.entry.at, shownZone);
              const breaks = previous && dayOf(previous.entry.at, shownZone) !== day;
              return (
                <li
                  key={`${row.index}`}
                  className={`timeline-item ${row.entry.collector === null ? "anchor" : ""} ${breaks ? "day-break" : ""}`}
                >
                  <TimeValue value={row.entry.at} />
                  <span className="kind">
                    {t(`common:ui.time.kind.${row.kind}`)}
                    {row.certainty !== "exact" && (
                      <>
                        <br />
                        <span className={`certainty-${row.certainty}`}>
                          {t(`common:ui.time.certainty.${row.certainty}`)}
                        </span>
                      </>
                    )}
                  </span>
                  <Entry entry={row.entry} from={from_(row.entry)} />
                </li>
              );
            })}
          </ol>
        )}
        <Pager {...paged} />

        {selectors.length > 0 && (
          <section className="selectors" aria-labelledby="timeline-selectors-title">
            <h4 id="timeline-selectors-title">{t("timeline.selectors")}</h4>
            {selectors.map((id) => {
              const text = texts[id];
              if (!text) {
                return null;
              }
              return (
                <div key={id} className="selector">
                  <p>
                    <strong>{text.title}</strong> — {text.description}
                  </p>
                  <p className="muted">{t("timeline.selector_causes")}</p>
                  <ul>
                    {text.falsepositives.map((cause) => (
                      <li key={cause}>{cause}</li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </section>
        )}
      </section>

      {/* Above and beside the timeline, in both modes, only when their conditions hold (ADR 0061). */}
      <CrossSource statements={view.cross_source ?? []} />
      {view.trace_ages && <TraceAges ages={view.trace_ages} texts={ages} />}
    </div>
  );
}

function Entry({ entry, from }: { entry: TimelineEntry; from: string }) {
  const { t } = useTranslation("report");
  if (entry.source.kind === "anchor") {
    return (
      <strong>
        {entry.field === "generated_at" ? t("timeline.scan_time") : t("timeline.boot_time")}
      </strong>
    );
  }
  const where = [
    entry.collector ? t(`collector.${entry.collector}`, { defaultValue: entry.collector }) : null,
    entry.place,
    entry.subject,
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <span>
      {where} — <code>{entry.field}</code> <span className="muted">({from})</span>
    </span>
  );
}
