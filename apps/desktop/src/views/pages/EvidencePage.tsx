// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The evidence (B.O.P.E, ADR 0132): the Roblox tool correlation, then every rule's result as one row —
// state, level, check, source, first time — filtered for real by text, state, level and category, and
// the selected row in a side panel. What the program left itself and what no rule matched follow,
// apart, as before (ADR 0010, ADR 0014).

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  type Filters,
  filterEvidence,
  NO_FILTERS,
  type SortOrder,
  sortEvidence,
} from "../../filters";
import { groupEvidence, type StateFilter } from "../../grouping";
import { withKeys } from "../../keys";
import type { ReportData } from "../../reportData";
import { compareInstants } from "../../time";
import type { Evidence, Observation } from "../../types";
import { Badge, EVIDENCE_LOOK, LEVEL_LOOK } from "../../ui/Badge";
import { Pager, usePage } from "../../ui/Paging";
import { Empty } from "../../ui/States";
import { TimeValue } from "../../ui/TimeValue";
import { EvidenceDetails, ObservationCard, stateKey } from "../EvidenceDetails";
import { CATEGORY_ORDER } from "../Home";
import { ReportSummary } from "../ReportSummary";
import { RobloxToolsPanel } from "../RobloxToolsPanel";
import { ScopeNotes } from "./OverviewPage";

/** What another page asked this one to show first. */
export interface EvidenceFocus {
  category: string | null;
  state: StateFilter | null;
}

interface Props {
  data: ReportData;
  focus: EvidenceFocus | null;
}

export function EvidencePage({ data, focus }: Props) {
  const { t } = useTranslation("report");
  const view = data.view;
  const [filters, setFilters] = useState<Filters>({
    ...NO_FILTERS,
    category: focus?.category ?? null,
  });
  const [state, setState] = useState<StateFilter | null>(focus?.state ?? null);
  const [sort, setSort] = useState<SortOrder>("category");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    if (focus) {
      setFilters((current) => ({ ...current, category: focus.category }));
      setState(focus.state);
    }
  }, [focus]);

  const { meta, texts } = data;
  const hasMeta = Object.keys(meta).length > 0;
  const timeFields = useMemo(
    () => new Set(Object.values(data.timeFields).flat()),
    [data.timeFields],
  );
  /** The earliest timeline time of each rule, from the core's timeline (ADR 0051). */
  const firstTime = useMemo(() => {
    const out = new Map<string, string>();
    for (const entry of view?.timeline.entries ?? []) {
      if (entry.source.kind !== "evidence") {
        continue;
      }
      const known = out.get(entry.source.rule_id);
      if (!known || compareInstants(entry.at, known) < 0) {
        out.set(entry.source.rule_id, entry.at);
      }
    }
    return out;
  }, [view]);

  if (!view) {
    return null;
  }
  const kept = filterEvidence(view.evidence, filters, meta, texts).filter(
    (item) => state === null || item.state === state,
  );
  const groups: { key: string; label: string; rows: Evidence[] }[] =
    sort === "category" && hasMeta
      ? [...CATEGORY_ORDER].flatMap((category) => {
          const rows = sortEvidence(
            kept.filter((item) => (meta[item.rule_id]?.category ?? "other") === category),
            "severity",
            meta,
          );
          return rows.length === 0
            ? []
            : [{ key: category, label: t(`category.${category}`), rows }];
        })
      : sort === "category"
        ? groupEvidence(kept, null, view.collector_order).map((group) => ({
            key: group.collector,
            label: t(`collector.${group.collector}`, { defaultValue: group.collector }),
            rows: group.rows,
          }))
        : [{ key: sort, label: t(`sort.${sort}`), rows: sortEvidence(kept, sort, meta) }];
  const selectedItem = view.evidence.find((item) => item.rule_id === selected) ?? null;
  const fileBase = data.links?.commit ? `${data.links.repository}/blob/${data.links.commit}` : null;
  const treeBase = data.links?.commit ? `${data.links.repository}/tree/${data.links.commit}` : null;

  return (
    <div className="page-stack">
      {view.roblox_tools && <RobloxToolsPanel tools={view.roblox_tools} />}

      <ReportSummary listed={view.listed} filter={state} onFilter={setState} />
      <ScopeNotes data={data} />

      <div className="finder panel">
        <label className="search">
          {t("finder.search")}
          <input
            type="search"
            value={filters.search}
            placeholder={t("finder.search_placeholder")}
            onChange={(event) =>
              setFilters((current) => ({ ...current, search: event.target.value }))
            }
          />
        </label>
        <label>
          {t("common:ui.evidence.state")}
          <select
            value={state ?? ""}
            onChange={(event) => setState((event.target.value || null) as StateFilter | null)}
          >
            <option value="">{t("common:ui.all")}</option>
            <option value="found">{t("summary.found")}</option>
            <option value="unmeasured">{t("summary.unmeasured")}</option>
            <option value="not_found">{t("summary.not_found")}</option>
          </select>
        </label>
        {hasMeta && (
          <label>
            {t("finder.level")}
            <select
              value={filters.level}
              onChange={(event) =>
                setFilters((current) => ({
                  ...current,
                  level: event.target.value as Filters["level"],
                }))
              }
            >
              <option value="all">{t("finder.level_all")}</option>
              <option value="flag">{t("common:level.flag")}</option>
              <option value="warn">{t("common:level.warn")}</option>
              <option value="info">{t("common:level.info")}</option>
            </select>
          </label>
        )}
        {hasMeta && (
          <label>
            {t("common:ui.evidence.category")}
            <select
              value={filters.category ?? ""}
              onChange={(event) =>
                setFilters((current) => ({ ...current, category: event.target.value || null }))
              }
            >
              <option value="">{t("common:ui.all")}</option>
              {CATEGORY_ORDER.map((category) => (
                <option key={category} value={category}>
                  {t(`category.${category}`)}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>
          {t("finder.sort")}
          <select value={sort} onChange={(event) => setSort(event.target.value as SortOrder)}>
            <option value="category">{t("sort.category")}</option>
            <option value="severity">{t("sort.severity")}</option>
            <option value="time">{t("sort.time")}</option>
          </select>
        </label>
        {(filters.search || state || filters.category || filters.level !== "all") && (
          <button
            type="button"
            className="disclosure"
            onClick={() => {
              setFilters(NO_FILTERS);
              setState(null);
            }}
          >
            {t("toolbar.clear")}
          </button>
        )}
        <span className="small muted aside">
          {t("common:ui.evidence.shown", { shown: kept.length, total: view.evidence.length })}
        </span>
      </div>

      <div className={selectedItem ? "split" : undefined}>
        <section className="panel" aria-labelledby="evidence-title">
          <h3 id="evidence-title" className="visually-hidden">
            {t("common:ui.nav.evidence")}
          </h3>
          {view.evidence.length === 0 && <Empty title={t("empty")} />}
          {/* A count of 0 is still a filter; choosing it says so rather than showing nothing. */}
          {view.evidence.length > 0 && kept.length === 0 && (
            <Empty title={t("toolbar.filtered_empty")} />
          )}
          {kept.length > 0 && (
            <div className="table-wrap">
              <table className={`evidence-table ${selectedItem ? "with-details" : ""}`}>
                <thead>
                  <tr>
                    <th scope="col">{t("common:ui.evidence.state")}</th>
                    <th scope="col">{t("finder.level")}</th>
                    <th scope="col">{t("check")}</th>
                    <th scope="col">{t("common:ui.evidence.source")}</th>
                    <th scope="col">{t("common:ui.evidence.first_time")}</th>
                  </tr>
                </thead>
                {groups.map((group) => (
                  <tbody key={group.key}>
                    <tr className="group-title">
                      <td colSpan={5}>
                        {group.label} · {group.rows.length}
                      </td>
                    </tr>
                    {group.rows.map((item) => {
                      const level = meta[item.rule_id]?.level;
                      const at = firstTime.get(item.rule_id);
                      return (
                        <tr
                          key={item.rule_id}
                          className={selected === item.rule_id ? "selected" : ""}
                        >
                          <td>
                            <Badge
                              {...EVIDENCE_LOOK[item.state]}
                              label={t(`state.${stateKey(item)}`)}
                            />
                          </td>
                          <td>
                            {item.state === "found" && level ? (
                              <Badge {...LEVEL_LOOK[level]} label={t(`common:level.${level}`)} />
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </td>
                          <td className="title-cell">
                            <button
                              type="button"
                              className="row-title"
                              aria-expanded={selected === item.rule_id}
                              onClick={() =>
                                setSelected(selected === item.rule_id ? null : item.rule_id)
                              }
                            >
                              {texts[item.rule_id]?.title ?? item.rule_id}
                            </button>
                          </td>
                          <td className="small">
                            {t(`collector.${item.collector}`, { defaultValue: item.collector })}
                          </td>
                          <td>
                            {at ? (
                              <TimeValue value={at} compact />
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                ))}
              </table>
            </div>
          )}
        </section>
        {selectedItem && (
          <EvidenceDetails
            item={selectedItem}
            text={texts[selectedItem.rule_id]}
            meta={meta[selectedItem.rule_id]}
            band={view.row_bands?.[selectedItem.rule_id]}
            timeFields={timeFields}
            fileBase={fileBase}
            treeBase={treeBase}
            linksKnown={data.links !== null}
            official={view.header.provenance.official}
            onClose={() => setSelected(null)}
          />
        )}
      </div>

      {/* Apart from the evidence, in both modes: what the program itself left (ADR 0010). */}
      {view.own_traces.length > 0 && (
        <section className="panel own-traces" aria-labelledby="own-traces-title">
          <h3 id="own-traces-title">{t("own_traces.title")}</h3>
          <details>
            <summary className="muted">{t("own_traces.note")}</summary>
            <ObservationList
              rows={view.own_traces.map((entry) => entry.observation)}
              timeFields={timeFields}
            />
          </details>
        </section>
      )}

      {/* What the collectors saw that no rule matched (ADR 0014). */}
      {view.unmatched.length > 0 && (
        <section className="panel unmatched" aria-labelledby="unmatched-title">
          <h3 id="unmatched-title">{t("unmatched.title")}</h3>
          <details>
            <summary className="muted">{t("unmatched.note")}</summary>
            <ObservationList
              rows={view.unmatched.flatMap((group) => group.observations)}
              timeFields={timeFields}
            />
          </details>
        </section>
      )}
    </div>
  );
}

/** Observations a page at a time, each with its collector and its fields; times are typed. */
function ObservationList({ rows, timeFields }: { rows: Observation[]; timeFields: Set<string> }) {
  const { t } = useTranslation("report");
  const paged = usePage(rows, 50);
  return (
    <div className="page-stack">
      <ul className="observations">
        {withKeys(paged.rows, (o) => `${o.collector}:${JSON.stringify(o.fields)}`).map(
          ([key, observation]) => (
            <li key={key}>
              <span className="muted">
                ({t(`collector.${observation.collector}`, { defaultValue: observation.collector })})
              </span>
              <div className="detail">{fieldsOf(observation)}</div>
              <details>
                <summary className="small">{t("common:ui.evidence.fields")}</summary>
                <ObservationCard observation={observation} timeFields={timeFields} />
              </details>
            </li>
          ),
        )}
      </ul>
      <Pager {...paged} />
    </div>
  );
}

/** One observation as a line of `field=value`. */
function fieldsOf(observation: Observation): string {
  return Object.entries(observation.fields)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(", ");
}
