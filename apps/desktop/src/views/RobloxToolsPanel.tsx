// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The Roblox tool correlation (B.O.P.E, ADR 0123): one row per tool with its status and the
// independent sources behind it, the traces each row stands on, and which sources could be read.
// It only arranges what the core computed; it decides nothing.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Observation, RobloxTools } from "../types";
import { Badge, STATUS_LOOK } from "../ui/Badge";
import { TimeValue } from "../ui/TimeValue";

interface Props {
  tools: RobloxTools;
}

const SOURCE_CLASS: Record<string, string> = {
  measured: "ok",
  not_measured: "na",
  not_applicable: "na",
  error: "warn",
};

function text(o: Observation, field: string): string {
  const value = o.fields[field];
  return typeof value === "string"
    ? value
    : value === undefined || value === null
      ? ""
      : String(value);
}

function flag(o: Observation, field: string): boolean {
  return o.fields[field] === true;
}

export function RobloxToolsPanel({ tools }: Props) {
  const { t } = useTranslation("report");
  const [open, setOpen] = useState<string | null>(null);
  const classes = (o: Observation) =>
    text(o, "classes")
      .split(", ")
      .filter((c) => c.length > 0)
      .map((c) => t(`tools.class.${c}`, { defaultValue: c }));

  return (
    <section className="roblox-tools panel" aria-labelledby="roblox-tools-title">
      <h3 id="roblox-tools-title">{t("tools.title")}</h3>
      <p className="muted small">{t("tools.intro")}</p>

      {tools.tools.length === 0 ? (
        <p>{t("tools.none")}</p>
      ) : (
        <div className="table-wrap">
          <table className="tools-table">
            <thead>
              <tr>
                <th>{t("tools.col_tool")}</th>
                <th>{t("tools.col_status")}</th>
                <th>{t("tools.col_sources")}</th>
                <th>{t("tools.col_evidence")}</th>
                <th>{t("tools.col_times")}</th>
              </tr>
            </thead>
            <tbody>
              {tools.tools.map((row) => {
                const id = text(row, "tool_id");
                const status = text(row, "status") || "info";
                const hits = tools.hits.filter((h) => text(h, "tool_id") === id);
                const first = text(row, "first_seen");
                return (
                  <tr key={id} className={`tool tool-${status}`}>
                    <td>
                      <strong>{text(row, "display")}</strong>
                      <div className="small muted">
                        {flag(row, "common_legitimate") && <span>{t("tools.legit")} · </span>}
                        {flag(row, "missing_now") && <span>{t("tools.missing")} · </span>}
                        {flag(row, "deleted") && <span>{t("tools.deleted")}</span>}
                      </div>
                      {hits.length > 0 && (
                        <button
                          type="button"
                          className="link small"
                          aria-expanded={open === id}
                          onClick={() => setOpen(open === id ? null : id)}
                        >
                          {open === id
                            ? t("tools.hide_hits")
                            : t("tools.show_hits", { count: hits.length })}
                        </button>
                      )}
                      {open === id && (
                        <ul className="hits small">
                          {hits.map((h) => (
                            <li
                              key={`${text(h, "source")}|${text(h, "path") || text(h, "name")}|${text(h, "time")}`}
                            >
                              {text(h, "time") ? (
                                <TimeValue value={text(h, "time")} compact />
                              ) : (
                                <code>—</code>
                              )}{" "}
                              {text(h, "source")} ·{" "}
                              {t(`tools.class.${text(h, "evidence_class")}`, {
                                defaultValue: text(h, "evidence_class"),
                              })}{" "}
                              · <span className="path">{text(h, "path") || text(h, "name")}</span>
                              {h.fields.exists === true && <> · {t("tools.hit_exists")}</>}
                              {h.fields.exists === false && <> · {t("tools.hit_missing")}</>}
                              {text(h, "matched_on") === "parent_folder" && (
                                <> · {t("tools.parent_folder")}</>
                              )}
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td>
                      <Badge
                        {...(STATUS_LOOK[status as keyof typeof STATUS_LOOK] ?? STATUS_LOOK.info)}
                        label={t(`tools.status.${status}`)}
                        title={t(`tools.status_note.${status}`)}
                      />
                    </td>
                    <td>
                      {text(row, "families_count")}
                      <div className="small muted">{text(row, "families")}</div>
                    </td>
                    <td className="small">{classes(row).join("; ")}</td>
                    <td className="small">
                      {first ? (
                        <>
                          <TimeValue value={first} kind="first_seen" compact />
                          {text(row, "last_seen") && text(row, "last_seen") !== first && (
                            <div>
                              <TimeValue value={text(row, "last_seen")} kind="last_seen" compact />
                            </div>
                          )}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {tools.sources.length > 0 && (
        <details className="tool-sources">
          <summary>{t("tools.sources_title")}</summary>
          <ul className="source-list">
            {tools.sources.map((s) => {
              const state = text(s, "state");
              return (
                <li key={text(s, "source")}>
                  <span className={`chip chip-${SOURCE_CLASS[state] ?? "na"}`}>
                    {t(`tools.source_state.${state}`, { defaultValue: state })}
                  </span>{" "}
                  {t(`collector.${text(s, "source")}`, { defaultValue: text(s, "source") })}
                  {text(s, "reason") && <span className="muted small"> ({text(s, "reason")})</span>}
                </li>
              );
            })}
          </ul>
        </details>
      )}
    </section>
  );
}
