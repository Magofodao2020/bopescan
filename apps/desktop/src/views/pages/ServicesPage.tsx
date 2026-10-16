// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Five Windows services (B.O.P.E, ADR 0130): what the Service Control Manager said at the moment it
// was asked, apart from what the System log remembers. No state is coloured as a finding: a stopped
// or disabled service has ordinary causes, and this page says what it may mean for other sources,
// never what it says about the person.

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { fieldText } from "../../reportData";
import { compareInstants } from "../../time";
import type { Observation, ReportView, UnmeasuredSource } from "../../types";
import { Badge, type Shape, type Tone } from "../../ui/Badge";
import { Pager, usePage } from "../../ui/Paging";
import { Empty } from "../../ui/States";
import { TimeValue } from "../../ui/TimeValue";

/** What each service is, and which other sources it feeds. */
export const SERVICE_ROLES: Record<string, string> = {
  PcaSvc: "pca",
  DiagTrack: "diagtrack",
  DPS: "dps",
  SysMain: "sysmain",
  EventLog: "eventlog",
};

const OTHER_LOOK: { tone: Tone; shape: Shape } = { tone: "neutral", shape: "dashed" };

const STATE_LOOK: Record<string, { tone: Tone; shape: Shape }> = {
  running: { tone: "info", shape: "circle" },
  stopped: { tone: "neutral", shape: "ring" },
  paused: { tone: "neutral", shape: "ring" },
  start_pending: { tone: "neutral", shape: "dashed" },
  stop_pending: { tone: "neutral", shape: "dashed" },
  continue_pending: { tone: "neutral", shape: "dashed" },
  pause_pending: { tone: "neutral", shape: "dashed" },
  other: { tone: "neutral", shape: "dashed" },
};

function gap(view: ReportView, place: string | undefined): UnmeasuredSource | undefined {
  return view.timeline.unmeasured.find(
    (source) => source.collector === "windows_service" && (source.place ?? undefined) === place,
  );
}

export function ServicesPage({ view }: { view: ReportView }) {
  const { t } = useTranslation();
  const rows = view.services ?? [];
  const current = rows.filter((o) => o.fields.scope === "current");
  const history = rows.filter((o) => o.fields.scope === "history" && o.fields.event !== "log_span");
  const span = rows.find((o) => o.fields.event === "log_span");
  const whole = gap(view, undefined);

  return (
    <div className="page-stack">
      <p className="note">{t("ui.services.intro")}</p>

      {whole && current.length === 0 && (
        <Empty title={t("ui.services.not_read")}>
          <p>{t(`report:reason.${whole.reason}`)}</p>
        </Empty>
      )}

      {current.length > 0 && (
        <CurrentTable rows={current} gapReason={gap(view, "current")?.reason} />
      )}

      {(history.length > 0 || span || gap(view, "history")) && (
        <HistoryPanel
          rows={history}
          span={span}
          reason={gap(view, "history")?.reason}
          services={current}
        />
      )}
    </div>
  );
}

function CurrentTable({ rows, gapReason }: { rows: Observation[]; gapReason?: string }) {
  const { t } = useTranslation();
  return (
    <section className="panel" aria-labelledby="services-current-title">
      <div className="panel-head">
        <h3 id="services-current-title">{t("ui.services.current_title")}</h3>
        <span className="small muted aside">{t("ui.services.source_scm")}</span>
      </div>
      {gapReason && (
        <p className="scope">
          {t("ui.services.partial", { reason: t(`report:reason.${gapReason}`) })}
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t("ui.services.col_service")}</th>
              <th scope="col">{t("ui.services.col_state")}</th>
              <th scope="col">{t("ui.services.col_start")}</th>
              <th scope="col">{t("ui.services.col_account")}</th>
              <th scope="col">{t("ui.services.col_pid")}</th>
              <th scope="col">{t("ui.services.col_collected")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((o) => (
              <ServiceRow key={fieldText(o.fields, "service")} row={o} />
            ))}
          </tbody>
        </table>
      </div>
      <details>
        <summary>{t("ui.services.paths")}</summary>
        <dl className="facts">
          {rows.map((o) => (
            <div key={fieldText(o.fields, "service")} style={{ display: "contents" }}>
              <dt>{fieldText(o.fields, "service")}</dt>
              <dd>
                {fieldText(o.fields, "binary_path") ? (
                  <code className="selectable">{fieldText(o.fields, "binary_path")}</code>
                ) : (
                  <span className="muted">{t("ui.services.not_reported")}</span>
                )}
              </dd>
            </div>
          ))}
        </dl>
      </details>
      <ul className="small muted">
        {rows.map((o) => {
          const name = fieldText(o.fields, "service");
          const role = SERVICE_ROLES[name];
          return role ? (
            <li key={name}>
              <strong>{name}</strong>: {t(`ui.services.role.${role}`)}
            </li>
          ) : null;
        })}
      </ul>
    </section>
  );
}

function ServiceRow({ row }: { row: Observation }) {
  const { t } = useTranslation();
  const f = row.fields;
  const name = fieldText(f, "service");
  const display = fieldText(f, "display_name");
  const query = fieldText(f, "query");
  const state = fieldText(f, "state");
  const config = fieldText(f, "config_query");
  return (
    <tr>
      <td>
        <strong>{display || name}</strong>
        <div className="small muted mono">{name}</div>
      </td>
      <td>
        {query === "ok" ? (
          <Badge
            {...(STATE_LOOK[state] ?? OTHER_LOOK)}
            label={t(`ui.services.state.${state}`, { defaultValue: state })}
          />
        ) : query === "not_installed" ? (
          <Badge tone="neutral" shape="ring" label={t("ui.services.query.not_installed")} />
        ) : (
          <Badge
            tone="unmeasured"
            shape="dashed"
            label={t(`ui.services.query.${query}`, { defaultValue: query })}
          />
        )}
      </td>
      <td>
        {f.start_type !== undefined ? (
          <>
            {t(`ui.services.start.${fieldText(f, "start_type")}`, {
              defaultValue: fieldText(f, "start_type"),
            })}
            {f.disabled === true && (
              <div className="small muted">{t("ui.services.disabled_note")}</div>
            )}
          </>
        ) : query === "ok" ? (
          <span className="muted">
            {t(`ui.services.query.${config}`, { defaultValue: config || "—" })}
          </span>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td className="small">{fieldText(f, "account") || <span className="muted">—</span>}</td>
      <td className="mono small">{fieldText(f, "pid") || <span className="muted">—</span>}</td>
      <td>
        {fieldText(f, "collected_at") ? (
          <TimeValue value={fieldText(f, "collected_at")} kind="collected" certainty="exact" />
        ) : (
          <span className="muted">—</span>
        )}
      </td>
    </tr>
  );
}

function HistoryPanel({
  rows,
  span,
  reason,
  services,
}: {
  rows: Observation[];
  span: Observation | undefined;
  reason?: string;
  services: Observation[];
}) {
  const { t } = useTranslation();
  const [service, setService] = useState("");
  const [event, setEvent] = useState("");
  const sorted = useMemo(
    () =>
      [...rows]
        .filter((o) => service === "" || o.fields.service === service)
        .filter((o) => event === "" || o.fields.event === event)
        .sort(
          (a, b) =>
            compareInstants(fieldText(b.fields, "event_at"), fieldText(a.fields, "event_at")) ||
            Number(b.fields.record_id ?? 0) - Number(a.fields.record_id ?? 0),
        ),
    [rows, service, event],
  );
  const paged = usePage(sorted, 50);
  const names = [...new Set(services.map((o) => fieldText(o.fields, "service")))];
  return (
    <section className="panel" aria-labelledby="services-history-title">
      <div className="panel-head">
        <h3 id="services-history-title">{t("ui.services.history_title")}</h3>
        <span className="small muted aside">{t("ui.services.source_log")}</span>
      </div>
      <p className="small muted">{t("ui.services.history_intro")}</p>
      {reason && (
        <p className="scope">
          {t("ui.services.history_not_read", { reason: t(`report:reason.${reason}`) })}
        </p>
      )}
      {span && fieldText(span.fields, "log_first") && (
        <p className="small">
          {t("ui.services.span")} <TimeValue value={fieldText(span.fields, "log_first")} compact />{" "}
          → <TimeValue value={fieldText(span.fields, "log_last")} compact />
        </p>
      )}
      {!reason && rows.length === 0 && <Empty title={t("ui.services.history_none")} />}
      {rows.length > 0 && (
        <>
          <div className="filters">
            <label>
              {t("ui.services.col_service")}
              <select value={service} onChange={(e) => setService(e.target.value)}>
                <option value="">{t("ui.all")}</option>
                {names.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t("ui.services.col_event")}
              <select value={event} onChange={(e) => setEvent(e.target.value)}>
                <option value="">{t("ui.all")}</option>
                {["state_change", "start_type_change", "unexpected_end", "installed"].map(
                  (kind) => (
                    <option key={kind} value={kind}>
                      {t(`ui.services.event.${kind}`)}
                    </option>
                  ),
                )}
              </select>
            </label>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("ui.services.col_when")}</th>
                  <th scope="col">{t("ui.services.col_service")}</th>
                  <th scope="col">{t("ui.services.col_event")}</th>
                  <th scope="col">{t("ui.services.col_recorded")}</th>
                  <th scope="col">{t("ui.services.col_record")}</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((o) => (
                  <tr
                    key={`${fieldText(o.fields, "record_id")}:${fieldText(o.fields, "event_at")}`}
                  >
                    <td>
                      <TimeValue
                        value={fieldText(o.fields, "event_at")}
                        kind="service_event"
                        certainty="exact"
                      />
                    </td>
                    <td>
                      <span className="mono">{fieldText(o.fields, "service")}</span>
                      <div className="small muted">
                        {t(`ui.services.matched.${fieldText(o.fields, "matched_by")}`)}
                      </div>
                    </td>
                    <td>
                      {t(`ui.services.event.${fieldText(o.fields, "event")}`)}
                      {fieldText(o.fields, "state") && (
                        <div className="small">
                          → {t(`ui.services.state.${fieldText(o.fields, "state")}`)}
                        </div>
                      )}
                      {fieldText(o.fields, "start_type") && (
                        <div className="small">
                          → {t(`ui.services.start.${fieldText(o.fields, "start_type")}`)}
                        </div>
                      )}
                    </td>
                    <td className="small">
                      {[
                        fieldText(o.fields, "state_text"),
                        fieldText(o.fields, "start_type_text"),
                        fieldText(o.fields, "installed_image_path"),
                      ]
                        .filter(Boolean)
                        .map((value) => (
                          <div key={value}>
                            <code>{value}</code>
                          </div>
                        ))}
                    </td>
                    <td className="small mono">
                      {fieldText(o.fields, "event_id")} · #{fieldText(o.fields, "record_id")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager {...paged} />
        </>
      )}
    </section>
  );
}
