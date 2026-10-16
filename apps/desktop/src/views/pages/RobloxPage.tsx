// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The Roblox forensic page (B.O.P.E, ADR 0133–0137): the FastFlag reference copy and its update,
// the monitoring mode, and — after a scan — what the forensic collectors read, each section saying
// first whether its read finished. Every row is evidence with its limits; nothing here is a verdict,
// and no section claims to be complete while its collector says it stopped early.

import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  clearMonitor,
  fflagReferenceStatus,
  fflagReferenceSync,
  monitorStatus,
  startMonitor,
  stopMonitor,
} from "../../api";
import { fieldText } from "../../reportData";
import type {
  MonitorEvent,
  MonitorStatus,
  Observation,
  ReferenceStatus,
  ReportView,
  SyncResult,
} from "../../types";
import { Badge } from "../../ui/Badge";
import { Icon } from "../../ui/Icon";
import { Pager, usePage } from "../../ui/Paging";
import { Empty } from "../../ui/States";
import { TimeValue } from "../../ui/TimeValue";

/** Whether the window checks for a newer reference on its own; the person can turn it off. */
export const AUTO_SYNC_KEY = "bope.fflagAutoSync";

export function autoSyncEnabled(): boolean {
  try {
    return window.localStorage.getItem(AUTO_SYNC_KEY) !== "off";
  } catch {
    return true;
  }
}

function setAutoSync(on: boolean) {
  try {
    window.localStorage.setItem(AUTO_SYNC_KEY, on ? "on" : "off");
  } catch {
    // The choice then lasts only for this window.
  }
}

const MONITOR_POLL_MS = 1000;

export function RobloxPage({ view }: { view: ReportView | null }) {
  const { t } = useTranslation();
  return (
    <div className="page-stack">
      <p className="note">{t("ui.roblox.intro")}</p>
      <ReferencePanel />
      <MonitorPanel />
      {view ? (
        <ForensicSections view={view} />
      ) : (
        <Empty title={t("ui.roblox.no_report")}>
          <p>{t("ui.roblox.no_report_detail")}</p>
        </Empty>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// The FastFlag reference copy.

function ReferencePanel() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ReferenceStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [last, setLast] = useState<SyncResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [auto, setAuto] = useState(autoSyncEnabled);

  useEffect(() => {
    void fflagReferenceStatus()
      .then(setStatus)
      .catch(() => {});
  }, []);

  const update = () => {
    setBusy(true);
    setError(null);
    void fflagReferenceSync(false)
      .then((result) => {
        setLast(result);
        if (result.status) {
          setStatus(result.status);
        }
      })
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setBusy(false));
  };

  const m = status?.metadata;
  return (
    <section className="panel" aria-labelledby="reference-title">
      <div className="panel-head">
        <h3 id="reference-title">{t("ui.roblox.reference.title")}</h3>
        <button type="button" className="aside" disabled={busy} onClick={update}>
          <Icon name="clock" />
          {busy ? t("ui.roblox.reference.updating") : t("ui.roblox.reference.update")}
        </button>
      </div>
      <p className="small muted">{t("ui.roblox.reference.what")}</p>
      {status === null ? (
        <p className="small muted">{t("ui.roblox.reference.no_folder")}</p>
      ) : (
        <dl className="facts">
          <dt>{t("ui.roblox.reference.state")}</dt>
          <dd>
            {status.available ? (
              <Badge tone="info" shape="circle" label={t("ui.roblox.reference.available")} />
            ) : (
              <Badge
                tone="unmeasured"
                shape="dashed"
                label={
                  status.unavailable_reason === "never_synchronised"
                    ? t("ui.roblox.reference.never")
                    : t("ui.roblox.reference.damaged")
                }
              />
            )}
          </dd>
          {m && (
            <>
              <dt>{t("ui.roblox.reference.revision")}</dt>
              <dd>
                <code>{m.revision}</code> ({t(`ui.roblox.reference.kind.${m.revision_kind}`)})
              </dd>
              {m.commit_date && (
                <>
                  <dt>{t("ui.roblox.reference.commit_date")}</dt>
                  <dd>
                    <TimeValue value={m.commit_date} />
                  </dd>
                </>
              )}
              <dt>{t("ui.roblox.reference.fetched_at")}</dt>
              <dd>
                <TimeValue value={m.fetched_at} />
              </dd>
              <dt>{t("ui.roblox.reference.entries")}</dt>
              <dd>{m.entries}</dd>
              <dt>{t("ui.roblox.reference.client_version")}</dt>
              <dd>{status.reference_client_version ?? t("ui.roblox.reference.not_stated")}</dd>
              <dt>{t("ui.roblox.reference.source")}</dt>
              <dd>
                <code>{m.source_url}</code>
              </dd>
            </>
          )}
          {status.state.last_attempt_at && (
            <>
              <dt>{t("ui.roblox.reference.last_attempt")}</dt>
              <dd>
                <TimeValue value={status.state.last_attempt_at} />{" "}
                {status.state.last_outcome &&
                  t(`ui.roblox.reference.outcome.${status.state.last_outcome}`)}
                {status.state.last_detail && (
                  <span className="small muted"> — {status.state.last_detail}</span>
                )}
              </dd>
            </>
          )}
          <dt>{t("ui.roblox.reference.folder")}</dt>
          <dd>
            <code>{status.folder}</code>
          </dd>
        </dl>
      )}
      {last && (
        <p className="small" role="status">
          {t(`ui.roblox.reference.outcome.${last.outcome}`)} — {last.detail}
        </p>
      )}
      {error && (
        <p className="note error" role="alert">
          {error}
        </p>
      )}
      <label className="small">
        <input
          type="checkbox"
          checked={auto}
          onChange={(e) => {
            setAuto(e.target.checked);
            setAutoSync(e.target.checked);
          }}
        />{" "}
        {t("ui.roblox.reference.auto")}
      </label>
      <p className="small muted">{t("ui.roblox.reference.privacy")}</p>
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
// The monitoring mode.

function MonitorPanel() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [interval, setIntervalSeconds] = useState(30);

  const refresh = useCallback(() => {
    void monitorStatus()
      .then(setStatus)
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, MONITOR_POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const running = status?.running === true;
  return (
    <section className="panel" aria-labelledby="monitor-title" aria-busy={running}>
      <div className="panel-head">
        <h3 id="monitor-title">{t("ui.roblox.monitor.title")}</h3>
        {running ? (
          <button
            type="button"
            className="danger aside"
            onClick={() => void stopMonitor().then(refresh)}
          >
            <Icon name="stop" />
            {t("ui.roblox.monitor.stop")}
          </button>
        ) : (
          <span className="aside">
            <select
              aria-label={t("ui.roblox.monitor.interval")}
              value={interval}
              onChange={(e) => setIntervalSeconds(Number(e.target.value))}
            >
              {[10, 30, 60, 120].map((s) => (
                <option key={s} value={s}>
                  {t("ui.roblox.monitor.every", { seconds: s })}
                </option>
              ))}
            </select>{" "}
            <button type="button" onClick={() => void startMonitor(interval).then(refresh)}>
              <Icon name="clock" />
              {t("ui.roblox.monitor.start")}
            </button>
          </span>
        )}
      </div>
      <p className="small muted">{t("ui.roblox.monitor.what")}</p>
      {running && (
        <p className="note" role="status">
          <Icon name="info" /> {t("ui.roblox.monitor.running_notice")}
        </p>
      )}
      {status?.started_at && (
        <>
          <dl className="facts">
            <dt>{t("ui.roblox.monitor.started")}</dt>
            <dd>
              <TimeValue value={status.started_at} />
            </dd>
            <dt>{t("ui.roblox.monitor.samples")}</dt>
            <dd>
              {status.samples}
              {status.partial_samples > 0 &&
                ` (${t("ui.roblox.monitor.partial", { count: status.partial_samples })})`}
            </dd>
            {status.last_sample_at && (
              <>
                <dt>{t("ui.roblox.monitor.last_sample")}</dt>
                <dd>
                  <TimeValue value={status.last_sample_at} />
                </dd>
              </>
            )}
            <dt>{t("ui.roblox.monitor.interval")}</dt>
            <dd>{t("ui.roblox.monitor.every", { seconds: status.interval_seconds })}</dd>
          </dl>
          <MonitorEvents events={status.events} dropped={status.events_dropped} />
          {!running && (
            <button
              type="button"
              className="small"
              onClick={() => void clearMonitor().then(refresh)}
            >
              {t("ui.roblox.monitor.clear")}
            </button>
          )}
        </>
      )}
    </section>
  );
}

function MonitorEvents({ events, dropped }: { events: MonitorEvent[]; dropped: number }) {
  const { t } = useTranslation();
  const newest = [...events].reverse();
  const paging = usePage(newest, 25);
  if (events.length === 0) {
    return <p className="small muted">{t("ui.roblox.monitor.no_events")}</p>;
  }
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t("ui.roblox.col.when")}</th>
              <th scope="col">{t("ui.roblox.col.event")}</th>
              <th scope="col">{t("ui.roblox.col.pid")}</th>
              <th scope="col">{t("ui.roblox.col.subject")}</th>
              <th scope="col">{t("ui.roblox.col.change")}</th>
            </tr>
          </thead>
          <tbody>
            {paging.rows.map((e) => (
              <tr key={`${e.at}-${e.event}-${e.pid}-${e.subject}-${e.source}`}>
                <td>
                  <TimeValue value={e.at} compact />
                  {e.since && (
                    <span className="small muted">
                      {" "}
                      ({t("ui.roblox.monitor.since")} <TimeValue value={e.since} compact />)
                    </span>
                  )}
                </td>
                <td>{t(`ui.roblox.event.${e.event}`, { defaultValue: e.event })}</td>
                <td>{e.pid ?? "—"}</td>
                <td>
                  <code>{e.subject}</code>
                  {e.source && <span className="small muted"> [{e.source}]</span>}
                </td>
                <td>
                  {e.before !== null && e.after !== null ? `${e.before} → ${e.after}` : "—"}
                  {e.first_seen_at && (
                    <span className="small muted">
                      {" "}
                      ({t("ui.roblox.monitor.held_earlier")}{" "}
                      <TimeValue value={e.first_seen_at} compact />)
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager {...paging} />
      {dropped > 0 && (
        <p className="small muted">{t("ui.roblox.monitor.dropped", { count: dropped })}</p>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------------------------
// What the scan read.

function scopeOf(rows: Observation[], scope: string): Observation[] {
  return rows.filter((o) => o.fields.scope === scope);
}

/** The gap a collector reported, from the view's list of sources that were not read. */
function gapOf(view: ReportView, collector: string): string | null {
  const gap = view.timeline.unmeasured.find((u) => u.collector === collector && !u.place);
  return gap ? gap.reason : null;
}

/** "This read did not finish" before any row, so a section is never read as complete when it is not. */
function Completeness({
  view,
  collector,
  summary,
}: {
  view: ReportView;
  collector: string;
  summary?: Observation;
}) {
  const { t } = useTranslation();
  const gap = gapOf(view, collector);
  if (gap) {
    return (
      <p className="scope">
        {t("ui.roblox.not_read", { reason: t(`report:reason.${gap}`, { defaultValue: gap }) })}
      </p>
    );
  }
  if (summary && summary.fields.complete === false) {
    return (
      <p className="scope">
        {t("ui.roblox.incomplete", {
          by: fieldText(summary.fields, "stopped_by") || "?",
        })}
      </p>
    );
  }
  return null;
}

interface Column {
  key: string;
  label: string;
  time?: boolean;
  code?: boolean;
}

function Rows({ rows, columns, empty }: { rows: Observation[]; columns: Column[]; empty: string }) {
  const paging = usePage(rows, 20);
  if (rows.length === 0) {
    return <p className="small muted">{empty}</p>;
  }
  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} scope="col">
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paging.rows.map((o) => (
              <tr key={JSON.stringify(o.fields)}>
                {columns.map((c) => {
                  const text = fieldText(o.fields, c.key);
                  let cell: ReactNode = text || "—";
                  if (text && c.time) {
                    cell = <TimeValue value={text} compact />;
                  } else if (text && c.code) {
                    cell = <code>{text}</code>;
                  }
                  return <td key={c.key}>{cell}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager {...paging} />
    </>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section className="panel" aria-labelledby={id}>
      <h3 id={id}>{title}</h3>
      {children}
    </section>
  );
}

function ForensicSections({ view }: { view: ReportView }) {
  const { t } = useTranslation();
  const f = view.forensics;
  if (!f) {
    return (
      <Empty title={t("ui.roblox.no_forensics")}>
        <p>{t("ui.roblox.no_forensics_detail")}</p>
      </Empty>
    );
  }
  const c = (key: string) => t(`ui.roblox.col.${key}`);
  const memory = f.roblox_memory;
  const flags = f.roblox_flags;
  const players = scopeOf(memory, "player");
  const reference = scopeOf(flags, "reference")[0];
  return (
    <>
      <Section id="roblox-players" title={t("ui.roblox.players.title")}>
        <Completeness
          view={view}
          collector="roblox_memory"
          summary={scopeOf(memory, "players")[0]}
        />
        <p className="small muted">{t("ui.roblox.players.note")}</p>
        <Rows
          rows={players}
          empty={t("ui.roblox.players.none")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "path", label: c("path"), code: true },
            { key: "identity_confidence", label: c("identity") },
            { key: "identity_checks", label: c("checks") },
            { key: "file_version", label: c("version") },
            { key: "machine", label: c("arch") },
            { key: "started_at", label: c("started"), time: true },
            { key: "sha256", label: "SHA-256", code: true },
            { key: "access", label: c("access") },
          ]}
        />
        {scopeOf(memory, "summary").map((s) => (
          <p key={fieldText(s.fields, "pid")} className="small muted">
            {t("ui.roblox.players.summary", {
              pid: fieldText(s.fields, "pid"),
              scanned: fieldText(s.fields, "bytes_scanned"),
              compared: fieldText(s.fields, "modules_compared"),
              complete: s.fields.complete === true ? t("ui.roblox.yes") : t("ui.roblox.no"),
            })}
          </p>
        ))}
      </Section>

      <Section id="roblox-code" title={t("ui.roblox.code.title")}>
        <p className="small muted">{t("ui.roblox.code.note")}</p>
        <h4>{t("ui.roblox.code.hooks")}</h4>
        <Rows
          rows={scopeOf(memory, "hook")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "module", label: c("module"), code: true },
            { key: "function", label: c("function") },
            { key: "hook_kind", label: c("kind") },
            { key: "target", label: c("target"), code: true },
            { key: "target_module", label: c("target_module") },
            { key: "target_class", label: c("class") },
            { key: "expected_runtime_change", label: c("expected") },
          ]}
        />
        <h4>{t("ui.roblox.code.changes")}</h4>
        <Rows
          rows={scopeOf(memory, "code_change")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "module", label: c("module"), code: true },
            { key: "bytes_compared", label: c("compared") },
            { key: "bytes_differing", label: c("differing") },
            { key: "not_compared", label: c("not_compared") },
            { key: "ranges", label: c("ranges"), code: true },
            { key: "expected_runtime_change", label: c("expected") },
          ]}
        />
        <h4>{t("ui.roblox.code.regions")}</h4>
        <Rows
          rows={scopeOf(memory, "region")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "finding", label: c("finding") },
            { key: "address", label: c("address"), code: true },
            { key: "size", label: c("size") },
            { key: "permissions", label: c("permissions") },
            { key: "mapped_file", label: c("mapped_file"), code: true },
          ]}
        />
        <h4>{t("ui.roblox.code.modules")}</h4>
        <Rows
          rows={scopeOf(memory, "module")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "path", label: c("path"), code: true },
            { key: "integrity_class", label: c("class") },
            { key: "integrity_reasons", label: c("reasons") },
            { key: "signer", label: c("signer") },
            { key: "limitations", label: c("limitations") },
          ]}
        />
      </Section>

      <Section id="roblox-strings" title={t("ui.roblox.strings.title")}>
        <p className="small muted">{t("ui.roblox.strings.note")}</p>
        <Rows
          rows={scopeOf(memory, "string")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "category", label: c("category") },
            { key: "text", label: c("text"), code: true },
            { key: "address", label: c("address"), code: true },
            { key: "region_kind", label: c("region") },
            { key: "permissions", label: c("permissions") },
            { key: "encoding", label: c("encoding") },
            { key: "length", label: c("length") },
            { key: "owner_module", label: c("module") },
          ]}
        />
      </Section>

      <Section id="roblox-flags" title={t("ui.roblox.flags.title")}>
        <Completeness view={view} collector="roblox_flags" />
        {reference && (
          <dl className="facts">
            <dt>{t("ui.roblox.flags.reference")}</dt>
            <dd>
              {reference.fields.available === true
                ? `${fieldText(reference.fields, "reference_revision")} · ${fieldText(reference.fields, "entries")} ${t("ui.roblox.flags.entries")}`
                : t("ui.roblox.flags.no_reference")}
            </dd>
            <dt>{t("ui.roblox.flags.correspondence")}</dt>
            <dd>
              {t(`ui.roblox.flags.match.${fieldText(reference.fields, "version_correspondence")}`, {
                defaultValue: fieldText(reference.fields, "version_correspondence"),
              })}
              {fieldText(reference.fields, "client_version") &&
                ` · ${t("ui.roblox.flags.client")} ${fieldText(reference.fields, "client_version")}`}
            </dd>
          </dl>
        )}
        <p className="small muted">{t("ui.roblox.flags.note")}</p>
        <h4>{t("ui.roblox.flags.files")}</h4>
        <Rows
          rows={scopeOf(flags, "value")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "flag", label: c("flag"), code: true },
            { key: "reference_value", label: c("reference_value") },
            { key: "value", label: c("observed_value") },
            { key: "comparison", label: c("divergence") },
            { key: "flag_kind", label: c("kind") },
            { key: "path", label: c("observed_source"), code: true },
            { key: "active_version", label: c("active") },
            { key: "reference_revision", label: c("revision"), code: true },
          ]}
        />
        <h4>{t("ui.roblox.flags.memory")}</h4>
        <Rows
          rows={scopeOf(memory, "flag_value")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "flag", label: c("flag"), code: true },
            { key: "reference_value", label: c("reference_value") },
            { key: "value", label: c("observed_value") },
            { key: "comparison", label: c("divergence") },
            { key: "address", label: c("address"), code: true },
            { key: "value_source", label: c("observed_source") },
          ]}
        />
        <h4>{t("ui.roblox.flags.identifiers")}</h4>
        <p className="small muted">{t("ui.roblox.flags.identifiers_note")}</p>
        <Rows
          rows={scopeOf(memory, "identifier")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "pid", label: c("pid") },
            { key: "flag", label: c("flag"), code: true },
            { key: "address", label: c("address"), code: true },
            { key: "pointers", label: c("pointers") },
            { key: "value_interpretation", label: c("interpretation") },
          ]}
        />
      </Section>

      <Section id="roblox-history" title={t("ui.roblox.history.title")}>
        <p className="small muted">{t("ui.roblox.history.note")}</p>
        <h4>{t("ui.roblox.history.copies")}</h4>
        <Rows
          rows={scopeOf(flags, "change")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "flag", label: c("flag"), code: true },
            { key: "finding", label: c("finding") },
            { key: "earlier_value", label: c("earlier_value") },
            { key: "earlier_modified", label: c("earlier_modified"), time: true },
            { key: "earlier_path", label: c("earlier_path"), code: true },
            { key: "current_value", label: c("current_value") },
            { key: "modified", label: c("current_modified"), time: true },
          ]}
        />
        <h4>{t("ui.roblox.history.dumps")}</h4>
        <Rows
          rows={scopeOf(flags, "dump_value")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "written_at", label: c("when"), time: true },
            { key: "flag", label: c("flag"), code: true },
            { key: "value", label: c("observed_value") },
            { key: "reference_value", label: c("reference_value") },
            { key: "comparison", label: c("divergence") },
            { key: "path", label: c("path"), code: true },
          ]}
        />
        <h4>{t("ui.roblox.history.monitor")}</h4>
        <Completeness view={view} collector="roblox_monitor" />
        <Rows
          rows={scopeOf(f.roblox_monitor, "event")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "at", label: c("when"), time: true },
            { key: "event", label: c("event") },
            { key: "pid", label: c("pid") },
            { key: "subject", label: c("subject"), code: true },
            { key: "before", label: c("earlier_value") },
            { key: "after", label: c("current_value") },
            { key: "first_seen_at", label: c("first_seen"), time: true },
          ]}
        />
      </Section>

      <Section id="processes-memory" title={t("ui.roblox.processes.title")}>
        <Completeness
          view={view}
          collector="process_modules"
          summary={scopeOf(f.process_modules, "summary")[0]}
        />
        <Rows
          rows={f.process_modules.filter((o) =>
            ["module", "allocation", "unlisted_image"].includes(fieldText(o.fields, "scope")),
          )}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "scope", label: c("kind") },
            { key: "path", label: c("path"), code: true },
            { key: "process_name", label: c("process") },
            { key: "loaded_by", label: c("process") },
            { key: "integrity_class", label: c("class") },
            { key: "integrity_reasons", label: c("reasons") },
            { key: "address", label: c("address"), code: true },
          ]}
        />
      </Section>

      <Section id="file-inventory" title={t("ui.roblox.inventory.title")}>
        <Completeness
          view={view}
          collector="file_inventory"
          summary={scopeOf(f.file_inventory, "summary")[0]}
        />
        <InventorySummary rows={f.file_inventory} />
        <Rows
          rows={scopeOf(f.file_inventory, "file")}
          empty={t("ui.roblox.none_seen")}
          columns={[
            { key: "path", label: c("path"), code: true },
            { key: "integrity_class", label: c("class") },
            { key: "integrity_reasons", label: c("reasons") },
            { key: "sha256", label: "SHA-256", code: true },
            { key: "modified", label: c("current_modified"), time: true },
            { key: "limitations", label: c("limitations") },
          ]}
        />
      </Section>
    </>
  );
}

function InventorySummary({ rows }: { rows: Observation[] }) {
  const { t } = useTranslation();
  const summary = scopeOf(rows, "summary")[0];
  if (!summary) {
    return null;
  }
  const keys = [
    "files_listed",
    "directories_listed",
    "directories_inaccessible",
    "links_skipped",
    "depth_limited",
    "images_found",
    "images_assessed",
    "images_counted_only",
    "images_not_assessed",
    "disguised_images",
    "class_not_verified",
    "class_inconclusive",
    "rows_withheld",
  ];
  return (
    <dl className="facts">
      {keys
        .filter((k) => summary.fields[k] !== undefined)
        .map((k) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{t(`ui.roblox.inventory.${k}`, { defaultValue: k })}</dt>
            <dd>{fieldText(summary.fields, k)}</dd>
          </div>
        ))}
    </dl>
  );
}
