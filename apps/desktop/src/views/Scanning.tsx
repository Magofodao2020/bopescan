// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The scan as it happens (B.O.P.E, ADR 0115, ADR 0132): the module running now as Rust reports it,
// how many finished, were not read or are still to run, the time since the scan started, what each
// finished module found, and a way to stop. Everything shown comes from `scan_status`; the bar is the
// share of modules finished, never an estimate of time.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { cancelScan, scanStatus } from "../api";
import { formatDuration, parseInstant } from "../time";
import type { AppInfo, RuleMeta, RuleText, ScanStatus, ScanStep } from "../types";
import { Badge, LEVEL_LOOK } from "../ui/Badge";
import { Icon } from "../ui/Icon";

/** How often the window asks Rust where the scan is. */
export const POLL_MS = 400;

interface Props {
  info: AppInfo | null;
  meta: Record<string, RuleMeta>;
  texts: Record<string, RuleText>;
  onFinished: (status: ScanStatus) => void;
}

export function Scanning({ info, meta, texts, onFinished }: Props) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const finished = useRef(false);

  useEffect(() => {
    let alive = true;
    const tick = () => {
      setNow(Date.now());
      void scanStatus()
        .then((next) => {
          if (!alive) {
            return;
          }
          setStatus(next);
          if (
            !finished.current &&
            (next.state === "done" || next.state === "cancelled" || next.state === "failed")
          ) {
            finished.current = true;
            onFinished(next);
          }
        })
        .catch(() => {});
    };
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [onFinished]);

  const steps = status?.steps ?? [];
  const total = status?.total ?? info?.collectors.length ?? 0;
  const running = status?.state === "running";
  const started = status?.started_at ? parseInstant(status.started_at) : null;
  const elapsed = started ? Math.max(0, now - started.getTime()) : null;

  return (
    <section className="scanning" aria-labelledby="scanning-title" aria-busy={running}>
      <div className="panel">
        <div className="panel-head">
          <h3 id="scanning-title">{t("scan.title")}</h3>
          {running && (
            <button
              type="button"
              className="danger aside"
              disabled={cancelling || status?.cancel_requested === true}
              onClick={() => {
                setCancelling(true);
                void cancelScan();
              }}
            >
              <Icon name="stop" />
              {cancelling || status?.cancel_requested ? t("scan.cancelling") : t("scan.cancel")}
            </button>
          )}
        </div>
        <ScanProgress
          steps={steps}
          total={total}
          current={running ? (status?.current ?? null) : null}
          elapsed={elapsed}
          building={running && steps.length === total && total > 0}
        />
      </div>

      <div className="grid-2">
        <ModuleLog
          steps={steps}
          current={running ? (status?.current ?? null) : null}
          pending={pendingOf(info, steps, running ? (status?.current ?? null) : null)}
        />
        <LiveFindings steps={steps} meta={meta} texts={texts} />
      </div>
    </section>
  );
}

/** Ids of the modules still to run, in the order `app_info` lists them. */
function pendingOf(info: AppInfo | null, steps: ScanStep[], current: string | null): string[] {
  const done = new Set(steps.map((s) => s.collector));
  return (info?.collectors ?? []).map((c) => c.id).filter((id) => !done.has(id) && id !== current);
}

export function ScanProgress({
  steps,
  total,
  current,
  elapsed,
  building,
}: {
  steps: ScanStep[];
  total: number;
  current: string | null;
  elapsed: number | null;
  building: boolean;
}) {
  const { t } = useTranslation();
  const done = steps.length;
  const percent = total > 0 ? Math.round((done / total) * 100) : 0;
  const measured = steps.filter((s) => s.state === "measured").length;
  const unmeasured = steps.filter((s) => s.state === "unmeasured").length;
  const notConsented = steps.filter((s) => s.state === "not_consented").length;
  const name = (id: string) => t(`report:collector.${id}`, { defaultValue: id });
  return (
    <>
      <div
        className="progress"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
        aria-label={t("scan.progress_label")}
      >
        <div className="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      <p className="progress-text">
        {t("scan.progress", { done, total, percent })}
        {current && (
          <>
            {" "}
            <span className="current">{t("scan.current", { module: name(current) })}</span>
          </>
        )}
        {building && (
          <>
            {" "}
            <span className="current">{t("ui.scan.building")}</span>
          </>
        )}
      </p>
      <dl className="progress-facts status-strip">
        <div>
          <dt>{t("ui.scan.measured")}</dt>
          <dd>{measured}</dd>
        </div>
        <div>
          <dt>{t("ui.scan.unmeasured")}</dt>
          <dd>{unmeasured}</dd>
        </div>
        <div>
          <dt>{t("ui.scan.not_consented")}</dt>
          <dd>{notConsented}</dd>
        </div>
        <div>
          <dt>{t("ui.scan.pending")}</dt>
          <dd>{Math.max(0, total - done)}</dd>
        </div>
        <div>
          <dt>{t("ui.scan.elapsed")}</dt>
          <dd>{elapsed === null ? "—" : formatDuration(elapsed)}</dd>
        </div>
      </dl>
    </>
  );
}

export function ModuleLog({
  steps,
  current,
  pending,
}: {
  steps: ScanStep[];
  current: string | null;
  pending: string[];
}) {
  const { t } = useTranslation();
  const name = (id: string) => t(`report:collector.${id}`, { defaultValue: id });
  return (
    <section className="panel" aria-labelledby="modules-title">
      <h3 id="modules-title">{t("scan.modules")}</h3>
      <ol className="module-log">
        {steps.map((step) => (
          <li key={step.collector} className={`step step-${step.state}`}>
            <StepMark state={step.state} />
            <span className="step-name">{name(step.collector)}</span>
            <span className="step-state">
              {step.state === "measured"
                ? t("scan.measured", { observations: step.observations })
                : step.state === "not_consented"
                  ? t("scan.not_consented")
                  : t("scan.unmeasured", {
                      reason: t(`report:reason.${step.reason ?? "read_failed"}`),
                    })}
              {step.gaps > 0 && ` · ${t("scan.gaps", { gaps: step.gaps })}`}
            </span>
            <span className="step-time muted">{formatDuration(step.elapsed_ms)}</span>
          </li>
        ))}
        {current && (
          <li className="step step-running" aria-current="step">
            <Icon name="clock" />
            <span className="step-name">{name(current)}</span>
            <span className="step-state">{t("ui.scan.running")}</span>
            <span />
          </li>
        )}
        {pending.map((id) => (
          <li key={id} className="step step-pending">
            <span />
            <span className="step-name muted">{name(id)}</span>
            <span className="step-state">{t("ui.scan.waiting")}</span>
            <span />
          </li>
        ))}
      </ol>
    </section>
  );
}

function StepMark({ state }: { state: ScanStep["state"] }) {
  return (
    <span
      className={`mark ${state === "measured" ? "mark-not_found" : "mark-unmeasured"}`}
      aria-hidden="true"
    />
  );
}

function LiveFindings({
  steps,
  meta,
  texts,
}: {
  steps: ScanStep[];
  meta: Record<string, RuleMeta>;
  texts: Record<string, RuleText>;
}) {
  const { t } = useTranslation();
  const found = steps.flatMap((step) =>
    step.found_rules
      .filter((id) => !meta[id]?.selector)
      .map((id) => ({ id, level: meta[id]?.level ?? "info" })),
  );
  return (
    <section className="panel" aria-labelledby="live-title">
      <h3 id="live-title">{t("scan.live")}</h3>
      {found.length === 0 ? (
        <p className="muted">{t("scan.live_none")}</p>
      ) : (
        <ul className="live-findings">
          {found.map((item) => (
            <li key={item.id}>
              <Badge {...LEVEL_LOOK[item.level]} label={t(`level.${item.level}`)} />{" "}
              {texts[item.id]?.title ?? item.id}
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">{t("scan.live_note")}</p>
    </section>
  );
}
