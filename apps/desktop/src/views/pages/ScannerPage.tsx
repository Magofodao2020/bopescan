// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The one scan flow (B.O.P.E, ADR 0115, ADR 0132): choose and consent, watch it run, and after it the
// record of what each module did, with the way to the report or to a new check.

import { useTranslation } from "react-i18next";
import type { AppInfo, RuleMeta, RuleText, ScanStatus } from "../../types";
import { Icon } from "../../ui/Icon";
import { Loading } from "../../ui/States";
import { Home, type ScanChoice } from "../Home";
import { ModuleLog, Scanning, ScanProgress } from "../Scanning";

export type Flow =
  | { kind: "home" }
  | { kind: "busy" }
  | { kind: "scanning"; choice: ScanChoice }
  | { kind: "done"; choice: ScanChoice }
  | { kind: "cancelled" }
  | { kind: "failed"; message: string | null };

interface Props {
  info: AppInfo | null;
  infoFailed: boolean;
  meta: Record<string, RuleMeta>;
  texts: Record<string, RuleText>;
  flow: Flow;
  lastStatus: ScanStatus | null;
  onStart: (choice: ScanChoice) => void;
  onFinished: (status: ScanStatus) => void;
  onNew: () => void;
  onOpenReport: () => void;
}

export function ScannerPage({
  info,
  infoFailed,
  meta,
  texts,
  flow,
  lastStatus,
  onStart,
  onFinished,
  onNew,
  onOpenReport,
}: Props) {
  const { t } = useTranslation();
  switch (flow.kind) {
    case "home":
      return <Home info={info} infoFailed={infoFailed} onStart={onStart} />;
    case "busy":
      return <Loading label={t("ui.scan.starting")} />;
    case "scanning":
      return <Scanning info={info} meta={meta} texts={texts} onFinished={onFinished} />;
    case "cancelled":
      return (
        <section className="panel" aria-labelledby="cancelled-title">
          <h3 id="cancelled-title">{t("scan.cancelled_title")}</h3>
          <p>{t("scan.cancelled_body")}</p>
          <div>
            <button type="button" className="primary" onClick={onNew}>
              {t("ui.scan.new")}
            </button>
          </div>
        </section>
      );
    case "failed":
      return (
        <section className="panel" aria-labelledby="failed-title">
          <h3 id="failed-title">{t("scan.failed_title")}</h3>
          <p>{t("scan.failed_body")}</p>
          {flow.message && <p className="note error">{flow.message}</p>}
          <div>
            <button type="button" onClick={onNew}>
              {t("ui.scan.new")}
            </button>
          </div>
        </section>
      );
    case "done":
      return (
        <section className="scan-done" aria-labelledby="done-title">
          <div className="panel">
            <div className="panel-head">
              <h3 id="done-title">{t("ui.scan.done_title")}</h3>
              <span className="aside" />
            </div>
            {lastStatus && (
              <ScanProgress
                steps={lastStatus.steps}
                total={lastStatus.total}
                current={null}
                elapsed={null}
                building={false}
              />
            )}
            <div className="toolbar">
              <button type="button" className="primary" onClick={onOpenReport}>
                <Icon name="overview" />
                {t("ui.scan.open_report")}
              </button>
              <button type="button" onClick={onNew}>
                {t("ui.scan.new")}
              </button>
            </div>
          </div>
          {lastStatus && <ModuleLog steps={lastStatus.steps} current={null} pending={[]} />}
        </section>
      );
  }
}
