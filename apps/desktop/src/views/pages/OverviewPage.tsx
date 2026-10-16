// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The first page of a report (B.O.P.E, ADR 0132): the assessment, the three counts, the facts about
// the scan, and one line on each other page with the way to it. It decides nothing the core did not.

import { useTranslation } from "react-i18next";
import type { Page } from "../../App";
import { fieldText, type ReportData } from "../../reportData";
import { showTime } from "../../time";
import type { BootTime, Observation } from "../../types";
import { Icon } from "../../ui/Icon";
import { TimeValue, timeLine, useTimeSettings } from "../../ui/TimeValue";
import { AssessmentPanel } from "../AssessmentPanel";
import { ReportSummary } from "../ReportSummary";
import type { EvidenceFocus } from "./EvidencePage";

interface Props {
  data: ReportData;
  go: (page: Page, focus?: EvidenceFocus | null) => void;
}

export function OverviewPage({ data, go }: Props) {
  const { t } = useTranslation("report");
  const view = data.view;
  if (!view) {
    return null;
  }
  const { header } = view;
  const rights =
    header.elevated === null
      ? t("header.elevated_unknown")
      : header.elevated
        ? t("header.elevated_yes")
        : t("header.elevated_no");
  const services = (view.services ?? []).filter((o) => o.fields.scope === "current");
  const bin = (view.recycle_bin ?? []).find((o) => o.fields.scope === "bin");
  const items = (view.recycle_bin ?? []).filter((o) => o.fields.scope === "item");
  const tools = view.roblox_tools?.tools ?? [];

  return (
    <div className="page-stack">
      {view.assessment && (
        <AssessmentPanel
          assessment={view.assessment}
          texts={data.texts}
          category={null}
          onCategory={(category) => go("evidence", { category, state: null })}
        />
      )}

      <ReportSummary
        listed={view.listed}
        filter={null}
        onFilter={(state) => go("evidence", { category: null, state })}
      />

      <ScopeNotes data={data} />

      <div className="grid-3">
        <button type="button" className="stat tile" onClick={() => go("evidence")}>
          <span className="stat-label">{t("common:ui.overview.tools")}</span>
          <span className="stat-value">{tools.length}</span>
          <span className="small muted">{t("common:ui.overview.tools_note")}</span>
        </button>
        <button type="button" className="stat tile" onClick={() => go("services")}>
          <span className="stat-label">{t("common:ui.nav.services")}</span>
          <span className="stat-value">
            {services.length === 0
              ? t("common:ui.overview.not_read")
              : t("common:ui.overview.services_value", {
                  running: services.filter((o) => o.fields.state === "running").length,
                  total: services.length,
                })}
          </span>
          <span className="small muted">{t("common:ui.overview.services_note")}</span>
        </button>
        <button type="button" className="stat tile" onClick={() => go("recycle")}>
          <span className="stat-label">{t("common:ui.nav.recycle")}</span>
          <span className="stat-value">
            {bin
              ? t("common:ui.overview.recycle_value", { count: items.length })
              : t("common:ui.overview.not_read")}
          </span>
          <span className="small muted">
            {bin && fieldText(bin.fields, "last_artifact_change") ? (
              <>
                {t("common:ui.recycle.last_change")}:{" "}
                <TimeValue value={fieldText(bin.fields, "last_artifact_change")} compact />
              </>
            ) : (
              t("common:ui.overview.recycle_note")
            )}
          </span>
        </button>
        <button type="button" className="stat tile" onClick={() => go("timeline")}>
          <span className="stat-label">{t("common:ui.nav.timeline")}</span>
          <span className="stat-value">
            {t("common:ui.overview.timeline_value", { count: view.timeline.entries.length })}
          </span>
          <span className="small muted">{t("common:ui.overview.timeline_note")}</span>
        </button>
      </div>

      <section className="panel" aria-labelledby="facts-title">
        <h3 id="facts-title">{t("common:ui.overview.facts")}</h3>
        <dl className="facts context">
          <dt>{t("common:ui.overview.mode")}</dt>
          <dd>{view.mode === "ss" ? t("header.mode_ss") : t("header.mode_self")}</dd>
          <dt>{t("header.scan_tier")}</dt>
          <dd>{header.scan_tier === "full" ? t("header.tier_full") : t("header.tier_standard")}</dd>
          <dt>{t("common:ui.overview.scanned_at")}</dt>
          <dd>
            {header.generated_at ? <TimeValue value={header.generated_at} kind="scan" /> : "—"}
          </dd>
          <dt>{t("header.version")}</dt>
          <dd>{header.provenance.version}</dd>
          <dt>{t("common:about.build")}</dt>
          <dd>
            {header.provenance.official ? (
              t("common:about.official")
            ) : (
              <span className="build-mark">{t("common:banner.unofficial")}</span>
            )}
          </dd>
          <dt>{t("header.platform")}</dt>
          <dd>{[header.platform, header.os_build].filter(Boolean).join(" ")}</dd>
          <dt>{t("header.rights")}</dt>
          <dd>{rights}</dd>
          {/* One line of context for reading every time, with the sentence that stops a start days
              ago being read as something the player did (ADR 0039). */}
          <dt>{t("header.boot_time")}</dt>
          <dd>
            <BootTimeValue bootTime={header.boot_time} />
          </dd>
          <dt>{t("header.rules")}</dt>
          <dd>
            {header.rules_bundle.rule_count} ·{" "}
            <code>{header.rules_bundle.sha256.slice(0, 12)}</code>
          </dd>
        </dl>
      </section>

      <button type="button" className="ghost" onClick={() => go("reports")}>
        <Icon name="reports" />
        {t("common:ui.overview.to_reports")}
      </button>
    </div>
  );
}

/** Facts about the scan stated once, above the evidence (ADR 0027, ADR 0030). */
export function ScopeNotes({ data }: { data: ReportData }) {
  const { t } = useTranslation("report");
  const view = data.view;
  if (!view) {
    return null;
  }
  const { header } = view;
  return (
    <>
      {view.scope.not_admin > 0 && (
        <p className="scope">{t("scope.not_admin", { checks: view.scope.not_admin })}</p>
      )}
      {view.scope.not_attempted > 0 && (
        <p className="scope">{t("scope.not_attempted", { checks: view.scope.not_attempted })}</p>
      )}
      {(view.scope.not_consented ?? 0) > 0 && (
        <p className="scope">
          {t("scope.not_consented", { checks: view.scope.not_consented ?? 0 })}
        </p>
      )}
      {view.mode === "ss" && header.scan_tier === "full" && !data.options?.server_identity && (
        <p className="muted">{t("header.server_identity_hidden")}</p>
      )}
      {view.mode === "ss" && header.scan_tier === "full" && !data.options?.download_host && (
        <p className="muted">{t("header.download_host_hidden")}</p>
      )}
    </>
  );
}

export function BootTimeValue({ bootTime }: { bootTime: BootTime }) {
  const { t } = useTranslation("report");
  const { zone, display } = useTimeSettings();
  if (bootTime.state === "unmeasured") {
    return <>{t("header.boot_time_unmeasured", { reason: t(`reason.${bootTime.reason}`) })}</>;
  }
  const seconds = bootTime.seconds_since_boot;
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const since =
    days > 0
      ? t("header.elapsed_days", { days, hours, minutes })
      : t("header.elapsed", { hours, minutes });
  const shown = showTime(bootTime.booted_at, zone);
  return (
    <>
      <span title={bootTime.booted_at}>
        {t("header.boot_time_value", {
          at: shown ? timeLine(shown, display) : bootTime.booted_at,
          since,
        })}
      </span>{" "}
      <span className="muted">{t("header.boot_time_note")}</span>
    </>
  );
}

/** Observations of `scope`, in order. */
export function scoped(rows: Observation[] | undefined, scope: string): Observation[] {
  return (rows ?? []).filter((o) => o.fields.scope === scope);
}
