// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The window (B.O.P.E, ADR 0115, ADR 0132): a side navigation over one scan flow — choose and consent,
// watch the real progress, then read the frozen report across its pages. A result page is reachable
// only once a report exists, so no page is ever shown empty for want of a scan.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { appInfo, ruleMeta, ruleTexts, startScan } from "./api";
import logo from "./assets/bope-logo.png";
import { languageNames, supportedLanguages } from "./i18n";
import { type ScanResult, useReportData } from "./reportData";
import { systemZone } from "./time";
import type { AppInfo, ReportHeader, RuleMeta, RuleText, ScanStatus } from "./types";
import { Badge } from "./ui/Badge";
import { Icon, type IconName } from "./ui/Icon";
import { type TimeDisplay, TimeSettingsContext, TimeValue } from "./ui/TimeValue";
import type { ScanChoice } from "./views/Home";
import { type EvidenceFocus, EvidencePage } from "./views/pages/EvidencePage";
import { OverviewPage } from "./views/pages/OverviewPage";
import { RecycleBinPage } from "./views/pages/RecycleBinPage";
import { ReportsPage } from "./views/pages/ReportsPage";
import { type Flow, ScannerPage } from "./views/pages/ScannerPage";
import { ServicesPage } from "./views/pages/ServicesPage";
import { SettingsPage } from "./views/pages/SettingsPage";
import { TimelinePage } from "./views/pages/TimelinePage";

export type Page =
  | "overview"
  | "scanner"
  | "evidence"
  | "services"
  | "recycle"
  | "timeline"
  | "reports"
  | "settings";

const NAV: { page: Page; icon: IconName; needsReport: boolean }[] = [
  { page: "overview", icon: "overview", needsReport: true },
  { page: "scanner", icon: "scanner", needsReport: false },
  { page: "evidence", icon: "evidence", needsReport: true },
  { page: "services", icon: "services", needsReport: true },
  { page: "recycle", icon: "recycle", needsReport: true },
  { page: "timeline", icon: "timeline", needsReport: true },
  { page: "reports", icon: "reports", needsReport: true },
  { page: "settings", icon: "settings", needsReport: false },
];

const TIME_DISPLAY_KEY = "bope.timeDisplay";

function storedDisplay(): TimeDisplay {
  try {
    return window.localStorage.getItem(TIME_DISPLAY_KEY) === "utc" ? "utc" : "local";
  } catch {
    return "local";
  }
}

/** The facts About shows, from what the start screen already read. */
function headerOf(info: AppInfo): ReportHeader {
  return {
    schema_version: 1,
    provenance: {
      official: info.official,
      version: info.version,
      commit: null,
      exe_sha256: info.exe_sha256,
    },
    rules_bundle: info.rules,
    platform: info.platform,
    os_build: info.os_build,
    elevated: info.elevated,
    generated_at: "",
    boot_time: { state: "unmeasured", reason: "not_attempted" },
  };
}

export function App() {
  const { t, i18n } = useTranslation();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [infoFailed, setInfoFailed] = useState(false);
  const [meta, setMeta] = useState<Record<string, RuleMeta>>({});
  const [texts, setTexts] = useState<Record<string, RuleText>>({});
  const [flow, setFlow] = useState<Flow>({ kind: "home" });
  const [result, setResult] = useState<ScanResult | null>(null);
  const [lastStatus, setLastStatus] = useState<ScanStatus | null>(null);
  const [page, setPage] = useState<Page>("scanner");
  const [focus, setFocus] = useState<EvidenceFocus | null>(null);
  const [display, setDisplay] = useState<TimeDisplay>(storedDisplay);
  const timeSettings = useMemo(() => ({ display, zone: systemZone() }), [display]);
  const data = useReportData(result, i18n.language);

  useEffect(() => {
    void appInfo()
      .then(setInfo)
      .catch(() => setInfoFailed(true));
    void ruleMeta()
      .then(setMeta)
      .catch(() => {});
  }, []);

  useEffect(() => {
    void ruleTexts(i18n.language)
      .then(setTexts)
      .catch(() => {});
  }, [i18n.language]);

  const choice = flow.kind === "scanning" ? flow.choice : null;
  const onFinished = useCallback(
    (status: ScanStatus) => {
      setLastStatus(status);
      if (status.state === "done" && choice) {
        setResult({ mode: choice.mode, options: choice.options });
        setFlow({ kind: "done", choice });
        setPage("overview");
      } else if (status.state === "cancelled") {
        setFlow({ kind: "cancelled" });
      } else {
        setFlow({ kind: "failed", message: status.message });
      }
    },
    [choice],
  );

  const onStart = (next: ScanChoice) => {
    setFlow({ kind: "busy" });
    setResult(null);
    setFocus(null);
    void startScan(next.tier)
      .then((started) =>
        setFlow(
          started
            ? { kind: "scanning", choice: next }
            : { kind: "failed", message: t("scan.already") },
        ),
      )
      .catch((reason: unknown) => setFlow({ kind: "failed", message: String(reason) }));
  };

  const go = (next: Page, nextFocus: EvidenceFocus | null = null) => {
    setFocus(nextFocus);
    setPage(next);
  };

  const changeDisplay = (next: TimeDisplay) => {
    setDisplay(next);
    try {
      window.localStorage.setItem(TIME_DISPLAY_KEY, next);
    } catch {
      // A preference that cannot be kept still applies to this window.
    }
  };

  const view = data.view;
  const hasReport = result !== null;
  const counts: Partial<Record<Page, number>> = view
    ? {
        evidence: view.listed.found,
        services: (view.services ?? []).filter((o) => o.fields.scope === "current").length,
        recycle: (view.recycle_bin ?? []).filter((o) => o.fields.scope === "item").length,
        timeline: view.timeline.entries.length,
      }
    : {};
  const scanning = flow.kind === "scanning" || flow.kind === "busy";

  return (
    <TimeSettingsContext.Provider value={timeSettings}>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <img src={logo} alt="" width={48} height={48} />
            <div>
              <h1>{t("app.name")}</h1>
              <p>{t("ui.brand_line")}</p>
            </div>
          </div>
          <nav aria-label={t("ui.nav.label")}>
            <ul className="nav-list">
              {NAV.map((item) => {
                const disabled = item.needsReport && (!hasReport || scanning);
                return (
                  <li key={item.page}>
                    <button
                      type="button"
                      className="nav-item"
                      data-page={item.page}
                      aria-current={page === item.page ? "page" : undefined}
                      disabled={disabled}
                      title={disabled ? t("ui.nav.after_scan") : undefined}
                      onClick={() => go(item.page)}
                    >
                      <Icon name={item.icon} />
                      {t(`ui.nav.${item.page}`)}
                      {counts[item.page] !== undefined && (
                        <span className="nav-count">{counts[item.page]}</span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          </nav>
          <div className="sidebar-foot">
            <label className="language">
              <span className="visually-hidden">{t("language.label")}</span>
              <select
                aria-label={t("language.label")}
                value={i18n.language}
                onChange={(e) => void i18n.changeLanguage(e.target.value)}
              >
                {supportedLanguages.map((lang) => (
                  <option key={lang} value={lang}>
                    {languageNames[lang]}
                  </option>
                ))}
              </select>
            </label>
            <span>
              {t("home.version")} {info?.version ?? "—"}
            </span>
          </div>
        </aside>

        <div className="content">
          <header className="topbar">
            <h2>{t(`ui.nav.${page}`)}</h2>
            {view && (
              <div className="context">
                <Badge
                  tone="neutral"
                  shape="ring"
                  label={view.mode === "ss" ? t("ui.mode.ss") : t("ui.mode.self")}
                />
                <Badge
                  tone="neutral"
                  shape="ring"
                  label={
                    view.header.scan_tier === "full"
                      ? t("report:header.tier_full")
                      : t("report:header.tier_standard")
                  }
                />
                {view.header.generated_at && (
                  <span className="small muted">
                    {t("ui.scanned_at")} <TimeValue value={view.header.generated_at} compact />
                  </span>
                )}
              </div>
            )}
          </header>

          <main className="page">
            {page === "scanner" && (
              <ScannerPage
                info={info}
                infoFailed={infoFailed}
                meta={meta}
                texts={texts}
                flow={flow}
                lastStatus={lastStatus}
                onStart={onStart}
                onFinished={onFinished}
                onNew={() => setFlow({ kind: "home" })}
                onOpenReport={() => go("overview")}
              />
            )}
            {page !== "scanner" && page !== "settings" && hasReport && (
              <ResultPage page={page} data={data} result={result} focus={focus} go={go} />
            )}
            {page === "settings" && (
              <SettingsPage
                header={view?.header ?? (info ? headerOf(info) : null)}
                headerFailed={infoFailed}
                display={display}
                onDisplay={changeDisplay}
              />
            )}
          </main>

          <footer className="page-footer">{t("footer.evidence_only")}</footer>
        </div>
      </div>
    </TimeSettingsContext.Provider>
  );
}

function ResultPage({
  page,
  data,
  result,
  focus,
  go,
}: {
  page: Page;
  data: ReturnType<typeof useReportData>;
  result: ScanResult;
  focus: EvidenceFocus | null;
  go: (page: Page, focus?: EvidenceFocus | null) => void;
}) {
  const { t } = useTranslation();
  if (data.failed) {
    return (
      <div className="note error" role="alert">
        {t("ui.state.report_failed")} <code>{data.failed}</code>
      </div>
    );
  }
  if (!data.view) {
    return (
      <div className="loading" role="status">
        <span className="bar" aria-hidden="true" />
        {t("ui.state.loading_report")}
      </div>
    );
  }
  switch (page) {
    case "overview":
      return <OverviewPage data={data} go={go} />;
    case "evidence":
      return <EvidencePage data={data} focus={focus} />;
    case "services":
      return <ServicesPage view={data.view} />;
    case "recycle":
      return <RecycleBinPage view={data.view} />;
    case "timeline":
      return <TimelinePage view={data.view} texts={data.texts} ages={data.ages} />;
    case "reports":
      return <ReportsPage mode={result.mode} options={result.options} />;
    default:
      return null;
  }
}
