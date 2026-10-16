// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Saving the report (B.O.P.E, ADR 0116, ADR 0129, ADR 0132): the same view this window shows, in the
// formats chosen, each with its SHA-256, and how the files write times.

import { useTranslation } from "react-i18next";
import type { Mode, SsOptions } from "../../types";
import { useTimeSettings } from "../../ui/TimeValue";
import { ExportPanel } from "../ExportPanel";

export function ReportsPage({ mode, options }: { mode: Mode; options?: SsOptions }) {
  const { t } = useTranslation();
  const { zone } = useTimeSettings();
  return (
    <div className="page-stack">
      <ExportPanel mode={mode} options={options} />
      <section className="panel" aria-labelledby="formats-title">
        <h3 id="formats-title">{t("ui.reports.formats_title")}</h3>
        <dl className="facts">
          <dt>HTML</dt>
          <dd>{t("ui.reports.html")}</dd>
          <dt>TXT</dt>
          <dd>{t("ui.reports.txt")}</dd>
          <dt>JSON</dt>
          <dd>{t("ui.reports.json")}</dd>
          <dt>PDF</dt>
          <dd>{t("ui.reports.pdf")}</dd>
        </dl>
        <p className="note">{t("ui.reports.times", { zone })}</p>
      </section>
    </div>
  );
}
