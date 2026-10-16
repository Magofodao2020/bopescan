// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Settings that change only how this window shows the report, and About: where the code is, the
// licence, the credits and the notices the licence asks this program to show (NOTICE section 7).

import { useTranslation } from "react-i18next";
import { languageNames, supportedLanguages } from "../../i18n";
import { showTime } from "../../time";
import type { ReportHeader } from "../../types";
import { type TimeDisplay, useTimeSettings } from "../../ui/TimeValue";
import { About } from "../About";

interface Props {
  header: ReportHeader | null;
  headerFailed: boolean;
  display: TimeDisplay;
  onDisplay: (display: TimeDisplay) => void;
}

export function SettingsPage({ header, headerFailed, display, onDisplay }: Props) {
  const { t, i18n } = useTranslation();
  const { zone } = useTimeSettings();
  const sample = showTime(new Date().toISOString().replace(/\.\d+Z$/, "Z"), zone);
  return (
    <div className="page-stack">
      <section className="panel" aria-labelledby="settings-title">
        <h3 id="settings-title">{t("ui.settings.title")}</h3>
        <label>
          {t("language.label")}
          <select value={i18n.language} onChange={(e) => void i18n.changeLanguage(e.target.value)}>
            {supportedLanguages.map((lang) => (
              <option key={lang} value={lang}>
                {languageNames[lang]}
              </option>
            ))}
          </select>
        </label>
        <fieldset>
          <legend>{t("ui.settings.time_title")}</legend>
          <div className="option-group">
            <label className={`option ${display === "local" ? "selected" : ""}`}>
              <input
                type="radio"
                name="time-display"
                checked={display === "local"}
                onChange={() => onDisplay("local")}
              />
              <span className="option-title">{t("ui.settings.time_local")}</span>
              <span className="muted small">
                {sample ? `${sample.local} (${sample.offset}, ${sample.zone})` : zone}
              </span>
            </label>
            <label className={`option ${display === "utc" ? "selected" : ""}`}>
              <input
                type="radio"
                name="time-display"
                checked={display === "utc"}
                onChange={() => onDisplay("utc")}
              />
              <span className="option-title">{t("ui.settings.time_utc")}</span>
              <span className="muted small">{sample ? `${sample.utc} UTC` : "UTC"}</span>
            </label>
          </div>
          <p className="small muted">{t("ui.settings.time_note")}</p>
        </fieldset>
      </section>
      <About header={header} headerFailed={headerFailed} />
    </div>
  );
}
