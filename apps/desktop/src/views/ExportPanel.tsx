// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Saving the report to a folder the person chooses, as JSON, HTML, text and PDF, each with its SHA-256
// (B.O.P.E, ADR 0116; PDF: ADR 0129). Nothing is sent anywhere.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { defaultExportDir, exportReport, pickExportDir } from "../api";
import type { SavedFile } from "../types";
import { useTimeSettings } from "../ui/TimeValue";

const FORMATS = ["html", "json", "txt", "pdf"] as const;

export function ExportPanel() {
  const { t, i18n } = useTranslation("report");
  const { zone } = useTimeSettings();
  const [dir, setDir] = useState("");
  const [formats, setFormats] = useState<string[]>([...FORMATS]);
  const [saved, setSaved] = useState<SavedFile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void defaultExportDir()
      .then((value) => setDir((current) => current || value || ""))
      .catch(() => {});
  }, []);

  const toggle = (format: string) =>
    setFormats((current) =>
      current.includes(format) ? current.filter((f) => f !== format) : [...current, format],
    );

  return (
    <section className="export panel" aria-labelledby="export-title">
      <h3 id="export-title">{t("export.title")}</h3>
      <p className="muted">{t("export.note_self")}</p>
      <div className="export-row">
        <label className="export-dir">
          {t("export.folder")}
          <input type="text" value={dir} onChange={(event) => setDir(event.target.value)} />
        </label>
        <button
          type="button"
          onClick={() =>
            void pickExportDir()
              .then((picked) => picked && setDir(picked))
              .catch(() => {})
          }
        >
          {t("export.pick")}
        </button>
      </div>
      <fieldset className="formats">
        <legend>{t("export.formats")}</legend>
        {FORMATS.map((format) => (
          <label key={format}>
            <input
              type="checkbox"
              checked={formats.includes(format)}
              onChange={() => toggle(format)}
            />{" "}
            {format.toUpperCase()}
          </label>
        ))}
      </fieldset>
      <button
        type="button"
        className="primary"
        disabled={busy || formats.length === 0 || dir.trim() === ""}
        onClick={() => {
          setBusy(true);
          setError(null);
          void exportReport(i18n.language, formats, dir, zone)
            .then(setSaved)
            .catch((reason: unknown) => setError(String(reason)))
            .finally(() => setBusy(false));
        }}
      >
        {t("export.save")}
      </button>
      {error && <p className="note">{t("export.failed", { error })}</p>}
      {saved.length > 0 && (
        <div className="saved">
          <p>{t("export.saved")}</p>
          <ul>
            {saved.map((file) => (
              <li key={file.path}>
                <code>{file.path}</code>
                <br />
                <span className="muted">SHA-256</span> <code className="hash">{file.sha256}</code>
              </li>
            ))}
          </ul>
          <p className="muted small">{t("export.hash_note")}</p>
        </div>
      )}
    </section>
  );
}
