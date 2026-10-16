// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// One recorded time as every page shows it (B.O.P.E, ADR 0132): the wall clock of the zone chosen in
// Settings with its offset, the other reading below it, what the time says happened, how certain it
// is, and the value exactly as received on hover and in the raw view.

import { createContext, useContext } from "react";
import { useTranslation } from "react-i18next";
import { type ShownTime, showTime, systemZone, type TimeCertainty, type TimeKind } from "../time";

export type TimeDisplay = "local" | "utc";

export interface TimeSettings {
  /** Which reading is shown first. */
  display: TimeDisplay;
  /** The zone of the local reading. */
  zone: string;
}

export const TimeSettingsContext = createContext<TimeSettings>({
  display: "local",
  zone: systemZone(),
});

export function useTimeSettings() {
  return useContext(TimeSettingsContext);
}

/** `shown` as one line of text in the chosen reading, for places that cannot hold two lines. */
export function timeLine(shown: ShownTime, display: TimeDisplay): string {
  return display === "utc" ? `${shown.utc} UTC` : `${shown.local} (${shown.offset})`;
}

export function TimeValue({
  value,
  kind,
  certainty,
  compact = false,
}: {
  value: string;
  kind?: TimeKind;
  certainty?: TimeCertainty;
  compact?: boolean;
}) {
  const { t } = useTranslation();
  const settings = useTimeSettings();
  const shown = showTime(value, settings.zone);
  if (!shown) {
    // Not a time this program reads: shown as received, never guessed.
    return (
      <span className="time-raw" title={t("ui.time.unrecognised")}>
        {value} <span className="kind">({t("ui.time.unrecognised_short")})</span>
      </span>
    );
  }
  const main = timeLine(shown, settings.display);
  const other = timeLine(shown, settings.display === "utc" ? "local" : "utc");
  const title = [
    `${t("ui.time.local")}: ${shown.local} ${shown.offset} (${shown.zone})`,
    `UTC: ${shown.utc}`,
    `${t("ui.time.received")}: ${shown.iso}`,
    kind ? `${t("ui.time.kind_label")}: ${t(`ui.time.kind.${kind}`)}` : null,
    certainty ? `${t("ui.time.certainty_label")}: ${t(`ui.time.certainty.${certainty}`)}` : null,
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <span className="time" title={title}>
      <time
        className={`time-main ${certainty ? `certainty-${certainty}` : ""}`}
        dateTime={shown.iso}
      >
        {main}
      </time>
      {!compact && <span className="time-sub">{other}</span>}
      {(kind || (certainty && certainty !== "exact")) && (
        <span className="kind">
          {kind && t(`ui.time.kind.${kind}`)}
          {certainty && certainty !== "exact" && ` · ${t(`ui.time.certainty.${certainty}`)}`}
        </span>
      )}
    </span>
  );
}
