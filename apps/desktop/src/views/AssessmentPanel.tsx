// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The assessment above the evidence: the conclusion, a board of the categories and what the
// conclusion rests on (B.O.P.E, ADR 0100). It reads the evidence and never replaces it.

import { useTranslation } from "react-i18next";
import type { Assessment, ModuleState, RuleText } from "../types";
import { Badge, LEVEL_LOOK } from "../ui/Badge";
import { TimeValue } from "../ui/TimeValue";

interface Props {
  assessment: Assessment;
  texts: Record<string, RuleText>;
  category: string | null;
  onCategory: (category: string | null) => void;
}

const STATE_CLASS: Record<ModuleState, string> = {
  ok: "ok",
  info: "info",
  warn: "warn",
  flag: "flag",
  not_checked: "na",
};

export function AssessmentPanel({ assessment, texts, category, onCategory }: Props) {
  const { t } = useTranslation("report");
  const title = (id: string) => texts[id]?.title ?? id;
  return (
    <section className="assessment page-stack" aria-labelledby="assessment-title">
      <div className={`verdict verdict-${assessment.conclusion}`} role="status">
        <h2 id="assessment-title">{t(`conclusion.${assessment.conclusion}`)}</h2>
        <p>{t(`conclusion_note.${assessment.conclusion}`)}</p>
        <p className="small">
          {t("assessment.sources", {
            sources: assessment.independent_sources,
            flags: assessment.flag_sources,
          })}
        </p>
      </div>

      <ul className="board" aria-label={t("assessment.board")}>
        {assessment.categories.map((item) => (
          <li key={item.category}>
            <button
              type="button"
              className={`tile tile-${STATE_CLASS[item.state]} ${category === item.category ? "active" : ""}`}
              aria-pressed={category === item.category}
              onClick={() => onCategory(category === item.category ? null : item.category)}
            >
              <span className={`chip chip-${STATE_CLASS[item.state]}`}>
                {t(`module_state.${item.state}`)}
              </span>
              <span className="tile-name">{t(`category.${item.category}`)}</span>
              <span className="tile-count muted">
                {t("assessment.counts", { measured: item.measured, unmeasured: item.unmeasured })}
                {item.partial && ` · ${t("assessment.partial")}`}
              </span>
            </button>
          </li>
        ))}
      </ul>

      {assessment.supporting.length > 0 && (
        <section className="supporting panel" aria-labelledby="supporting-title">
          <h3 id="supporting-title">{t("assessment.supporting")}</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t("assessment.col_level")}</th>
                  <th>{t("assessment.col_rule")}</th>
                  <th>{t("assessment.col_source")}</th>
                  <th>{t("assessment.col_times")}</th>
                </tr>
              </thead>
              <tbody>
                {assessment.supporting.map((item) => (
                  <tr key={item.rule_id}>
                    <td>
                      <Badge {...LEVEL_LOOK[item.level]} label={t(`common:level.${item.level}`)} />
                    </td>
                    <td>{title(item.rule_id)}</td>
                    <td>{t(`source.${item.source}`, { defaultValue: item.source })}</td>
                    <td className="times">
                      {item.earliest ? <TimeValue value={item.earliest} compact /> : "—"}
                      {item.latest && item.latest !== item.earliest && (
                        <div>
                          → <TimeValue value={item.latest} compact />
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {assessment.proximity.map((pair) => (
            <p key={`${pair.a}-${pair.b}`} className="proximity">
              {t("assessment.proximity", {
                minutes: Math.round(pair.seconds / 60),
                a: title(pair.a),
                b: title(pair.b),
              })}
            </p>
          ))}
        </section>
      )}

      <details className="caveats">
        <summary>{t("assessment.limits")}</summary>
        <ul>
          {assessment.caveats.map((key) => (
            <li key={key}>{t(`caveat.${key}`)}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}
