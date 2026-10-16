// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// One piece of evidence in the side panel (ADR 0045 layers, B.O.P.E ADR 0132): what it is and what it
// means first, then what was observed — each time with what it says happened and how certain it is,
// the path, hash and signature picked out — then the rule and its code, and the raw JSON only on
// request.

import { useTranslation } from "react-i18next";
import { withKeys } from "../keys";
import { timeCertainty, timeKind } from "../time";
import type { Evidence, Observation, RowBand, RuleFiles, RuleMeta, RuleText } from "../types";
import { Badge, EVIDENCE_LOOK, LEVEL_LOOK } from "../ui/Badge";
import { Icon } from "../ui/Icon";
import { TimeValue } from "../ui/TimeValue";
import { CodeLink } from "./CodeLink";

interface Props {
  item: Evidence;
  text: RuleText | undefined;
  meta: RuleMeta | undefined;
  band?: RowBand | undefined;
  /** Fields the core declared as times for this collector, from the timeline (ADR 0051). */
  timeFields: Set<string>;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
  official: boolean;
  onClose: () => void;
}

/** Fields shown first in an observation, because a reviewer checks them first. */
const KEY_FIELDS = ["path", "name", "sha256", "signature", "signer", "tool_id", "scope"];

export function stateKey(item: Evidence): string {
  return item.state === "unmeasured"
    ? item.expected
      ? "unmeasured_expected"
      : "unmeasured_unexpected"
    : item.state;
}

export function EvidenceDetails({
  item,
  text,
  meta,
  band,
  timeFields,
  fileBase,
  treeBase,
  linksKnown,
  official,
  onClose,
}: Props) {
  const { t } = useTranslation("report");
  const observations: Observation[] = item.state === "found" ? item.observations : [];
  return (
    <aside className="panel drawer" aria-labelledby="details-title">
      <div className="drawer-head">
        <h3 id="details-title">{text?.title ?? item.rule_id}</h3>
        <button type="button" className="ghost" onClick={onClose} aria-label={t("common:ui.close")}>
          <Icon name="close" />
        </button>
      </div>
      <div className="toolbar">
        <Badge {...EVIDENCE_LOOK[item.state]} label={t(`state.${stateKey(item)}`)} />
        {item.state === "found" && meta && (
          <Badge {...LEVEL_LOOK[meta.level]} label={t(`common:level.${meta.level}`)} />
        )}
        <span className="small muted">
          {t(`collector.${item.collector}`, { defaultValue: item.collector })}
        </span>
      </div>
      {text?.description && (
        <p className="description">
          {t("description")}: {text.description}
        </p>
      )}
      <Meaning item={item} text={text} />
      {band && <Band item={item} band={band} />}

      {observations.length > 0 && (
        <section aria-label={t("layers.observation")}>
          <h4>{t("common:ui.evidence.observed", { count: observations.length })}</h4>
          {withKeys(observations, (o) => JSON.stringify(o.fields)).map(([key, observation]) => (
            <ObservationCard key={key} observation={observation} timeFields={timeFields} />
          ))}
        </section>
      )}

      <dl className="facts">
        <dt>{t("layers.rule_id")}</dt>
        <dd>
          <code className="selectable">{item.rule_id}</code>
        </dd>
        {text && (
          <>
            <dt>{t("layers.status")}</dt>
            <dd>
              <code>{text.status}</code>
            </dd>
          </>
        )}
        <dt>{t("layers.collector")}</dt>
        <dd>
          <code>{item.collector}</code>
        </dd>
        <dt>{t("layers.strength")}</dt>
        <dd>
          {t(`strength.${item.strength}`)} (<code>{item.strength}</code>)
        </dd>
        {item.state === "unmeasured" && (
          <>
            <dt>{t("layers.reason")}</dt>
            <dd>
              <code>
                {item.reason} · expected={String(item.expected)}
              </code>
            </dd>
          </>
        )}
      </dl>
      {text && (
        <Files
          files={text.files}
          fileBase={fileBase}
          treeBase={treeBase}
          linksKnown={linksKnown}
          official={official}
        />
      )}
      <details className="raw-json">
        <summary>{t("common:ui.evidence.raw")}</summary>
        <pre>{JSON.stringify(item, null, 2)}</pre>
      </details>
    </aside>
  );
}

export function ObservationCard({
  observation,
  timeFields,
}: {
  observation: Observation;
  timeFields: Set<string>;
}) {
  const { t } = useTranslation("report");
  const entries = Object.entries(observation.fields);
  const ordered = [
    ...entries.filter(([field]) => KEY_FIELDS.includes(field)),
    ...entries.filter(([field]) => !KEY_FIELDS.includes(field)),
  ];
  return (
    <div className="observation-card">
      <div className="table-wrap">
        <table className="fields">
          <caption className="visually-hidden">{t("layers.observation")}</caption>
          <thead className="visually-hidden">
            <tr>
              <th scope="col">{t("layers.field")}</th>
              <th scope="col">{t("layers.value")}</th>
            </tr>
          </thead>
          <tbody>
            {ordered.map(([field, value]) => (
              <tr key={field}>
                <th scope="row">{field}</th>
                <td>
                  {timeFields.has(field) && typeof value === "string" ? (
                    <TimeValue
                      value={value}
                      kind={timeKind(observation.collector, field)}
                      certainty={timeCertainty(observation.collector, field)}
                    />
                  ) : (
                    <code className="selectable">{String(value)}</code>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Meaning({ item, text }: { item: Evidence; text: RuleText | undefined }) {
  const { t } = useTranslation("report");
  switch (item.state) {
    case "found": {
      const causes = text?.falsepositives ?? [];
      return causes.length === 0 ? null : (
        <div className="falsepositives">
          <p className="muted">{t("falsepositives")}:</p>
          <ul>
            {causes.map((cause) => (
              <li key={cause}>{cause}</li>
            ))}
          </ul>
        </div>
      );
    }
    case "not_found":
      return (
        <p className="detail">
          {t("retention")}: {text?.retention ?? item.retention}
        </p>
      );
    case "unmeasured":
      return <p className="detail">{t(`reason.${item.reason}`)}</p>;
  }
}

/**
 * The span the row's count is for: a count the change journal gives is for the span it still held,
 * and without the span "nothing deleted" reads as "nothing was ever deleted".
 */
function Band({ item, band }: { item: Evidence; band: RowBand }) {
  const { t } = useTranslation("report");
  if (band.state === "no_span") {
    return <p className="detail">{t("row_band.none")}</p>;
  }
  const key = item.state === "not_found" ? "row_band.not_found" : "row_band.found";
  return <p className="detail">{t(key, { from: band.from, to: band.to })}</p>;
}

function Files({
  files,
  fileBase,
  treeBase,
  linksKnown,
  official,
}: {
  files: RuleFiles;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
  official: boolean;
}) {
  const { t } = useTranslation("report");
  const paths: [string, string, string | null][] = [
    ["layers.rule_file", files.rule, fileBase && `${fileBase}/${files.rule}`],
    ["layers.fixtures", files.fixtures, treeBase && `${treeBase}/${files.fixtures}`],
    ["layers.collector_file", files.collector, fileBase && `${fileBase}/${files.collector}`],
  ];
  // Whether the commit is known and whether the build is official are two facts.
  const filesSentence = fileBase
    ? t("layers.files_at_commit")
    : official
      ? t("layers.files_commit_unknown")
      : t("layers.files_unknown_build");
  return (
    <section className="rule-files" aria-label={t("layers.code_title")}>
      <p className="muted">
        {t("layers.code_title")}
        {/* Carried fix (b): neither statement until it is known whether this build's commit is known. */}
        {linksKnown && <> · {filesSentence}</>}
      </p>
      <ul>
        {paths.map(([label, path, link]) => (
          <li key={label}>
            <span className="muted">{t(label)}</span> <CodeLink text={path} copy={link} />
          </li>
        ))}
        {files.references.map((url) => (
          <li key={url}>
            <span className="muted">{t("layers.reference")}</span>{" "}
            <CodeLink text={url} copy={url} />
          </li>
        ))}
      </ul>
    </section>
  );
}
