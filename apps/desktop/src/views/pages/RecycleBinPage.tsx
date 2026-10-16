// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The account's Recycle Bin and its times (B.O.P.E, ADR 0131). "When was the Recycle Bin modified?"
// is answered with the last modification observed in an artifact and where it was observed — the
// folder or one of its entries — never with a time no artifact holds. Each item keeps its own times
// apart: the deletion time inside its `$I`, the `$I` entry's own times, and its `$R` entry's.

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { fieldText } from "../../reportData";
import { compareInstants } from "../../time";
import type { Observation, ReportView } from "../../types";
import { Badge } from "../../ui/Badge";
import { Pager, usePage } from "../../ui/Paging";
import { Empty } from "../../ui/States";
import { TimeValue } from "../../ui/TimeValue";

type ItemFilter = "all" | "catalog" | "no_content";

export function RecycleBinPage({ view }: { view: ReportView }) {
  const { t } = useTranslation();
  const rows = view.recycle_bin ?? [];
  const bin = rows.find((o) => o.fields.scope === "bin");
  const items = rows.filter((o) => o.fields.scope === "item");
  const unread = view.timeline.unmeasured.find((source) => source.collector === "recycle_bin");

  if (!bin) {
    return (
      <div className="page-stack">
        <p className="note">{t("ui.recycle.intro")}</p>
        <Empty title={t("ui.recycle.not_read")}>
          {unread && <p>{t(`report:reason.${unread.reason}`)}</p>}
        </Empty>
      </div>
    );
  }
  return (
    <div className="page-stack">
      <p className="note">{t("ui.recycle.intro")}</p>
      <Summary bin={bin} />
      <Items items={items} ss={view.mode === "ss"} />
    </div>
  );
}

function Summary({ bin }: { bin: Observation }) {
  const { t } = useTranslation();
  const f = bin.fields;
  const time = (name: string) => fieldText(f, name);
  const source = time("last_artifact_change_source");
  return (
    <section className="panel" aria-labelledby="recycle-summary-title">
      <div className="panel-head">
        <h3 id="recycle-summary-title">{t("ui.recycle.summary_title")}</h3>
        <span className="small muted aside">{t("ui.recycle.drive", { drive: time("drive") })}</span>
      </div>
      <div className="grid-2">
        <div className="stat">
          <span className="stat-label">{t("ui.recycle.last_change")}</span>
          {time("last_artifact_change") ? (
            <TimeValue
              value={time("last_artifact_change")}
              kind="range_end"
              certainty="uncertain"
            />
          ) : (
            <span className="muted">{t("ui.recycle.no_time")}</span>
          )}
          <span className="small muted">
            {source ? t(`ui.recycle.last_change_source.${source}`) : t("ui.recycle.no_time")}
          </span>
        </div>
        <div className="stat">
          <span className="stat-label">{t("ui.recycle.newest_deletion")}</span>
          {time("newest_deleted_at") ? (
            <TimeValue value={time("newest_deleted_at")} kind="deleted" certainty="exact" />
          ) : (
            <span className="muted">{t("ui.recycle.no_deletion")}</span>
          )}
          <span className="small muted">{t("ui.recycle.newest_deletion_note")}</span>
        </div>
      </div>
      <p className="small muted">{t("ui.recycle.last_change_note")}</p>
      <dl className="facts">
        <dt>{t("ui.recycle.folder_created")}</dt>
        <dd>
          {time("folder_created") ? (
            <TimeValue value={time("folder_created")} kind="created" certainty="uncertain" />
          ) : (
            "—"
          )}
        </dd>
        <dt>{t("ui.recycle.folder_modified")}</dt>
        <dd>
          {time("folder_modified") ? (
            <TimeValue value={time("folder_modified")} kind="modified" certainty="uncertain" />
          ) : (
            "—"
          )}
        </dd>
        <dt>{t("ui.recycle.oldest_deletion")}</dt>
        <dd>
          {time("oldest_deleted_at") ? (
            <TimeValue value={time("oldest_deleted_at")} kind="deleted" certainty="exact" />
          ) : (
            "—"
          )}
        </dd>
        <dt>{t("ui.recycle.entries")}</dt>
        <dd>
          {t("ui.recycle.entries_value", {
            index: f.index_entries ?? 0,
            content: f.content_entries ?? 0,
          })}
        </dd>
        <dt>{t("ui.recycle.orphans")}</dt>
        <dd>
          {t("ui.recycle.orphans_value", {
            index: f.orphan_index ?? 0,
            content: f.orphan_content ?? 0,
          })}
        </dd>
        <dt>{t("ui.recycle.unreadable")}</dt>
        <dd>{String(f.unreadable_index ?? 0)}</dd>
      </dl>
      {f.read_capped === true && <p className="scope">{t("ui.recycle.capped")}</p>}
      <p className="small muted">{t("ui.recycle.orphans_note")}</p>
    </section>
  );
}

function Items({ items, ss }: { items: Observation[]; ss: boolean }) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState<ItemFilter>("all");
  const [search, setSearch] = useState("");
  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items
      .filter((o) => filter !== "catalog" || o.fields.tool_id !== undefined)
      .filter((o) => filter !== "no_content" || o.fields.content_present === false)
      .filter((o) => !needle || fieldText(o.fields, "path").toLowerCase().includes(needle))
      .sort(
        (a, b) =>
          compareInstants(fieldText(b.fields, "deleted_at"), fieldText(a.fields, "deleted_at")) ||
          fieldText(a.fields, "index_file").localeCompare(fieldText(b.fields, "index_file")),
      );
  }, [items, filter, search]);
  const paged = usePage(shown, 50);
  return (
    <section className="panel" aria-labelledby="recycle-items-title">
      <div className="panel-head">
        <h3 id="recycle-items-title">{t("ui.recycle.items_title")}</h3>
        <span className="small muted aside">
          {t("ui.evidence.shown", { shown: shown.length, total: items.length })}
        </span>
      </div>
      {ss && <p className="small muted">{t("ui.recycle.ss_note")}</p>}
      {items.length === 0 ? (
        <Empty title={t("ui.recycle.no_items")} />
      ) : (
        <>
          <div className="filters">
            <label className="search">
              {t("ui.recycle.search")}
              <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
            </label>
            <label>
              {t("ui.recycle.show")}
              <select value={filter} onChange={(e) => setFilter(e.target.value as ItemFilter)}>
                <option value="all">{t("ui.all")}</option>
                <option value="catalog">{t("ui.recycle.only_catalog")}</option>
                <option value="no_content">{t("ui.recycle.only_no_content")}</option>
              </select>
            </label>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("ui.recycle.col_item")}</th>
                  <th scope="col">{t("ui.recycle.col_deleted")}</th>
                  <th scope="col">{t("ui.recycle.col_index")}</th>
                  <th scope="col">{t("ui.recycle.col_content")}</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((o) => (
                  <ItemRow key={fieldText(o.fields, "index_file")} row={o} />
                ))}
              </tbody>
            </table>
          </div>
          <Pager {...paged} />
        </>
      )}
      <p className="small muted">{t("ui.recycle.content_note")}</p>
    </section>
  );
}

function ItemRow({ row }: { row: Observation }) {
  const { t } = useTranslation();
  const f = row.fields;
  const time = (name: string) => fieldText(f, name);
  return (
    <tr>
      <td>
        <strong>{time("name")}</strong>
        <div className="path">{time("path")}</div>
        <div className="small muted">
          {t("ui.recycle.size", { size: f.size ?? "—" })} ·{" "}
          <span className="mono">{time("index_file")}</span>
        </div>
        {f.tool_id !== undefined && (
          <Badge
            tone="warn"
            shape="diamond"
            label={t("ui.recycle.catalog", { tool: time("tool_id") })}
          />
        )}
      </td>
      <td>
        {time("deleted_at") ? (
          <TimeValue value={time("deleted_at")} kind="deleted" certainty="exact" />
        ) : (
          <span className="muted">{t("ui.recycle.no_time")}</span>
        )}
      </td>
      <td className="small">
        {time("index_created") ? (
          <TimeValue value={time("index_created")} kind="created" certainty="uncertain" compact />
        ) : (
          "—"
        )}
        {time("index_modified") && time("index_modified") !== time("index_created") && (
          <div>
            <TimeValue
              value={time("index_modified")}
              kind="modified"
              certainty="uncertain"
              compact
            />
          </div>
        )}
      </td>
      <td className="small">
        {f.content_present === true ? (
          <>
            {time("content_modified") ? (
              <TimeValue
                value={time("content_modified")}
                kind="modified"
                certainty="uncertain"
                compact
              />
            ) : (
              <span className="muted">{t("ui.recycle.no_time")}</span>
            )}
            {f.content_is_folder === true && <div className="muted">{t("ui.recycle.folder")}</div>}
          </>
        ) : (
          <Badge tone="neutral" shape="ring" label={t("ui.recycle.no_content")} />
        )}
      </td>
    </tr>
  );
}
