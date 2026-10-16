// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Long lists are shown a page at a time, so thousands of rows never reach the DOM at once.

import { useState } from "react";
import { useTranslation } from "react-i18next";

export const PAGE_SIZE = 100;

/** The slice of `items` on the current page; the page goes back to the first when `items` changes. */
export function usePage<T>(items: T[], size: number = PAGE_SIZE) {
  const [page, setPage] = useState(0);
  // The rows are compared by count and by their first and last element, not by the array itself: a
  // caller may build a new array of the same rows on every render.
  const signature: [number, T | undefined, T | undefined] = [items.length, items[0], items.at(-1)];
  const [seen, setSeen] = useState(signature);
  if (seen[0] !== signature[0] || seen[1] !== signature[1] || seen[2] !== signature[2]) {
    // Other rows (a filter changed): back to the first page, during render rather than after it.
    setSeen(signature);
    setPage(0);
  }
  const pages = Math.max(1, Math.ceil(items.length / size));
  const current = Math.min(page, pages - 1);
  return {
    rows: items.slice(current * size, current * size + size),
    page: current,
    pages,
    setPage,
    from: items.length === 0 ? 0 : current * size + 1,
    to: Math.min(items.length, current * size + size),
    total: items.length,
  };
}

export function Pager({
  page,
  pages,
  setPage,
  from,
  to,
  total,
}: {
  page: number;
  pages: number;
  setPage: (page: number) => void;
  from: number;
  to: number;
  total: number;
}) {
  const { t } = useTranslation();
  if (pages <= 1) {
    return null;
  }
  return (
    <nav className="pager" aria-label={t("ui.pager.label")}>
      <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
        {t("ui.pager.previous")}
      </button>
      <span>{t("ui.pager.range", { from, to, total })}</span>
      <button type="button" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>
        {t("ui.pager.next")}
      </button>
    </nav>
  );
}
