// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The states every page shows the same way: loading, empty, failed, and "not read" with its reason.

import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "./Icon";

export function Loading({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div className="loading" role="status">
      <span className="bar" aria-hidden="true" />
      {label ?? t("ui.state.loading")}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

export function Failed({ title, detail }: { title: string; detail?: string | null }) {
  return (
    <div className="note error notice-row" role="alert">
      <Icon name="alert" />
      <div>
        <strong>{title}</strong>
        {detail && <p className="small mono">{detail}</p>}
      </div>
    </div>
  );
}
