// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The start screen: what will be examined, how deep, and consent — all before anything is read
// (B.O.P.E, ADR 0115).

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { type ElevateOutcome, relaunchElevated } from "../api";
import type { AppInfo, ScanTier } from "../types";

export interface ScanChoice {
  tier: ScanTier;
}

interface Props {
  info: AppInfo | null;
  infoFailed: boolean;
  onStart: (choice: ScanChoice) => void;
}

/** The categories in display order, as the core names them. */
export const CATEGORY_ORDER = [
  "roblox_tools",
  "roblox",
  "fastflags",
  "processes_memory",
  "execution",
  "files",
  "persistence",
  "drivers",
  "macros_peripherals",
  "usb_devices",
  "browser_scripts",
  "network",
  "system_logs",
  "firmware_boot",
  "other",
] as const;

export function Home({ info, infoFailed, onStart }: Props) {
  const { t } = useTranslation();
  const [tier, setTier] = useState<ScanTier>("standard");
  const [agreed, setAgreed] = useState(false);
  const [elevation, setElevation] = useState<ElevateOutcome | null>(null);

  const fullOnly = (info?.collectors ?? []).filter((c) => c.tier === "full");
  const categories = CATEGORY_ORDER;

  return (
    <section className="home page-stack" aria-labelledby="home-title">
      <div className="home-lead">
        <h2 id="home-title">{t("home.title")}</h2>
        <p>{t("home.purpose")}</p>
      </div>

      <dl className="status-strip">
        <div>
          <dt>{t("home.rights")}</dt>
          <dd className={info?.elevated ? "good" : "attention"}>
            {info === null
              ? t("home.unknown")
              : info.elevated
                ? t("home.rights_admin")
                : t("home.rights_user")}
          </dd>
        </div>
        <div>
          <dt>{t("home.version")}</dt>
          <dd>{info?.version ?? "—"}</dd>
        </div>
        <div>
          <dt>{t("home.rules")}</dt>
          <dd>
            {info ? (
              <>
                {info.rules.rule_count} <code>{info.rules.sha256.slice(0, 12)}</code>
              </>
            ) : (
              "—"
            )}
          </dd>
        </div>
        <div>
          <dt>{t("home.system")}</dt>
          <dd>{info ? [info.platform, info.os_build].filter(Boolean).join(" ") : "—"}</dd>
        </div>
      </dl>
      {infoFailed && <p className="note">{t("home.info_failed")}</p>}

      {info?.elevated === false && (
        <div className="elevate note">
          <p>{t("home.elevate_hint")}</p>
          <button type="button" onClick={() => void relaunchElevated().then(setElevation)}>
            {t("home.elevate_button")}
          </button>
          {elevation === "declined" && <p className="muted">{t("home.elevate_declined")}</p>}
          {elevation === "failed" && <p className="note">{t("home.elevate_failed")}</p>}
        </div>
      )}

      <fieldset className="option-group">
        <legend>{t("home.depth")}</legend>
        <label className={`option ${tier === "standard" ? "selected" : ""}`}>
          <input
            type="radio"
            name="tier"
            checked={tier === "standard"}
            onChange={() => setTier("standard")}
          />
          <span className="option-title">{t("home.tier_standard")}</span>
          <span className="muted">{t("home.tier_standard_hint")}</span>
        </label>
        <label className={`option ${tier === "full" ? "selected" : ""}`}>
          <input
            type="radio"
            name="tier"
            checked={tier === "full"}
            onChange={() => setTier("full")}
          />
          <span className="option-title">{t("home.tier_full")}</span>
          <span className="muted">{t("home.tier_full_hint")}</span>
          {fullOnly.length > 0 && (
            <ul className="adds">
              {fullOnly.map((c) => (
                <li key={c.id}>{t(`report:collector.${c.id}`, { defaultValue: c.id })}</li>
              ))}
            </ul>
          )}
        </label>
      </fieldset>

      <section className="consent-box panel" aria-labelledby="consent-title">
        <h3 id="consent-title">{t("home.consent_title")}</h3>
        <p>{t("home.reads_intro")}</p>
        <ul className="reads">
          {categories.map((category) => (
            <li key={category}>
              <strong>{t(`report:category.${category}`)}</strong>{" "}
              <span className="muted">{t(`home.reads.${category}`)}</span>
            </li>
          ))}
        </ul>
        <ul className="promises">
          <li>{t("home.promise_offline")}</li>
          <li>{t("home.promise_readonly")}</li>
          <li>{t("home.promise_private")}</li>
          <li>{t("home.promise_visible")}</li>
        </ul>
        <p className="muted">{t("home.limits")}</p>
        <label className="agree">
          <input
            type="checkbox"
            checked={agreed}
            onChange={(event) => setAgreed(event.target.checked)}
          />{" "}
          {t("home.agree")}
        </label>
        <p className="muted">{t("home.refuse_ok")}</p>
      </section>

      <button
        type="button"
        className="primary start-button"
        disabled={!agreed || info === null}
        onClick={() => onStart({ tier })}
      >
        {t("home.start")}
      </button>
    </section>
  );
}
