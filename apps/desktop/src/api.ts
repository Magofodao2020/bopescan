// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// The only way the UI talks to Rust: local Tauri IPC commands. No network (ADR 0003).

import { invoke } from "@tauri-apps/api/core";
import type {
  AgeText,
  AppInfo,
  CodeLinks,
  Mode,
  ReportHeader,
  ReportView,
  RuleMeta,
  RuleText,
  SavedFile,
  ScanStatus,
  ScanTier,
  SsOptions,
} from "./types";

/** Facts for the start screen, read before any scan: version, rules, rights and the collectors. */
export function appInfo(): Promise<AppInfo> {
  return invoke<AppInfo>("app_info");
}

/** Starts the scan the person chose and agreed to; `false` when one already ran in this window. */
export function startScan(tier: ScanTier): Promise<boolean> {
  return invoke<boolean>("start_scan", { tier });
}

/** Asks the running scan to stop before its next collector; a stopped scan has no report. */
export function cancelScan(): Promise<void> {
  return invoke<void>("cancel_scan");
}

/** The scan's real progress: every collector that finished, with what it found. */
export function scanStatus(): Promise<ScanStatus> {
  return invoke<ScanStatus>("scan_status");
}

/** Level, category and collector of every rule. */
export function ruleMeta(): Promise<Record<string, RuleMeta>> {
  return invoke<Record<string, RuleMeta>>("rule_meta");
}

/** `Documents\B.O.P.E Scanner` of this account, where reports go unless another folder is chosen. */
export function defaultExportDir(): Promise<string | null> {
  return invoke<string | null>("default_export_dir");
}

/** The folder picked in the Windows folder picker, or `null` when cancelled. */
export function pickExportDir(): Promise<string | null> {
  return invoke<string | null>("pick_export_dir");
}

/** Saves the report as `mode` shows it, in each format, with a `.sha256` file beside each. */
export function exportReport(
  mode: Mode,
  options: SsOptions | undefined,
  lang: string,
  formats: string[],
  dir: string,
  timeZone: string,
): Promise<SavedFile[]> {
  return invoke<SavedFile[]>("export_report", {
    mode,
    options: options ?? null,
    lang,
    formats,
    dir,
    timeZone,
  });
}

/** Facts about the scan (provenance, platform) without any evidence. */
export function reportHeader(): Promise<ReportHeader> {
  return invoke<ReportHeader>("report_header");
}

/**
 * The frozen report as `mode` may see it, with what the player agreed SS mode may show beyond its
 * default. Filtering, redaction and the placeholders happen in Rust (ADR 0052).
 */
export function reportView(mode: Mode, options?: SsOptions): Promise<ReportView> {
  return invoke<ReportView>("report_view", { mode, options: options ?? null });
}

/** What came of a request to restart with administrator rights. */
export type ElevateOutcome = "started" | "declined" | "failed";

/**
 * Starts an elevated copy of this program and closes this one; the new copy shows the start screen again.
 * Declining the Windows prompt is reported as `declined`, a normal outcome rather than a failure.
 */
export function relaunchElevated(): Promise<ElevateOutcome> {
  return invoke<ElevateOutcome>("relaunch_elevated");
}

/** Rule text in `lang`, keyed by rule id, English fallback applied in Rust. */
export function ruleTexts(lang: string): Promise<Record<string, RuleText>> {
  return invoke<Record<string, RuleText>>("rule_texts", { lang });
}

/** Every field each collector declares as a time, by collector (B.O.P.E, ADR 0132). */
export function timeFields(): Promise<Record<string, string[]>> {
  return invoke<Record<string, string[]>>("time_fields");
}

/** Each source's ordinary retention in `lang`, keyed by collector, English fallback applied in Rust (ADR 0061). */
export function ageTexts(lang: string): Promise<Record<string, AgeText>> {
  return invoke<Record<string, AgeText>>("age_texts", { lang });
}

/** Where this binary's code can be read: the commit of an official build, the repository otherwise. */
export function codeLinks(): Promise<CodeLinks> {
  return invoke<CodeLinks>("code_links");
}

/** A QR code of a link into the repository as SVG text, drawn in Rust; `null` for any other text. */
export function codeLinkQr(url: string): Promise<string | null> {
  return invoke<string | null>("code_link_qr", { url });
}
