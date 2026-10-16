// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Every time the interface shows goes through this file (B.O.P.E, ADR 0132).
//
// Rust stores and sends each time once, as RFC 3339 in UTC ("2026-10-16T13:00:00Z"), with the field
// it came from. This file parses that string, and only that string: a value already formatted for
// display is never parsed again, so a time is converted exactly once. A value that is not RFC 3339 is
// shown as it was received, marked as not recognised — never guessed, completed or replaced.

/** One time as the interface shows it. `iso` is always the value received, unchanged. */
export interface ShownTime {
  /** The value as Rust sent it. Technical exports and the raw view use this. */
  iso: string;
  /** `DD/MM/AAAA HH:mm:ss` in UTC. */
  utc: string;
  /** `DD/MM/AAAA HH:mm:ss` in `zone`. */
  local: string;
  /** The zone's offset at that instant, as `UTC−03:00`. */
  offset: string;
  /** The IANA name of the zone shown, as `America/Sao_Paulo`. */
  zone: string;
  /** Digits after the seconds the source kept: 0 for whole seconds. */
  fraction: number;
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/;

/** The zone the person's Windows uses, as the WebView reports it; `UTC` when it reports none. */
export function systemZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** The instant `text` names, or `null` when it is not RFC 3339 with an offset. */
export function parseInstant(text: string): Date | null {
  const match = RFC3339.exec(text.trim());
  if (!match) {
    return null;
  }
  const [y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0] = match.slice(1, 7).map(Number);
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth || h > 23 || mi > 59 || s > 59) {
    return null;
  }
  const millis = Number((match[7] ?? "").padEnd(3, "0").slice(0, 3));
  const zone = (match[8] ?? "Z").toUpperCase();
  const offsetMinutes =
    zone === "Z"
      ? 0
      : (zone.startsWith("-") ? -1 : 1) *
        (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  // `setUTCFullYear` takes the year literally, where `Date.UTC` maps 0–99 to 1900–1999.
  const date = new Date(0);
  date.setUTCFullYear(y, mo - 1, d);
  date.setUTCHours(h, mi, s, millis);
  date.setTime(date.getTime() - offsetMinutes * 60_000);
  return Number.isNaN(date.getTime()) ? null : date;
}

const pad = (value: number, width = 2) => String(value).padStart(width, "0");

/** `DD/MM/AAAA HH:mm:ss` of `date` in `zone`. */
export function wallClock(date: Date, zone: string): string {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const part = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return `${part("day")}/${part("month")}/${part("year")} ${part("hour")}:${part("minute")}:${part("second")}`;
}

/** The offset of `zone` at `date`, as `UTC+07:00` or `UTC−03:00` (a real minus sign). */
export function offsetOf(date: Date, zone: string): string {
  const name =
    new Intl.DateTimeFormat("en-US", { timeZone: zone, timeZoneName: "longOffset" })
      .formatToParts(date)
      .find((p) => p.type === "timeZoneName")?.value ?? "GMT";
  if (name === "GMT") {
    return "UTC+00:00";
  }
  const match = /GMT([+-])(\d{1,2})(?::?(\d{2}))?/.exec(name);
  if (!match) {
    return "UTC";
  }
  const sign = match[1] === "-" ? "−" : "+";
  return `UTC${sign}${pad(Number(match[2]))}:${match[3] ?? "00"}`;
}

/** `text` as the interface shows it in `zone`, or `null` when it is not a time this file reads. */
export function showTime(text: string, zone: string = systemZone()): ShownTime | null {
  const date = parseInstant(text);
  if (!date) {
    return null;
  }
  let shownZone = zone;
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: zone });
  } catch {
    shownZone = "UTC";
  }
  return {
    iso: text,
    utc: wallClock(date, "UTC"),
    local: wallClock(date, shownZone),
    offset: offsetOf(date, shownZone),
    zone: shownZone,
    fraction: RFC3339.exec(text.trim())?.[7]?.length ?? 0,
  };
}

/** Whole seconds from `earlier` to `later`, or `null` when either is not a time this file reads. */
export function secondsBetween(earlier: string, later: string): number | null {
  const a = parseInstant(earlier);
  const b = parseInstant(later);
  if (!a || !b) {
    return null;
  }
  return Math.floor((b.getTime() - a.getTime()) / 1000);
}

/** Orders two RFC 3339 values by instant; a value that is not one sorts after every time, by text. */
export function compareInstants(a: string, b: string): number {
  const da = parseInstant(a);
  const db = parseInstant(b);
  if (da && db) {
    return da.getTime() - db.getTime() || a.localeCompare(b);
  }
  if (da) {
    return -1;
  }
  if (db) {
    return 1;
  }
  return a.localeCompare(b);
}

/** `ms` as `1 h 02 min 03 s`, `2 min 05 s` or `4,2 s`. */
export function formatDuration(ms: number): string {
  if (ms < 10_000) {
    return `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
  }
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) {
    return `${h} h ${pad(m)} min ${pad(s)} s`;
  }
  return `${m} min ${pad(s)} s`;
}

// ─── What a time is ─────────────────────────────────────────────────────────────────────────────

/**
 * What a recorded time says happened. The interface labels every time with one of these, from the
 * collector and field it came from; a field this table does not know is `recorded`, never guessed.
 */
export type TimeKind =
  | "created"
  | "modified"
  | "accessed"
  | "changed"
  | "execution"
  | "first_seen"
  | "last_seen"
  | "registered"
  | "installed"
  | "deleted"
  | "event"
  | "service_event"
  | "system_start"
  | "connected"
  | "removed"
  | "collected"
  | "scan"
  | "range_start"
  | "range_end"
  | "recorded";

/**
 * How far a time can be taken as the moment of what its kind says:
 * - `exact`: written by Windows when the event happened (an Event Log record, a `$I` deletion time).
 * - `approximate`: a bound or a summary — the oldest or newest of several values, a registry key's
 *   last write (any value under it), a first or last time a source noticed something.
 * - `uncertain`: a file system time any program able to write the file can set.
 */
export type TimeCertainty = "exact" | "approximate" | "uncertain";

const KIND_RULES: [RegExp, TimeKind][] = [
  [/^(collected_at)$/, "collected"],
  [/^(generated_at)$/, "scan"],
  [/^(deleted_at)$/, "deleted"],
  [/^(oldest|earliest|log_first|first_install)/, "range_start"],
  [/^(newest|latest|log_last|last_artifact_change)/, "range_end"],
  [/accessed$/, "accessed"],
  [/(si_changed)$/, "changed"],
  [/(created|created_at)$/, "created"],
  [/(modified|modified_at|written|write)$/, "modified"],
  [/^(last_run)$/, "execution"],
  [/^(first_seen)$/, "first_seen"],
  [/^(last_seen)$/, "last_seen"],
  [/^(last_arrival|last_arrival_at)$/, "connected"],
  [/^(last_removal|last_removal_at)$/, "removed"],
];

/** The kind of `field` of `collector`. */
export function timeKind(collector: string | null, field: string): TimeKind {
  if (collector === null) {
    return field === "generated_at" ? "scan" : "system_start";
  }
  if (collector === "windows_service" && field === "event_at") {
    return "service_event";
  }
  if (collector === "windows_start" && field === "started_at") {
    return "system_start";
  }
  if (collector === "process" && field === "started_at") {
    return "execution";
  }
  if (field === "event_at" || field === "time") {
    return "event";
  }
  if (field === "first_install_at" || field === "first_install") {
    return "installed";
  }
  if (field === "key_written" || field === "hive_written") {
    return "registered";
  }
  for (const [pattern, kind] of KIND_RULES) {
    if (pattern.test(field)) {
      return kind;
    }
  }
  return "recorded";
}

/** How certain `field` of `collector` is, as {@link TimeCertainty} defines it. */
export function timeCertainty(collector: string | null, field: string): TimeCertainty {
  const kind = timeKind(collector, field);
  if (kind === "scan" || kind === "collected" || kind === "system_start") {
    return "exact";
  }
  if (kind === "event" || kind === "service_event" || kind === "deleted") {
    return "exact";
  }
  if (kind === "execution" && collector !== "process") {
    // Prefetch, BAM and UserAssist keep a last run Windows wrote, not a log of every run.
    return "approximate";
  }
  if (kind === "execution") {
    return "exact";
  }
  if (
    kind === "range_start" ||
    kind === "range_end" ||
    kind === "first_seen" ||
    kind === "last_seen" ||
    kind === "registered" ||
    kind === "installed" ||
    kind === "connected" ||
    kind === "removed" ||
    kind === "recorded"
  ) {
    return "approximate";
  }
  return "uncertain";
}
