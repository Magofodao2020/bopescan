// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// Mirrors crates/bope-core/src/model.rs and view.rs. The UI tests feed these types with the Rust
// report snapshots, so a drift between the two fails `pnpm test`. (Generating them with ts-rs is planned.)

export type UnmeasuredReason =
  | "not_windows"
  | "not_on_this_os"
  | "not_admin"
  | "not_attempted"
  | "access_denied"
  | "service_disabled"
  | "source_absent"
  | "source_empty"
  | "partial"
  | "budget_spent"
  | "read_failed"
  | "collector_unavailable"
  | "not_consented"
  | "other_volume";

export type Strength = "execution" | "presence" | "tamper" | "posture" | "context";

export interface Observation {
  collector: string;
  fields: Record<string, unknown>;
}

export type EvidenceState =
  | { state: "found"; observations: Observation[] }
  | { state: "not_found"; retention: string }
  /** `expected` is whether the rule named this reason in its `unmeasured_when` (ADR 0027). */
  | { state: "unmeasured"; reason: UnmeasuredReason; expected: boolean };

export type Evidence = {
  rule_id: string;
  collector: string;
  strength: Strength;
} & EvidenceState;

export interface Provenance {
  official: boolean;
  version: string;
  commit: string | null;
  exe_sha256: string | null;
}

/**
 * When the running Windows kernel started counting (ADR 0039). Context for reading the times on the
 * rows, never evidence. A "Shut down" with Fast Startup, sleep and hibernation do not reset it.
 */
export type BootTime =
  | { state: "measured"; booted_at: string; seconds_since_boot: number }
  | { state: "unmeasured"; reason: UnmeasuredReason };

export interface ReportHeader {
  schema_version: number;
  provenance: Provenance;
  rules_bundle: { schema_version: number; sha256: string; rule_count: number };
  platform: string;
  os_build: string | null;
  elevated: boolean | null;
  generated_at: string;
  boot_time: BootTime;
  /** Which scan the player chose before it started; absent from an older report, which was standard (ADR 0052). */
  scan_tier?: ScanTier;
  /** Dated facts about when parts of this PC were set up, UTC dates only (ADR 0061). */
  anchors?: Anchor[];
}

/** Which anchor: a dated fact about when part of this PC was set up (ADR 0061). */
export type AnchorKind =
  | "install_date"
  | "setup_earliest_install"
  | "usn_journal_created"
  | "system_drive_root_created"
  | "recycle_bin_created"
  | "fivem_legacy_program_folder_created"
  | "fivem_legacy_app_folder_created"
  | "fivem_enhanced_program_folder_created";

/** An anchor's UTC date and what was read, or why there is none. */
export type Anchor = { anchor: AnchorKind } & (
  | { state: "measured"; on: string; source: string; kept?: number }
  | { state: "unmeasured"; reason: UnmeasuredReason }
);

/** An anchor as the trace-ages section shows it: `boot_time` first, then the header's, in days. */
export type AnchorAge = { anchor: "boot_time" | AnchorKind } & (
  | { state: "measured"; on: string; days_before: number; source?: string; kept?: number }
  | { state: "unmeasured"; reason: UnmeasuredReason }
);

/**
 * How far back one source reaches (ADR 0061): its oldest time and how much it holds, or why it was
 * not read. `not_admin` is "not known", never "empty".
 */
export type TraceAge = {
  collector: string;
  place?: string;
  subject?: string;
  index_beside?: IndexBeside[];
} & (
  | {
      state: "measured";
      oldest?: string;
      days_before?: number;
      count: number;
      extra?: Record<string, unknown>;
    }
  | { state: "unmeasured"; reason: UnmeasuredReason }
);

/** The logs the bundle does not read, as one line. */
export interface FoldedLogs {
  collector: string;
  logs: number;
  with_records: number;
  not_read: number;
}

/** The trace-ages section, built in Rust (ADR 0061). Nothing in it is compared. */
export interface TraceAges {
  anchors: AnchorAge[];
  rows: TraceAge[];
  folded_logs?: FoldedLogs;
}

/** FiveM's side of the cross-source statement: a presence, a count and dates, never a name. */
export interface FivemSide {
  editions: string[];
  folders_written?: string;
  folders_days_before?: number;
  server_folders: number;
  servers_written?: string;
}

/** One of Windows' records of programs that ran, in one of ADR 0061's line forms. */
export type SourceLine = { collector: string } & (
  | { line: "selected"; entries: number; latest: string }
  | { line: "no_entry"; entries: number; oldest: string; days_before: number }
  | { line: "could_not_show"; entries: number }
  | { line: "not_read"; reason: UnmeasuredReason }
  | { line: "switched_off" }
);

/**
 * FiveM's side beside Prefetch, BAM and PCA (ADR 0061 section 3). Not evidence and never counted;
 * built in Rust only when its conditions hold, and always shown with its ordinary causes.
 */
export interface RecordsStatement {
  fivem: FivemSide;
  sources: SourceLine[];
}

/** A duration as the core rounds it: minutes under an hour, hours under two days, then days. */
export interface Duration {
  amount: number;
  unit: "minutes" | "hours" | "days";
}

/** Which anchor name a session's time came from (ADR 0062 section 2). */
export type AnchorName = "fivem_exe" | "gta_process";

/** Where a session's start came from, or why there is none. */
export type SessionStart =
  | { from: "process" | "prefetch"; at: string; name: AnchorName }
  | { from: "switched_off" | "not_recorded" }
  | { from: "not_read"; reason: UnmeasuredReason };

/** Where a session's end came from, or why there is none. */
export type SessionEnd =
  | { from: "still_running" | "not_recorded" }
  | { from: "bam"; at: string }
  | { from: "not_read"; reason: UnmeasuredReason };

/** One time compared with the session. */
export interface Comparison {
  relation: "before_start" | "after_start" | "before_end" | "near_end" | "after_end";
  duration: Duration;
}

/** One source of an edition in one of ADR 0062's line forms. */
export type SessionLine = {
  source: string;
  variant?: string;
} & (
  | { line: "compared"; created?: Comparison; written: Comparison }
  | { line: "not_there" | "no_file" | "not_listed" }
  | { line: "not_read"; reason: UnmeasuredReason }
);

/** One edition's last session beside its own folders (ADR 0062). Not evidence and never counted. */
export type SessionStatement = { edition: "legacy" | "enhanced" } & (
  | {
      session: "known";
      start: SessionStart;
      end: SessionEnd;
      before_scan?: Duration;
      lines: SessionLine[];
      causes: string[];
    }
  | { session: "not_known"; prefetch: UnmeasuredReason; bam: UnmeasuredReason }
);

/** The cross-source statements, told apart by `kind` (ADR 0061, amended by ADR 0062 section 1). */
export type CrossSourceStatement =
  | ({ kind: "fivem_and_records" } & RecordsStatement)
  | ({ kind: "session" } & SessionStatement);

/** One Legacy launch mode's index beside its oldest cache file (ADR 0062 section 4). */
export interface IndexBeside {
  variant: string;
  index_created_on: string;
  oldest_file_created_on?: string;
  cache_files: number;
}

/** A source's ordinary retention, from `rules/ages/<collector>.yaml`, translated (ADR 0061). */
export interface AgeText {
  retention: string;
  documented: boolean;
  references: string[];
}

/** How much a scan reads, chosen before it starts (ADR 0052). */
export type ScanTier = "standard" | "full";

/**
 * One observation that describes aeterna-rongroi itself rather than the machine. The tool is running
 * while it scans, so a collector that enumerates the machine sees it (ADR 0010).
 */
export interface OwnTraceEntry {
  collector: string;
  observation: Observation;
}

/**
 * Observations of one collector that no rule matched. A collector reads the machine whether or not a
 * rule asks about what it finds, and evidence carries observations only where a rule matched, so
 * without this bucket what such a collector saw would be read and then discarded (ADR 0014).
 */
export interface UnmatchedGroup {
  collector: string;
  observations: Observation[];
}

/** How many of the evidence a view lists are in each state (ADR 0045). Never added into one number. */
export interface ListedCounts {
  found: number;
  not_found: number;
  unmeasured: number;
}

/** Where a timeline entry came from (ADR 0051). */
export type EntrySource =
  | { kind: "anchor" }
  | { kind: "evidence"; rule_id: string }
  | { kind: "selector"; selector_id: string }
  | { kind: "observation" };

/** One time value on the timeline. `collector` is null for the scan's own times. */
export interface TimelineEntry {
  at: string;
  collector: string | null;
  field: string;
  place: string | null;
  source: EntrySource;
  subject: string | null;
}

/** The span one source could see. "Nothing recorded" can be read only inside it. */
export interface CoverageBand {
  collector: string;
  place: string | null;
  subject: string | null;
  from: string;
  to: string;
}

/** A source of times, or one place of it, that could not be read. */
export interface UnmeasuredSource {
  collector: string;
  place?: string;
  reason: UnmeasuredReason;
}

/**
 * The times a view may show, oldest first, with the spans that bound them (ADR 0051). Nothing is
 * computed from the entries: no gap, no count, no summary. Built in Rust.
 */
export interface Timeline {
  entries: TimelineEntry[];
  bands: CoverageBand[];
  unmeasured: UnmeasuredSource[];
}

/**
 * The span one row's count is for: the coverage band of the place its collector's coverage names —
 * for `usn`, the change journal (ADR 0047, amendment of 2026-09-30). `no_span` when the source was
 * read and held no record. Built in Rust, in both modes.
 */
export type RowBand = { state: "span"; from: string; to: string } | { state: "no_span" };

/** The Roblox tool correlation, arranged for its own panel (B.O.P.E, ADR 0123). */
export interface RobloxTools {
  tools: Observation[];
  hits: Observation[];
  sources: Observation[];
}

/** Every row of the forensic collectors, by collector (B.O.P.E, ADR 0133–0137). */
export interface Forensics {
  roblox_memory: Observation[];
  roblox_flags: Observation[];
  roblox_monitor: Observation[];
  process_modules: Observation[];
  file_inventory: Observation[];
}

export interface ReportView {
  /** The forensic collectors' rows (B.O.P.E, ADR 0133–0137); absent from older snapshots. */
  forensics?: Forensics;
  /** The Roblox tool correlation; absent from upstream snapshots. */
  roblox_tools?: RobloxTools;
  /** `windows_service` observations, current state first (B.O.P.E, ADR 0130); absent when none. */
  services?: Observation[];
  /** `recycle_bin` observations (B.O.P.E, ADR 0131). */
  recycle_bin?: Observation[];
  /** The B.O.P.E assessment of the report this view came from (ADR 0100); absent from upstream snapshots. */
  assessment?: Assessment;
  header: ReportHeader;
  evidence: Evidence[];
  /** What this program itself left in what the collectors saw, kept apart from the evidence (ADR 0010). */
  own_traces: OwnTraceEntry[];
  /** What the collectors saw that no rule matched (ADR 0014). */
  unmatched: UnmatchedGroup[];
  /**
   * Facts about the scan, above the evidence. `not_admin` is how many checks missing administrator
   * rights left unanswered — one fact about the scan rather than one per rule, and the one with a
   * remedy (ADR 0027).
   */
  scope: { not_admin: number; not_attempted: number; not_consented?: number };
  listed: ListedCounts;
  timeline: Timeline;
  /** The order collector groups appear in, from the core (ADR 0051). */
  collector_order: string[];
  /** By rule id, for a `found` or `not_found` row whose count is for a span; absent when none is. */
  row_bands?: Record<string, RowBand>;
  /** How far back each source reaches, beside the anchors (ADR 0061). */
  trace_ages?: TraceAges;
  /** At most one cross-source statement; absent when its conditions do not hold (ADR 0061). */
  cross_source?: CrossSourceStatement[];
}

/** Where a rule, its fixtures and its collector are in the repository, from its root (ADR 0045). */
export interface RuleFiles {
  rule: string;
  fixtures: string;
  collector: string;
  references: string[];
}

export interface RuleText {
  title: string;
  description: string;
  falsepositives: string[];
  /** Look-back note for `not_found`, translated. Evidence keeps the English source. */
  retention: string;
  status: "experimental" | "test" | "stable" | "deprecated";
  files: RuleFiles;
}

/** Where this binary's code can be read (ADR 0045). `commit` is set for an official build only. */
export interface CodeLinks {
  repository: string;
  code: string;
  commit: string | null;
}

// ─── B.O.P.E Scanner additions (ADR 0100, 0115, 0116) ───────────────────────────────────────────

/** What a `found` result means to the assessment. */
export type Level = "info" | "warn" | "flag";

/** The state of one category. `ok` means the checks ran and found none of their indicators. */
export type ModuleState = "not_checked" | "ok" | "info" | "warn" | "flag";

/** The overall reading; deliberately no "clean" and no "guilty". */
export type Conclusion =
  | "no_suspicious_evidence"
  | "inconclusive"
  | "manual_review"
  | "corroborated"
  | "high_confidence";

export interface FoundRule {
  rule_id: string;
  collector: string;
  level: Level;
  source: string;
  observations: number;
  earliest: string | null;
  latest: string | null;
}

export interface CategoryAssessment {
  category: string;
  state: ModuleState;
  found: FoundRule[];
  measured: number;
  unmeasured: number;
  partial: boolean;
}

export interface Proximity {
  a: string;
  b: string;
  seconds: number;
}

export interface Assessment {
  categories: CategoryAssessment[];
  conclusion: Conclusion;
  supporting: FoundRule[];
  independent_sources: number;
  flag_sources: number;
  proximity: Proximity[];
  caveats: string[];
}

export interface CollectorInfo {
  id: string;
  tier: ScanTier;
  category: string;
}

export interface AppInfo {
  version: string;
  official: boolean;
  exe_sha256: string | null;
  rules: { schema_version: number; sha256: string; rule_count: number };
  elevated: boolean | null;
  platform: string;
  os_build: string | null;
  collectors: CollectorInfo[];
}

/** One finished collector, as the scan reports it. */
export interface ScanStep {
  done: number;
  total: number;
  collector: string;
  state: "measured" | "unmeasured" | "not_consented";
  reason: UnmeasuredReason | null;
  observations: number;
  gaps: number;
  found_rules: string[];
  elapsed_ms: number;
  /** The collector running after this one; `null` after the last. */
  next?: string | null;
}

export interface ScanStatus {
  state: "idle" | "running" | "done" | "cancelled" | "failed";
  steps: ScanStep[];
  total: number;
  started_at: string | null;
  message: string | null;
  tier: ScanTier | null;
  /** The collector running now; `null` when none is (building the report, or not running). */
  current?: string | null;
  /** A stop was asked for and the scan has not stopped yet. */
  cancel_requested?: boolean;
  /** What the running collector says it is reading now, when it says (B.O.P.E, ADR 0133). */
  detail?: string | null;
}

/** How the last reference update ended (B.O.P.E, ADR 0136). */
export type SyncOutcome = "updated" | "not_modified" | "rejected" | "failed" | "too_soon";

/** What is known about the FastFlag reference copy held. */
export interface ReferenceMetadata {
  file: string;
  sha256: string;
  entries: number;
  source_url: string;
  revision: string;
  revision_kind: "commit" | "content" | "import";
  commit_date?: string | null;
  commit_message?: string | null;
  fetched_at: string;
}

/** The FastFlag reference panel's facts. */
export interface ReferenceStatus {
  available: boolean;
  unavailable_reason: string | null;
  metadata: ReferenceMetadata | null;
  reference_client_version: string | null;
  state: {
    last_attempt_at?: string | null;
    last_outcome?: SyncOutcome | null;
    last_detail?: string | null;
    last_success_at?: string | null;
    last_import_at?: string | null;
  };
  folder: string;
}

/** What one reference update did. */
export interface SyncResult {
  outcome: SyncOutcome;
  detail: string;
  status: ReferenceStatus | null;
}

/** One change the monitoring mode saw (B.O.P.E, ADR 0137). */
export interface MonitorEvent {
  at: string;
  since: string | null;
  event: string;
  pid: number | null;
  subject: string;
  source: string | null;
  before: string | null;
  after: string | null;
  first_seen_at: string | null;
}

/** Where the monitoring mode is. */
export interface MonitorStatus {
  running: boolean;
  started_at: string | null;
  last_sample_at: string | null;
  interval_seconds: number;
  samples: number;
  partial_samples: number;
  events: MonitorEvent[];
  events_dropped: number;
}

export interface RuleMeta {
  level: Level;
  category: string;
  collector: string;
  selector: boolean;
}

export interface SavedFile {
  path: string;
  sha256: string;
}
