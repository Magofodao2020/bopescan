// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

// L4: the UI renders the same report the Rust pipeline produces (the insta snapshots), through mocked IPC.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import i18n, { initI18n } from "./i18n";
import { showTime } from "./time";
import type { ReportHeader, ReportView, RuleText, UnmeasuredReason } from "./types";
import { timeLine } from "./ui/TimeValue";
import { COPIED_FOR_MS } from "./views/CodeLink";

// Vitest runs with apps/desktop as the working directory.
const SNAPSHOTS = resolve(process.cwd(), "../../crates/bope-collectors/tests/snapshots");

/** Reads an insta snapshot, strips its front matter (`---\n…\n---\n`) and parses the JSON body. */
function snapshot(name: string): ReportView {
  const raw = readFileSync(resolve(SNAPSHOTS, `report_snapshot__${name}.snap`), "utf8");
  const body = raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n");
  return JSON.parse(body) as ReportView;
}

const RULE_ID = "7c1f3a52-9d4e-4b8a-a6f2-3e5d9b0c41e7";
const ENGLISH_RETENTION =
  "Current setting only. It says nothing about how the PC was configured in the past.";
const THAI_RETENTION = "เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น บอกไม่ได้ว่าในอดีตเครื่องนี้เคยตั้งค่าไว้อย่างไร";
// Both are mandatory in every rule and CI rejects a rule that leaves either empty, so the mock
// carries them the way the real bundle does (ADR 0027).
const ENGLISH_DESCRIPTION = "Windows reports that UEFI Secure Boot is off.";
const THAI_DESCRIPTION = "Windows รายงานว่า UEFI Secure Boot ปิดอยู่";
const ENGLISH_FALSEPOSITIVE = "PCs that boot in legacy BIOS or CSM mode";
const THAI_FALSEPOSITIVE = "เครื่องที่บูตแบบ legacy BIOS หรือ CSM";
const selfView = snapshot("secure_boot_off_self_view");
const ssView = snapshot("secure_boot_off_ss_view");

// The evidence entry these tests build their overrides from: the Secure Boot rule, found by id
// rather than taken as `evidence[0]`. Every assertion below is about that rule's own text, and the
// order of the evidence list is the order of the rules bundle — which changes whenever a rule is
// added, as `rules/evtx/` did.
function subject(view: ReportView) {
  const found = view.evidence.find((item) => item.rule_id === RULE_ID);
  if (!found) {
    throw new Error(`the snapshot has no evidence for ${RULE_ID}`);
  }
  return found;
}
let calls: string[] = [];
let viewOverride: ReportView | null = null;
/** Rule texts added to the mocked `rule_texts` answer, for tests that need a timeline selector's. */
let extraTexts: Record<string, RuleText> = {};
let headerOverride: ReportHeader | null = null;
/** What `app_info` answers; `elevated` is what the start screen reads. */
let infoElevated: boolean | null = true;
/** What `scan_status` answers after `start_scan`. */
let scanState: "running" | "done" | "cancelled" = "done";
let exportedWith: Record<string, unknown> | null = null;
let startedTier: unknown = null;
let linksOverride: { repository: string; code: string; commit: string | null } | null = null;
// Carried fix (b): a `code_links` call that never resolves, so `links` stays `null` — the same shape
// the UI sees while the call is still in flight or after it failed.
let linksNeverResolve = false;
/** An IPC call Rust refused, for the pages that must say so rather than stay blank. */
let headerFails = false;
let linksFail = false;
let clipboardWrites: string[] = [];
const REPOSITORY = "https://github.com/aeterna/aeterna-rongroi";
const COMMIT = "2c673c54aeb084cd3773057efbb9ed3b98fd2dbc";
// Carried fix (d): the real descriptor before any test stubs it, so it can be restored afterwards
// instead of leaking a fake `navigator.clipboard` into the next test file.
const originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");

beforeAll(async () => {
  await initI18n("en");
});

beforeEach(async () => {
  calls = [];
  viewOverride = null;
  extraTexts = {};
  headerOverride = null;
  linksOverride = null;
  infoElevated = true;
  scanState = "done";
  exportedWith = null;
  startedTier = null;
  linksNeverResolve = false;
  headerFails = false;
  linksFail = false;
  clipboardWrites = [];
  await i18n.changeLanguage("en");
  mockIPC(mockIPCAnswer);
});

/** The default IPC answers; a test that needs to see an argument wraps it. */
function mockIPCAnswer(cmd: string, args: unknown): unknown {
  {
    calls.push(cmd);
    const payload = (args ?? {}) as Record<string, unknown>;
    switch (cmd) {
      case "report_header":
        if (headerFails) {
          throw new Error("refused");
        }
        return headerOverride ?? selfView.header;
      case "report_view":
        return viewOverride ?? (payload.mode === "ss" ? ssView : selfView);
      case "rule_texts":
        return {
          ...extraTexts,
          [RULE_ID]: {
            title: payload.lang === "th" ? "Secure Boot ถูกปิดอยู่" : "Secure Boot is turned off",
            description: payload.lang === "th" ? THAI_DESCRIPTION : ENGLISH_DESCRIPTION,
            falsepositives: [payload.lang === "th" ? THAI_FALSEPOSITIVE : ENGLISH_FALSEPOSITIVE],
            retention: payload.lang === "th" ? THAI_RETENTION : ENGLISH_RETENTION,
            status: "test",
            files: {
              rule: "rules/posture/boot/secure-boot-disabled/rule.yaml",
              fixtures: "rules/posture/boot/secure-boot-disabled/tests",
              collector: "crates/bope-collectors/src/posture.rs",
              references: [],
            },
          },
        };
      case "age_texts":
        return {
          prefetch: {
            retention:
              payload.lang === "th"
                ? "Windows ลบไฟล์ Prefetch เอง"
                : "Windows removes Prefetch files itself.",
            documented: false,
            references: ["docs/adr/0030-the-words-for-what-was-not-measured.md"],
          },
        };
      case "code_links":
        if (linksNeverResolve) {
          return new Promise(() => {});
        }
        if (linksFail) {
          throw new Error("refused");
        }
        return linksOverride ?? { repository: REPOSITORY, code: REPOSITORY, commit: null };
      case "app_info": {
        if (headerFails) {
          throw new Error("refused");
        }
        const header = headerOverride ?? selfView.header;
        return {
          version: header.provenance.version,
          official: header.provenance.official,
          exe_sha256: header.provenance.exe_sha256,
          rules: header.rules_bundle,
          elevated: infoElevated,
          platform: header.platform,
          os_build: header.os_build,
          collectors: [
            { id: "roblox", tier: "standard", category: "roblox" },
            { id: "posture", tier: "standard", category: "firmware_boot" },
            { id: "browser_ext", tier: "full", category: "browser_scripts" },
          ],
        };
      }
      case "rule_meta":
        return {};
      case "time_fields":
        return {
          prefetch: ["last_run"],
          windows_service: ["collected_at", "event_at", "log_first", "log_last"],
          recycle_bin: ["deleted_at", "content_modified", "index_created"],
        };
      case "start_scan":
        startedTier = payload.tier;
        return true;
      case "cancel_scan":
        scanState = "cancelled";
        return null;
      case "scan_status":
        return {
          state: scanState,
          steps: [
            {
              done: 1,
              total: 3,
              collector: "roblox",
              state: "measured",
              reason: null,
              observations: 4,
              gaps: 0,
              found_rules: [RULE_ID],
              elapsed_ms: 120,
            },
          ],
          total: 3,
          started_at: "2026-10-15T12:00:00Z",
          message: null,
          tier: "standard",
          current: scanState === "running" ? "posture" : null,
          cancel_requested: false,
        };
      case "default_export_dir":
        return "C:\\Users\\x\\Documents\\B.O.P.E Scanner";
      case "pick_export_dir":
        return null;
      case "export_report":
        exportedWith = payload;
        return [
          { path: "C:\\Users\\x\\Documents\\B.O.P.E Scanner\\r.html", sha256: "ab".repeat(32) },
        ];
      case "code_link_qr":
        return `<?xml version="1.0" standalone="yes"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`;
      default:
        throw new Error(`unexpected command ${cmd}`);
    }
  }
}

afterEach(() => {
  cleanup();
  clearMocks();
  if (originalClipboardDescriptor) {
    Object.defineProperty(navigator, "clipboard", originalClipboardDescriptor);
  } else {
    // jsdom had no `navigator.clipboard` of its own before any test stubbed it.
    (navigator as { clipboard?: unknown }).clipboard = undefined;
  }
});

/** Goes through the start screen and the scan to the report, as a person does (ADR 0115). */
async function openReport(mode: "self" | "ss", tier: "standard" | "full" = "standard") {
  fireEvent.click(
    await screen.findByLabelText(
      mode === "ss" ? /Screenshare \(SS mode\)/ : /Only me \(self check\)/,
    ),
  );
  if (tier === "full") {
    fireEvent.click(screen.getByLabelText(/^Advanced/));
  }
  fireEvent.click(screen.getByLabelText("I have read what will be examined and I agree"));
  fireEvent.click(screen.getByText("Start the check"));
}

/** The side navigation's button for `page`, whatever the language. */
function nav(page: string): HTMLButtonElement {
  const button = document.querySelector<HTMLButtonElement>(`[data-page="${page}"]`);
  if (!button) {
    throw new Error(`no navigation entry ${page}`);
  }
  return button;
}

/** Opens `page` once the report it shows exists. */
async function goTo(page: string) {
  await waitFor(() => expect(nav(page).disabled).toBe(false));
  fireEvent.click(nav(page));
}

/** Goes through the scan to the report and opens `page` of it. */
async function openPage(mode: "self" | "ss", page: string, tier: "standard" | "full" = "standard") {
  await openReport(mode, tier);
  await screen.findByRole("region", { name: /What this scan lists|สิ่งที่การสแกนนี้แสดง/ });
  await goTo(page);
}

/** `iso` as the window shows it first, in the zone the tests run in. */
function shown(iso: string): string {
  const time = showTime(iso, "America/Sao_Paulo");
  if (!time) {
    throw new Error(`not a time: ${iso}`);
  }
  return timeLine(time, "local");
}

function stubClipboard(result: "ok" | "refused") {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (text: string) => {
        if (result === "refused") {
          return Promise.reject(new Error("refused"));
        }
        clipboardWrites.push(text);
        return Promise.resolve();
      },
    },
  });
}

const TITLE = "Secure Boot is turned off";
const THAI_TITLE = "Secure Boot ถูกปิดอยู่";

describe("App", () => {
  it("snapshots are the Rust pipeline output", () => {
    expect(selfView.mode).toBe("self");
    expect(ssView.mode).toBe("ss");
    expect(subject(selfView).rule_id).toBe(RULE_ID);
  });

  // B.O.P.E, ADR 0132: no banner across the window; the indication NOTICE section 7(c) asks for stays
  // in About and in the report's own facts.
  it("shows no UNOFFICIAL BUILD banner, and keeps the indication in About and the report facts", async () => {
    render(<App />);
    expect(await screen.findByText(selfView.header.provenance.version)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText(/UNOFFICIAL BUILD/)).toBeNull();
    fireEvent.click(nav("settings"));
    expect((await screen.findAllByText("UNOFFICIAL BUILD")).length).toBeGreaterThan(0);
    fireEvent.click(nav("scanner"));
    await openReport("self");
    expect(await screen.findByText("UNOFFICIAL BUILD")).toBeTruthy();
  });

  it("keeps every result page closed until a report exists", async () => {
    render(<App />);
    await screen.findByText("What will be examined");
    for (const page of ["overview", "evidence", "services", "recycle", "timeline", "reports"]) {
      expect(nav(page).disabled).toBe(true);
    }
    expect(nav("scanner").disabled).toBe(false);
    expect(nav("settings").disabled).toBe(false);
    await openReport("self");
    await waitFor(() => expect(nav("evidence").disabled).toBe(false));
  });

  // B.O.P.E, ADR 0123: the Roblox tool correlation has its own panel, with each tool's status, the
  // independent sources behind it, its traces on demand, and which sources could be read.
  it("shows the Roblox tools panel with status, sources and traces", async () => {
    const row = (fields: Record<string, unknown>) => ({ collector: "roblox_trace", fields });
    viewOverride = {
      ...snapshot("trace_ages_elevated_ss_view"),
      roblox_tools: {
        tools: [
          row({
            scope: "tool",
            tool_id: "fluxus",
            display: "Fluxus",
            status: "corroborated",
            families: "amcache, userassist",
            families_count: 2,
            classes: "execution, inventory",
            missing_now: true,
            first_seen: "2026-10-14T20:01:00Z",
            last_seen: "2026-10-14T22:40:00Z",
          }),
          row({
            scope: "tool",
            tool_id: "bloxstrap",
            display: "Bloxstrap",
            status: "info",
            common_legitimate: true,
            families: "file_listing",
            families_count: 1,
            classes: "current_file",
          }),
        ],
        hits: [
          row({
            scope: "hit",
            tool_id: "fluxus",
            source: "userassist",
            evidence_class: "execution",
            path: "C:\\Users\\<user>\\Downloads\\Fluxus\\Fluxus.exe",
            time: "2026-10-14T20:02:00Z",
            exists: false,
          }),
        ],
        sources: [
          row({ scope: "source", source: "prefetch", state: "not_measured", reason: "not_admin" }),
          row({ scope: "source", source: "amcache", state: "measured" }),
          row({ scope: "source", source: "srum", state: "measured" }),
          row({ scope: "source", source: "mft", state: "not_applicable", reason: "not_consented" }),
          row({ scope: "source", source: "wmi_subscription", state: "measured" }),
        ],
      },
    };
    render(<App />);
    await openPage("ss", "evidence");
    expect(await screen.findByRole("heading", { name: "Roblox tools" })).toBeTruthy();
    // A status is its word and its shape, never a colour alone.
    const corroborated = screen.getByText("CORROBORATED");
    expect(corroborated.querySelector("svg")).toBeTruthy();
    expect(screen.getByText("Fluxus")).toBeTruthy();
    expect(screen.getByText("Bloxstrap")).toBeTruthy();
    expect(screen.getByText("commonly used legitimately ·")).toBeTruthy();
    expect(screen.getByText("execution recorded; inventory (not proof of execution)")).toBeTruthy();
    // Times are shown once converted, in the zone, with the value received kept on the element.
    expect(screen.getAllByText(shown("2026-10-14T20:01:00Z")).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("Show the 1 traces"));
    expect(screen.getByText(/not at this path today/)).toBeTruthy();
    expect(document.querySelector('time[datetime="2026-10-14T20:02:00Z"]')).toBeTruthy();
    expect(screen.getByText("Sources the correlation could use")).toBeTruthy();
    expect(screen.getByText("(not_admin)")).toBeTruthy();
    expect(screen.getAllByText(/SRUM/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Master File Table/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/WMI/).length).toBeGreaterThan(0);
    expect(screen.getByText("(not_consented)")).toBeTruthy();
  });

  // ADR 0061: the SS view shows how far back each source reaches, beside the anchors; a source not
  // read without administrator rights is "not known", never "empty".
  it("shows the trace ages and the cross-source statement in SS mode", async () => {
    viewOverride = snapshot("trace_ages_elevated_ss_view");
    render(<App />);
    await openPage("ss", "timeline");
    expect(await screen.findByText("How far back the traces reach")).toBeTruthy();
    expect(screen.getByText(/beside when parts of this PC were set up/)).toBeTruthy();
    expect(
      screen.getByText(
        /Windows installed or last feature-upgraded \(InstallDate\): 2025-10-21, 72 days before this scan/,
      ),
    ).toBeTruthy();
    expect(screen.getByText(/Earliest installation date Windows Setup kept \(2 kept/)).toBeTruthy();
    expect(screen.getByText(/1 other logs: 1 hold records, 0 not read/)).toBeTruthy();
    expect(
      screen.getByText(/Windows removes Prefetch files itself\. \(not documented/),
    ).toBeTruthy();
    expect(screen.getByText("a clock that was changed")).toBeTruthy();
    expect(
      screen.getByText("FiveM on this PC, beside Windows' records of programs that ran"),
    ).toBeTruthy();
    expect(
      screen.getByText(
        /no entry for FiveM\.exe, GTA5\.exe, GTA5_Enhanced\.exe, PlayGTAV\.exe or FiveM_b…_GTAProcess\.exe\. It holds 1 entries; the oldest is from 2016-01-12/,
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "not read — Windows refused to open this. Whether it holds an entry is not known.",
      ),
    ).toBeTruthy();
    expect(screen.getByText(/This is not evidence of anything/)).toBeTruthy();
  });

  // ADR 0062: each edition's last session beside its own folders.
  it("shows each edition's session statement in SS mode", async () => {
    const statements = snapshot(
      "session_elevated_statements",
    ) as unknown as ReportView["cross_source"];
    viewOverride = { ...snapshot("trace_ages_elevated_ss_view"), cross_source: statements };
    render(<App />);
    await openPage("ss", "timeline");
    expect(
      await screen.findByText("FiveM for GTA V Legacy: its last session, beside its own folders"),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "began 2025-12-31T20:00:00Z (Prefetch, FiveM.exe); ended 2025-12-31T21:30:00Z (BAM); 2 hours before this scan",
      ),
    ).toBeTruthy();
    expect(screen.getByText("last written 36 hours before the session began")).toBeTruthy();
    expect(screen.getByText("Resource cache index (priv)")).toBeTruthy();
    expect(screen.getByText("not read: the folder could not be listed")).toBeTruthy();
    expect(screen.queryByText("Server cache")).toBeNull();
    expect(
      screen.getAllByText(
        "A time more than 10 minutes before the session began is shown as before it; any later time as after it.",
      ),
    ).toHaveLength(2);
  });

  it("says when FiveM last ran is not known, in Thai", async () => {
    const statements = snapshot(
      "session_limited_running_statements",
    ) as unknown as ReportView["cross_source"];
    viewOverride = { ...snapshot("trace_ages_elevated_ss_view"), cross_source: statements };
    await i18n.changeLanguage("th");
    render(<App />);
    await openPage("self", "timeline");
    expect(
      await screen.findByText("ยังรันอยู่ตั้งแต่ 2025-12-31T23:40:00Z (process ที่กำลังรัน, FiveM.exe)"),
    ).toBeTruthy();
    expect(
      screen.getByText(/^ไม่รู้ว่า FiveM รันครั้งล่าสุดเมื่อไร เพราะอ่าน Prefetch และ BAM ไม่ได้ \(/),
    ).toBeTruthy();
  });

  it("says a source not read without administrator rights is not known, in Thai too", async () => {
    const view = snapshot("trace_ages_elevated_ss_view");
    const ages = view.trace_ages;
    if (!ages) {
      throw new Error("the snapshot has no trace ages");
    }
    viewOverride = {
      ...view,
      cross_source: [],
      trace_ages: {
        ...ages,
        rows: ages.rows.map((row) =>
          row.collector === "prefetch"
            ? { collector: "prefetch", state: "unmeasured", reason: "not_admin" }
            : row,
        ),
      },
    };
    await i18n.changeLanguage("th");
    render(<App />);
    await openPage("self", "timeline");
    expect(await screen.findByText("ร่องรอยย้อนกลับไปได้ไกลแค่ไหน")).toBeTruthy();
    expect(screen.getByText("อ่านไม่ได้เพราะไม่มีสิทธิ์ผู้ดูแลระบบ — ไม่รู้")).toBeTruthy();
  });

  it("shows the timeline in SS mode with its note and the scan time, converted once", async () => {
    render(<App />);
    await openPage("ss", "timeline");
    expect(
      await screen.findByText(/An order of recorded times is not an order of events/),
    ).toBeTruthy();
    expect(screen.getByText("This scan ran")).toBeTruthy();
    const at = ssView.header.generated_at;
    const element = document.querySelector(`.timeline-list time[datetime="${at}"]`);
    expect(element?.textContent).toBe(shown(at));
    // UTC is the second reading, never a second conversion of the first.
    const utc = showTime(at, "America/Sao_Paulo")?.utc;
    expect(screen.getAllByText(`${utc} UTC`).length).toBeGreaterThan(0);
  });

  it("names the selector behind a selected time and its ordinary causes", async () => {
    viewOverride = {
      ...ssView,
      timeline: {
        entries: [
          {
            at: "2026-09-15T18:02:11Z",
            collector: "prefetch",
            field: "last_run",
            place: null,
            source: { kind: "selector", selector_id: "selector-id" },
            subject: "FIVEM.EXE",
          },
        ],
        bands: [],
        unmeasured: [{ collector: "usn", reason: "not_admin" }],
      },
    };
    extraTexts = {
      "selector-id": {
        title: "When Prefetch recorded a program named like FiveM or GTA V",
        description: "Puts a time on the timeline.",
        falsepositives: ["Any program of one of these names"],
        retention: "Only the Prefetch files still in the folder.",
        status: "experimental",
        files: { rule: "r", fixtures: "f", collector: "c", references: [] },
      },
    };
    render(<App />);
    await openPage("ss", "timeline");
    expect(await screen.findByText(/Windows Prefetch · FIVEM\.EXE/)).toBeTruthy();
    expect(
      screen.getAllByText(/When Prefetch recorded a program named like FiveM or GTA V/).length,
    ).toBe(2);
    expect(screen.getByText("Any program of one of these names")).toBeTruthy();
    expect(
      screen.getByText(
        "NTFS change journal: not measured — Windows would not show this without administrator rights",
      ),
    ).toBeTruthy();
    // Prefetch keeps a last run, not every run: the time is labelled and marked approximate.
    expect(screen.getAllByText("Execution").length).toBeGreaterThan(0);
    expect(screen.getAllByText("approximate").length).toBeGreaterThan(0);
  });

  // B.O.P.E, ADR 0132: the timeline orders the same input the same way every time, keeps two
  // entries of the same second apart, and its filters remove only what they name.
  it("orders the timeline deterministically and filters it by kind, certainty and date", async () => {
    const entry = (at: string, collector: string, field: string, subject: string) => ({
      at,
      collector,
      field,
      place: null,
      subject,
      source: { kind: "observation" as const },
    });
    viewOverride = {
      ...selfView,
      timeline: {
        entries: [
          entry("2026-10-10T12:00:00Z", "recycle_bin", "deleted_at", "b.txt"),
          entry("2026-10-10T12:00:00Z", "prefetch", "last_run", "A.EXE"),
          entry("2026-10-01T03:00:00Z", "roblox_files", "modified", "c.zip"),
          entry("2026-10-10T12:00:00Z", "prefetch", "last_run", "A.EXE"),
        ],
        bands: [],
        unmeasured: [],
      },
    };
    render(<App />);
    await openPage("self", "timeline");
    await screen.findByText("Times: 4");
    const subjects = () =>
      Array.from(document.querySelectorAll(".timeline-item")).map((li) => li.textContent ?? "");
    const first = subjects();
    expect(first[0]).toContain("c.zip");
    expect(first[1]).toContain("A.EXE");
    expect(first[2]).toContain("A.EXE");
    expect(first[3]).toContain("b.txt");
    // A file time can be set by any program, and is marked so.
    expect(first[0]).toContain("uncertain");
    fireEvent.change(screen.getByLabelText("Kind of time"), { target: { value: "deleted" } });
    expect(subjects()).toHaveLength(1);
    expect(subjects()[0]).toContain("b.txt");
    fireEvent.change(screen.getByLabelText("Kind of time"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Certainty"), { target: { value: "uncertain" } });
    expect(subjects()).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Certainty"), { target: { value: "" } });
    // 2026-10-01T03:00:00Z is 2026-10-01 00:00 in São Paulo: the date filter reads the shown zone.
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-02" } });
    expect(subjects()).toHaveLength(3);
  });

  it("says what will be examined and starts nothing without consent", async () => {
    render(<App />);
    expect(await screen.findByText("What will be examined")).toBeTruthy();
    expect(
      screen.getByText(/Prefetch, BAM, PCA, UserAssist, MuiCache, FeatureUsage and AppCompatCache/),
    ).toBeTruthy();
    expect(screen.getByText(/never history, cookies or passwords/)).toBeTruthy();
    expect(screen.getByText(/PcaSvc, DiagTrack, DPS, SysMain, EventLog/)).toBeTruthy();
    expect(screen.getByText(/never the deleted file itself/)).toBeTruthy();
    expect(screen.getByText("You may refuse: close the program and nothing is read.")).toBeTruthy();
    const start = screen.getByText("Start the check") as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    fireEvent.click(start);
    expect(calls).not.toContain("start_scan");
    expect(calls).not.toContain("report_view");
  });

  it("shows the scan's real progress — the module running, counts and time — and lets it be cancelled, with no report", async () => {
    scanState = "running";
    render(<App />);
    await openReport("ss");
    expect(await screen.findByText("1 of 3 modules (33%)", { exact: false })).toBeTruthy();
    expect(screen.getByText("read · 4 observations")).toBeTruthy();
    // The module running is the one Rust names, not one guessed from the order.
    expect(screen.getByText("running now")).toBeTruthy();
    expect(screen.getAllByText("Security settings of this PC").length).toBeGreaterThan(0);
    expect(screen.getByText("waiting")).toBeTruthy();
    expect(screen.getByText("To run").nextElementSibling?.textContent).toBe("2");
    expect(screen.getByText("Elapsed").nextElementSibling?.textContent).not.toBe("—");
    fireEvent.click(screen.getByText("Cancel the check"));
    expect(await screen.findByText("Check cancelled", {}, { timeout: 3000 })).toBeTruthy();
    expect(calls).toContain("cancel_scan");
    expect(calls).not.toContain("report_view");
  });

  it("starts an advanced scan only when it was chosen", async () => {
    render(<App />);
    await openPage("ss", "overview", "full");
    expect(startedTier).toBe("full");
  });

  it("shows the SS view with hidden counts after consent", async () => {
    render(<App />);
    await openPage("ss", "evidence");
    expect(await screen.findByText(TITLE)).toBeTruthy();
    expect(screen.getByText(/^Hidden in SS mode:/).textContent).toBe(
      `Hidden in SS mode: ${ssView.hidden.not_found} not found · ${ssView.hidden.unmeasured_expected} not measured (expected) · ${ssView.hidden.unmeasured_unexpected} not measured (not expected) · ${ssView.hidden.unmatched} unmatched observations`,
    );
    expect(calls).toContain("report_view");
  });

  it("shows the program version in the report facts, which the release notes ask people to check", async () => {
    render(<App />);
    await openReport("self");
    expect(await screen.findByText("Version")).toBeTruthy();
    expect(screen.getAllByText(selfView.header.provenance.version).length).toBeGreaterThan(0);
  });

  // One line of context, in both modes, with the caveat that stops a start days before the scan
  // being read as something the player did (ADR 0039).
  it.each([["self" as const], ["ss" as const]])(
    "shows when Windows started, with its caveat, in %s mode",
    async (mode) => {
      render(<App />);
      await openReport(mode);
      expect(await screen.findByText("Windows start")).toBeTruthy();
      expect(
        screen.getByText(`${shown("2025-12-28T21:56:56Z")}, 3d 2h 3m before this scan.`),
      ).toBeTruthy();
      expect(screen.getByText(/Not reset by "Shut down" with Fast Startup/)).toBeTruthy();
    },
  );

  it("shows when Windows started in Thai", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    await openReport("self");
    expect(await screen.findByText("Windows เริ่มทำงาน")).toBeTruthy();
    expect(
      screen.getByText(`${shown("2025-12-28T21:56:56Z")} (3 วัน 2 ชม. 3 นาที ก่อนการสแกนนี้)`),
    ).toBeTruthy();
  });

  it("shows an unmeasured boot time as a reason and no time", async () => {
    viewOverride = {
      ...selfView,
      header: { ...selfView.header, boot_time: { state: "unmeasured", reason: "not_windows" } },
    };
    render(<App />);
    await openReport("self");
    expect(await screen.findByText("not measured — not running on Windows")).toBeTruthy();
    expect(screen.queryByText(/before this scan/)).toBeNull();
  });

  it("offers the administrator restart before scanning when the program has no administrator rights", async () => {
    infoElevated = false;
    render(<App />);
    expect(await screen.findByText("Restart as administrator")).toBeTruthy();
    expect(screen.getByText("standard user — some sources will not be read")).toBeTruthy();
  });

  it("does not offer the administrator restart when the program already has those rights", async () => {
    render(<App />);
    // The version proves the facts arrived, so the button is absent by choice and not by timing.
    await screen.findByText(selfView.header.provenance.version);
    expect(screen.queryByText("Restart as administrator")).toBeNull();
  });

  it("does not offer the administrator restart before the program's facts have loaded", () => {
    infoElevated = false;
    render(<App />);
    expect(screen.queryByText("Restart as administrator")).toBeNull();
  });

  it("switches to Thai, keeping the UNOFFICIAL BUILD token in English", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    await openPage("self", "evidence");
    expect(await screen.findByText(THAI_TITLE)).toBeTruthy();
    fireEvent.click(nav("settings"));
    expect((await screen.findAllByText("UNOFFICIAL BUILD")).length).toBeGreaterThan(0);
  });

  it("lists what the tool itself left, apart from the evidence", async () => {
    viewOverride = {
      ...selfView,
      own_traces: [
        {
          collector: "process",
          observation: {
            collector: "process",
            fields: {
              name: "aeterna-rongroi.exe",
              path: "%USERPROFILE%\\Downloads\\aeterna-rongroi.exe",
            },
          },
        },
      ],
    };
    render(<App />);
    await openPage("self", "evidence");
    const section = await screen.findByRole("region", { name: "Own traces (excluded)" });
    expect(section.textContent).toContain("aeterna-rongroi.exe");
    expect(screen.getByText(TITLE)).toBeTruthy();
  });

  it("lists what the collectors saw that no rule matched, apart from the evidence", async () => {
    viewOverride = {
      ...selfView,
      unmatched: [
        {
          collector: "fivem_dir",
          observations: [
            {
              collector: "fivem_dir",
              fields: {
                location: "plugins",
                path: "C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.app\\plugins\\overlay.dll",
              },
            },
          ],
        },
      ],
    };
    render(<App />);
    await openPage("self", "evidence");
    const section = await screen.findByRole("region", { name: "Unmatched observations" });
    expect(section.textContent).toContain("overlay.dll");
    expect(screen.getByText(TITLE)).toBeTruthy();
  });

  it("shows no unmatched section when every observation matched a rule", async () => {
    viewOverride = { ...selfView, unmatched: [] };
    render(<App />);
    await openPage("self", "evidence");
    await screen.findByText(TITLE);
    expect(screen.queryByRole("region", { name: "Unmatched observations" })).toBeNull();
  });

  // A match shown without what else produces it is a match shown as an accusation (ADR 0027).
  it("shows a found entry's description and its false positives in the side panel", async () => {
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    const panel = await screen.findByRole("complementary", { name: TITLE });
    expect(panel.textContent).toContain(`About this check: ${ENGLISH_DESCRIPTION}`);
    expect(screen.getByText("Ordinary things that also produce this:")).toBeTruthy();
    expect(screen.getByText(ENGLISH_FALSEPOSITIVE)).toBeTruthy();
    // The raw JSON is there, folded, for whoever wants it.
    expect(screen.getByText("Raw data (JSON)").closest("details")?.open).toBe(false);
  });

  it("shows a found entry's description and its false positives in Thai", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(THAI_TITLE));
    expect(await screen.findByText(`เกี่ยวกับการตรวจนี้: ${THAI_DESCRIPTION}`)).toBeTruthy();
    expect(screen.getByText("เรื่องปกติที่ทำให้เกิดผลแบบนี้ได้เหมือนกัน:")).toBeTruthy();
    expect(screen.getByText(THAI_FALSEPOSITIVE)).toBeTruthy();
  });

  it("shows the description but no false positives beside a not-found entry", async () => {
    const first = subject(selfView);
    viewOverride = {
      ...selfView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "not_found",
          retention: ENGLISH_RETENTION,
        },
      ],
    };
    render(<App />);
    await openPage("self", "evidence");
    const title = await screen.findByText(TITLE);
    // A row starts closed: nothing about it until it is chosen.
    expect(title.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText(`About this check: ${ENGLISH_DESCRIPTION}`)).toBeNull();
    fireEvent.click(title);
    expect(title.getAttribute("aria-expanded")).toBe("true");
    expect(await screen.findByText(`About this check: ${ENGLISH_DESCRIPTION}`)).toBeTruthy();
    expect(screen.queryByText("Ordinary things that also produce this:")).toBeNull();
    expect(screen.getByText(`Look-back: ${ENGLISH_RETENTION}`)).toBeTruthy();
  });

  it("lists the unmeasured result its rule did not expect and counts the one it did", async () => {
    const first = subject(selfView);
    viewOverride = {
      ...ssView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "unmeasured",
          reason: "read_failed",
          expected: false,
        },
      ],
      hidden: { ...ssView.hidden, unmeasured_expected: 3 },
    };
    render(<App />);
    await openPage("ss", "evidence");
    expect(await screen.findByText("Not measured (not expected)")).toBeTruthy();
    expect(screen.getByText(/^Hidden in SS mode:/).textContent).toContain(
      "3 not measured (expected)",
    );
  });

  // One fact about the scan that applies to every rule at once, stated once (ADR 0012, ADR 0027).
  it("states missing administrator rights once, on the overview", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 2, not_attempted: 0 } };
    render(<App />);
    await openReport("self");
    const statements = await screen.findAllByText(/could not be answered because this scan/);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.textContent).toContain("2 check(s)");
  });

  it("states the sources it never reached once, on the overview", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 0, not_attempted: 3 } };
    render(<App />);
    await openReport("self");
    const statements = await screen.findAllByText(/this program stopped reading before/);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.textContent).toContain("3 check(s)");
    expect(statements[0]?.textContent).toContain("not a finding about this PC");
  });

  // Each reason reaches a reader as a sentence, never as its identifier (ADR 0030).
  it.each([
    ["not_on_this_os", "this version of Windows does not keep this record"],
    ["not_attempted", "the scan stopped before reaching it"],
    ["service_disabled", "the Windows service that writes this record is switched off"],
    ["source_absent", "this PC has no such record to read"],
    ["source_empty", "the place this is kept is there and holds nothing"],
    ["partial", "part of this was read and part of it was not"],
    ["budget_spent", "this program stopped reading before it finished"],
    ["not_consented", "only a full scan reads this, and this was the standard scan"],
    ["other_volume", "this is on another drive, and this program reads only the system drive"],
  ])("shows %s as a sentence a non-expert reads", async (reason, sentence) => {
    const first = subject(selfView);
    viewOverride = {
      ...selfView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "unmeasured",
          reason: reason as UnmeasuredReason,
          expected: false,
        },
      ],
      timeline: { ...selfView.timeline, unmeasured: [] },
      trace_ages: undefined,
    };
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    expect(await screen.findByText(new RegExp(sentence))).toBeTruthy();
  });

  // A count the change journal gives is for the span it still held (ADR 0047, amendment of 2026-09-30).
  it.each([
    [
      { state: "span", from: "2026-09-30T10:24:00Z", to: "2026-09-30T11:03:00Z" },
      /held only 2026-09-30T10:24:00Z to 2026-09-30T11:03:00Z/,
    ],
    [{ state: "no_span" }, /so there is no span/],
  ] as const)("shows the span a row's count is for (%o)", async (band, sentence) => {
    const first = subject(selfView);
    viewOverride = {
      ...selfView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "found",
          observations: [],
        },
      ],
      row_bands: { [first.rule_id]: band },
    };
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    expect(await screen.findByText(sentence)).toBeTruthy();
  });

  it("states the checks only a full scan answers once, on the overview", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 0, not_attempted: 0, not_consented: 1 } };
    render(<App />);
    await openReport("self");
    const statements = await screen.findAllByText(/read only in a full scan/);
    expect(statements).toHaveLength(1);
    expect(statements[0]?.textContent).toContain("1 check(s)");
  });

  it("offers the website-name choice only for an advanced SS check, and passes the answer to the view", async () => {
    const seen: unknown[] = [];
    render(<App />);
    fireEvent.click(await screen.findByLabelText(/Screenshare \(SS mode\)/));
    expect(screen.queryByRole("checkbox", { name: /website names/ })).toBeNull();
    fireEvent.click(screen.getByLabelText(/^Advanced/));
    const toggle = screen.getByRole("checkbox", { name: /website names/ }) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    fireEvent.click(toggle);
    fireEvent.click(screen.getByLabelText("I have read what will be examined and I agree"));
    const answer = mockIPCAnswer;
    mockIPC((cmd, args) => {
      if (cmd === "report_view") {
        seen.push((args as Record<string, unknown>).options);
      }
      return answer(cmd, args);
    });
    fireEvent.click(screen.getByText("Start the check"));
    await screen.findByRole("region", { name: "What this scan lists" });
    expect(seen).toContainEqual({
      server_identity: false,
      account_identifier: false,
      download_host: true,
    });
  });

  it("saves the report where the person chose, and shows each file's SHA-256", async () => {
    render(<App />);
    await openPage("ss", "reports");
    fireEvent.click(await screen.findByText("Save report"));
    expect(await screen.findByText("ab".repeat(32))).toBeTruthy();
    expect(exportedWith?.mode).toBe("ss");
    expect(exportedWith?.formats).toEqual(["html", "json", "txt", "pdf"]);
    expect(screen.getByText(/does not prove the scan was honest/)).toBeTruthy();
    expect(screen.getByText(/America\/Sao_Paulo/)).toBeTruthy();
    expect(exportedWith?.timeZone).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);
  });

  it("states nothing about administrator rights when every check was answerable", async () => {
    viewOverride = { ...selfView, scope: { not_admin: 0, not_attempted: 0 } };
    render(<App />);
    await openReport("self");
    await screen.findByRole("region", { name: "What this scan lists" });
    expect(screen.queryByText(/could not be answered because this scan/)).toBeNull();
  });

  it("shows the look-back note of not-found evidence in the chosen language", async () => {
    const first = subject(selfView);
    viewOverride = {
      ...selfView,
      evidence: [
        {
          rule_id: first.rule_id,
          collector: first.collector,
          strength: first.strength,
          state: "not_found",
          retention: ENGLISH_RETENTION,
        },
      ],
    };
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(THAI_TITLE));
    expect(await screen.findByText(`ย้อนดูได้: ${THAI_RETENTION}`)).toBeTruthy();
    // Only the folded raw data carries the English source the evidence keeps.
    expect(screen.queryByText(ENGLISH_RETENTION, { exact: false, ignore: "pre" })).toBeNull();
  });

  // Three counts of states and the sentence that no report proves a PC clean; never one number.
  it("lists how many rows are in each state, beside the sentence that it proves nothing clean", async () => {
    render(<App />);
    await openReport("self");
    const summary = await screen.findByRole("region", { name: "What this scan lists" });
    const buttons = Array.from(summary.querySelectorAll("button"));
    expect(buttons.map((b) => b.textContent)).toEqual([
      `${selfView.listed.found} found — each one lists ordinary things that also produce it`,
      `${selfView.listed.not_found} not found — each row says how far back it can see`,
      `${selfView.listed.unmeasured} not measured — each row says why`,
    ]);
    expect(
      screen.getByRole("button", {
        name: `${selfView.listed.found} found — each one lists ordinary things that also produce it`,
      }),
    ).toBeTruthy();
    expect(summary.textContent).toContain("This report cannot prove that a PC is clean");
  });

  it("opens the evidence filtered to one state from its count, and clears it", async () => {
    render(<App />);
    await openReport("self");
    const summary = await screen.findByRole("region", { name: "What this scan lists" });
    fireEvent.click(summary.querySelector("button") as HTMLElement);
    expect(await screen.findByText(TITLE)).toBeTruthy();
    const state = screen.getByLabelText("State") as HTMLSelectElement;
    expect(state.value).toBe("found");
    expect(document.querySelectorAll(".evidence-table tbody tr:not(.group-title)").length).toBe(
      selfView.listed.found,
    );
    fireEvent.click(screen.getByText("Show every state"));
    expect(state.value).toBe("");
    expect(document.querySelectorAll(".evidence-table tbody tr:not(.group-title)").length).toBe(
      selfView.evidence.length,
    );
  });

  // A count of 0 is a filter like the others; choosing it must not leave an empty page.
  it("says so when the chosen state has no row", async () => {
    viewOverride = {
      ...selfView,
      evidence: selfView.evidence.filter((item) => item.state !== "unmeasured"),
      listed: { ...selfView.listed, unmeasured: 0 },
    };
    render(<App />);
    await openPage("self", "evidence");
    const summary = await screen.findByRole("region", { name: "What this scan lists" });
    expect(screen.queryByText("No row in this scan is in this state.")).toBeNull();
    fireEvent.click(summary.querySelectorAll("button")[2] as HTMLElement);
    expect(screen.getByText("No row in this scan is in this state.")).toBeTruthy();
    expect(screen.queryByText("No evidence to show.")).toBeNull();
    fireEvent.click(screen.getByText("Show every state"));
    expect(screen.queryByText("No row in this scan is in this state.")).toBeNull();
  });

  it("finds rows by text and says how many it shows", async () => {
    render(<App />);
    await openPage("self", "evidence");
    await screen.findByText(TITLE);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "secure boot" } });
    expect(screen.getByText(TITLE)).toBeTruthy();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "nothing-matches-this" } });
    expect(screen.queryByText(TITLE)).toBeNull();
    expect(screen.getByText("No row in this scan is in this state.")).toBeTruthy();
    expect(screen.getByText(`0 of ${selfView.evidence.length} shown`)).toBeTruthy();
  });

  // Two copies of one program running are two identical observations (ADR 0010).
  it("lists two identical observations twice, without a repeated key", async () => {
    const twin = {
      collector: "process",
      fields: { name: "FiveM.exe", path: "C:\\Users\\a\\AppData\\Local\\FiveM\\FiveM.exe" },
    };
    viewOverride = {
      ...selfView,
      unmatched: [{ collector: "process", observations: [twin, twin] }],
    };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      render(<App />);
      await openPage("self", "evidence");
      const section = await screen.findByRole("region", { name: "Unmatched observations" });
      expect(section.querySelectorAll(".observations > li").length).toBe(2);
      expect(section.textContent?.split("name=FiveM.exe").length).toBe(3);
      const keyWarnings = errors.mock.calls.filter((call) =>
        call.some((part) => String(part).includes("same key")),
      );
      expect(keyWarnings).toEqual([]);
    } finally {
      errors.mockRestore();
    }
  });

  it("groups rows under a plain name for their collector", async () => {
    render(<App />);
    await act(async () => {
      await i18n.changeLanguage("th");
    });
    await openPage("self", "evidence");
    expect(await screen.findByText(/^การตั้งค่าความปลอดภัยของเครื่อง · \d+$/)).toBeTruthy();
  });

  it("shows the rule and its files at this build's commit in the side panel", async () => {
    linksOverride = {
      repository: REPOSITORY,
      code: `${REPOSITORY}/tree/${COMMIT}`,
      commit: COMMIT,
    };
    stubClipboard("ok");
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    expect(screen.getAllByText(RULE_ID).length).toBeGreaterThan(0);
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    const copy = rulePath.parentElement?.querySelector("button");
    if (!copy) throw new Error("no copy button");
    await act(async () => {
      fireEvent.click(copy);
    });
    expect(clipboardWrites).toEqual([
      `${REPOSITORY}/blob/${COMMIT}/rules/posture/boot/secure-boot-disabled/rule.yaml`,
    ]);
    expect(copy.textContent).toBe("Copied");
  });

  it("shows no file links for an unofficial build and says why", async () => {
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(screen.getAllByText(/This build is not official/).length).toBeGreaterThan(0);
  });

  it("says the commit is not known, not that the build is unofficial, for an official build without one", async () => {
    const official = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: null },
    };
    headerOverride = official;
    viewOverride = { ...selfView, header: official };
    linksOverride = { repository: REPOSITORY, code: REPOSITORY, commit: null };
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(
      (await screen.findAllByText(/The commit this program was built from is not known\./)).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/This build is not official/)).toBeNull();
  });

  // Carried fix (b): before `codeLinks()` has arrived, the report does not know whether this build is
  // official, so it must not say either thing about the commit.
  it("says nothing about the build's commit before the code links resolve", async () => {
    linksNeverResolve = true;
    render(<App />);
    await openPage("self", "evidence");
    fireEvent.click(await screen.findByText(TITLE));
    const rulePath = await screen.findByText("rules/posture/boot/secure-boot-disabled/rule.yaml");
    expect(rulePath.parentElement?.querySelector("button")).toBeNull();
    expect(screen.queryByText(/This build is not official/)).toBeNull();
    expect(screen.queryByText(/At the commit this program was built from/)).toBeNull();
  });

  it("opens About from the start screen, with the repository, its QR code, credits and licence", async () => {
    stubClipboard("ok");
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    expect(await screen.findByText("About this program and its code")).toBeTruthy();
    expect(screen.getByText(REPOSITORY)).toBeTruthy();
    const qr = await screen.findByAltText(`QR code for ${REPOSITORY}`);
    expect(qr.getAttribute("src")).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
    expect(screen.getByText(/The code this build was made from is not known/)).toBeTruthy();
    expect(screen.getByText("aeterna-rongroi's own code sends nothing anywhere.")).toBeTruthy();
    expect(screen.getByText(/is a modified version of aeterna-rongroi 0\.9\.0/)).toBeTruthy();
    expect(
      screen.getByText(/GPL-3\.0-or-later\. Rules and rule translations: CC-BY-SA-4\.0/),
    ).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getAllByText("Copy link")[0] as HTMLElement);
    });
    expect(clipboardWrites).toEqual([REPOSITORY]);
  });

  it("links the commit of an official build and the attestation command for its file", async () => {
    headerOverride = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: COMMIT },
    };
    linksOverride = {
      repository: REPOSITORY,
      code: `${REPOSITORY}/tree/${COMMIT}`,
      commit: COMMIT,
    };
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    expect(await screen.findByText(`${REPOSITORY}/tree/${COMMIT}`)).toBeTruthy();
    expect(
      screen.getByText(
        `gh attestation verify aeterna-rongroi-${selfView.header.provenance.version}-windows-x64.exe -R aeterna/aeterna-rongroi`,
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/The code this build was made from is not known/)).toBeNull();
  });

  it("says on About that an official build's commit is not known, without calling it unofficial", async () => {
    headerOverride = {
      ...selfView.header,
      provenance: { ...selfView.header.provenance, official: true, commit: null },
    };
    linksOverride = { repository: REPOSITORY, code: REPOSITORY, commit: null };
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    expect(
      await screen.findByText("The commit this build was made from is not known."),
    ).toBeTruthy();
    expect(screen.queryByText(/not built by the release workflow/)).toBeNull();
  });

  // Moving between pages never leaves the report or asks for consent again.
  it("returns from About to the same SS report without asking again", async () => {
    render(<App />);
    await openPage("ss", "evidence");
    expect(await screen.findByText(TITLE)).toBeTruthy();
    fireEvent.click(nav("settings"));
    expect(await screen.findByText("About this program and its code")).toBeTruthy();
    fireEvent.click(nav("evidence"));
    expect(await screen.findByText(TITLE)).toBeTruthy();
    expect(screen.getByText(/^Hidden in SS mode:/)).toBeTruthy();
    expect(screen.queryByText("What will be examined")).toBeNull();
    expect(calls.filter((cmd) => cmd === "start_scan")).toHaveLength(1);
  });

  it("asks for the header once, whether or not About is opened", async () => {
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    await screen.findByText(REPOSITORY);
    expect(calls.filter((cmd) => cmd === "app_info")).toEqual(["app_info"]);
  });

  it("says on About that its details could not be read, and the start screen is still there", async () => {
    linksFail = true;
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    expect(
      await screen.findByText("What this page shows could not be read from the program."),
    ).toBeTruthy();
    fireEvent.click(nav("scanner"));
    expect(await screen.findByText("What will be examined")).toBeTruthy();
  });

  it("says on About that its details could not be read when the header was refused", async () => {
    headerFails = true;
    render(<App />);
    fireEvent.click(nav("settings"));
    expect(
      await screen.findByText("What this page shows could not be read from the program."),
    ).toBeTruthy();
  });

  it("offers to copy again after saying Copied", async () => {
    stubClipboard("ok");
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    await screen.findByText(REPOSITORY);
    vi.useFakeTimers();
    try {
      await act(async () => {
        fireEvent.click(screen.getAllByText("Copy link")[0] as HTMLElement);
      });
      expect(screen.getByText("Copied")).toBeTruthy();
      act(() => {
        vi.advanceTimersByTime(COPIED_FOR_MS - 1);
      });
      expect(screen.getByText("Copied")).toBeTruthy();
      act(() => {
        vi.advanceTimersByTime(1);
      });
      expect(screen.queryByText("Copied")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("says a refused copy and leaves the text to select", async () => {
    stubClipboard("refused");
    render(<App />);
    await screen.findByText(selfView.header.provenance.version);
    fireEvent.click(nav("settings"));
    await screen.findByText(REPOSITORY);
    await act(async () => {
      fireEvent.click(screen.getAllByText("Copy link")[0] as HTMLElement);
    });
    expect(screen.getByText("Could not copy — select the text instead")).toBeTruthy();
  });

  it("switches the first reading of every time to UTC and keeps the choice", async () => {
    render(<App />);
    await openReport("self");
    const at = selfView.header.generated_at;
    await screen.findByRole("region", { name: "What this scan lists" });
    fireEvent.click(nav("settings"));
    fireEvent.click(screen.getByLabelText(/UTC first/));
    fireEvent.click(nav("overview"));
    const utc = showTime(at, "UTC")?.utc;
    const element = await screen.findAllByText(`${utc} UTC`);
    expect(element.length).toBeGreaterThan(0);
    expect(window.localStorage.getItem("bope.timeDisplay")).toBe("utc");
    window.localStorage.removeItem("bope.timeDisplay");
  });
});
