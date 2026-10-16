// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The services and Recycle Bin pages over synthetic observations shaped as the Rust collectors emit
// them (`windows_service`, `recycle_bin`); nothing here comes from a real PC.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import i18n, { initI18n } from "../../i18n";
import { showTime } from "../../time";
import type { Observation, ReportView } from "../../types";
import { TimeSettingsContext, timeLine } from "../../ui/TimeValue";
import { RecycleBinPage } from "./RecycleBinPage";
import { ServicesPage } from "./ServicesPage";

const raw = readFileSync(
  resolve(
    process.cwd(),
    "../../crates/bope-collectors/tests/snapshots/report_snapshot__secure_boot_off_self_view.snap",
  ),
  "utf8",
);
const base = JSON.parse(
  raw.replace(/\r\n/g, "\n").split("\n---\n").slice(1).join("\n---\n"),
) as ReportView;

const ZONE = "America/Sao_Paulo";
const shown = (iso: string) => {
  const time = showTime(iso, ZONE);
  if (!time) throw new Error(iso);
  return timeLine(time, "local");
};

const service = (fields: Record<string, unknown>): Observation => ({
  collector: "windows_service",
  fields: { scope: "current", ...fields },
});

const history = (fields: Record<string, unknown>): Observation => ({
  collector: "windows_service",
  fields: { scope: "history", matched_by: "service_name", ...fields },
});

function renderWith(page: ReactElement) {
  return render(
    <TimeSettingsContext.Provider value={{ display: "local", zone: ZONE }}>
      {page}
    </TimeSettingsContext.Provider>,
  );
}

beforeAll(async () => {
  await initI18n("en");
  await i18n.changeLanguage("en");
});

afterEach(cleanup);

describe("Windows services page", () => {
  const collected = "2026-10-16T13:00:00Z";
  const view: ReportView = {
    ...base,
    services: [
      service({
        service: "PcaSvc",
        query: "ok",
        exists: true,
        state: "running",
        pid: 1200,
        config_query: "ok",
        start_type: "manual",
        disabled: false,
        display_name: "Program Compatibility Assistant Service",
        account: "LocalSystem",
        binary_path: "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
        collected_at: collected,
      }),
      service({
        service: "DiagTrack",
        query: "ok",
        exists: true,
        state: "stopped",
        config_query: "ok",
        start_type: "disabled",
        disabled: true,
        collected_at: collected,
      }),
      service({
        service: "DPS",
        query: "ok",
        exists: true,
        state: "start_pending",
        pid: 800,
        config_query: "access_denied",
        collected_at: collected,
      }),
      service({ service: "SysMain", query: "not_installed", exists: false }),
      service({ service: "EventLog", query: "access_denied" }),
      history({
        event: "log_span",
        service: "*",
        log_first: "2026-09-01T00:00:00Z",
        log_last: "2026-10-16T12:59:00Z",
      }),
      history({
        service: "SysMain",
        event: "state_change",
        event_id: 7036,
        record_id: 41,
        event_at: "2026-10-15T22:10:05Z",
        state_text: "stopped",
        state: "stopped",
      }),
      history({
        service: "DiagTrack",
        event: "start_type_change",
        event_id: 7040,
        record_id: 42,
        event_at: "2026-10-16T01:00:00Z",
        start_type_text: "auto start → disabled",
        start_type: "disabled",
      }),
    ],
    timeline: { ...base.timeline, unmeasured: [] },
  };

  it("states each service's current state with its word and shape, never as a finding", () => {
    renderWith(<ServicesPage view={view} />);
    expect(screen.getByText(/is not, on its own, a sign of cheating/)).toBeTruthy();
    const stopped = screen.getAllByText("Stopped")[0] as HTMLElement;
    expect(stopped.closest(".badge")?.className).toContain("tone-neutral");
    expect(stopped.querySelector("svg")).toBeTruthy();
    expect(document.querySelector(".tone-flag")).toBeNull();
    expect(document.querySelector(".tone-warn")).toBeNull();
    expect(screen.getByText("Running")).toBeTruthy();
    expect(screen.getByText("Starting")).toBeTruthy();
    expect(screen.getByText("Not installed")).toBeTruthy();
    // EventLog refused the status query; DPS answered it but refused its configuration.
    const denied = screen.getAllByText("Access denied");
    expect(denied).toHaveLength(2);
    expect(
      denied.some((node) => node.closest(".badge")?.className.includes("tone-unmeasured")),
    ).toBe(true);
    expect(screen.getByText("disabled")).toBeTruthy();
    expect(screen.getByText("1200")).toBeTruthy();
    expect(screen.getByText("LocalSystem")).toBeTruthy();
    expect(
      screen.getByText("C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p"),
    ).toBeTruthy();
    // When the manager was asked, typed as a collection time.
    expect(screen.getAllByText(shown(collected)).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Collected").length).toBeGreaterThan(0);
  });

  it("keeps the history apart, newest first, with each event's own time and record", () => {
    renderWith(<ServicesPage view={view} />);
    expect(screen.getByText("History in the System log")).toBeTruthy();
    const rows = Array.from(
      document.querySelectorAll('[aria-labelledby="services-history-title"] tbody tr'),
    ).map((row) => row.textContent ?? "");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain("DiagTrack");
    expect(rows[0]).toContain("Start type change");
    expect(rows[0]).toContain("auto start → disabled");
    expect(rows[1]).toContain("SysMain");
    expect(rows[1]).toContain(shown("2026-10-15T22:10:05Z"));
    expect(rows[1]).toContain("7036 · #41");
    expect(screen.getByText(/The System log covers/)).toBeTruthy();
    fireEvent.change(screen.getAllByLabelText("Service")[0] as HTMLElement, {
      target: { value: "SysMain" },
    });
    expect(
      document.querySelectorAll('[aria-labelledby="services-history-title"] tbody tr'),
    ).toHaveLength(1);
  });

  it("says when the log holds no event, and when it could not be read", () => {
    const quiet: ReportView = {
      ...view,
      services: (view.services ?? []).filter(
        (o) => o.fields.event !== "state_change" && o.fields.event !== "start_type_change",
      ),
    };
    renderWith(<ServicesPage view={quiet} />);
    expect(screen.getByText("The System log holds no event of these services.")).toBeTruthy();
    cleanup();
    const unread: ReportView = {
      ...view,
      services: (view.services ?? []).filter((o) => o.fields.scope === "current"),
      timeline: {
        ...view.timeline,
        unmeasured: [{ collector: "windows_service", place: "history", reason: "not_admin" }],
      },
    };
    renderWith(<ServicesPage view={unread} />);
    expect(screen.getByText(/The history could not be read:/)).toBeTruthy();
    expect(screen.queryByText("The System log holds no event of these services.")).toBeNull();
  });

  it("says the services were not read, with the reason, when nothing was", () => {
    renderWith(
      <ServicesPage
        view={{
          ...view,
          services: [],
          timeline: {
            ...view.timeline,
            unmeasured: [{ collector: "windows_service", reason: "not_windows" }],
          },
        }}
      />,
    );
    expect(screen.getByText("The services could not be read.")).toBeTruthy();
    expect(screen.getByText("not running on Windows")).toBeTruthy();
  });
});

describe("Recycle Bin page", () => {
  const item = (fields: Record<string, unknown>): Observation => ({
    collector: "recycle_bin",
    fields: { scope: "item", drive: "C:", ...fields },
  });
  const view: ReportView = {
    ...base,
    recycle_bin: [
      {
        collector: "recycle_bin",
        fields: {
          scope: "bin",
          drive: "C:",
          folder_created: "2023-01-01T00:00:00Z",
          folder_modified: "2026-10-10T12:00:00Z",
          index_entries: 2,
          content_entries: 2,
          orphan_index: 1,
          orphan_content: 1,
          unreadable_index: 0,
          read_capped: false,
          newest_deleted_at: "2026-10-09T08:00:00Z",
          oldest_deleted_at: "2026-06-01T00:00:00Z",
          last_artifact_change: "2026-10-10T12:00:00Z",
          last_artifact_change_source: "folder",
        },
      },
      item({
        index_file: "$IAB12CD.exe",
        path: "C:\\Users\\a\\Downloads\\Solara.exe",
        name: "Solara.exe",
        size: 4096,
        deleted_at: "2026-10-09T08:00:00Z",
        index_created: "2026-10-09T08:00:00Z",
        index_modified: "2026-10-09T08:00:00Z",
        content_present: true,
        content_is_folder: false,
        content_modified: "2026-10-08T20:00:00Z",
        tool_id: "solara",
        tool_kind: "executor",
        match_kind: "exact",
      }),
      item({
        index_file: "$IZZ99.txt",
        path: "C:\\Users\\a\\Documents\\notes.txt",
        name: "notes.txt",
        size: 12,
        deleted_at: "2026-06-01T00:00:00Z",
        content_present: false,
      }),
    ],
  };

  it("answers when the bin was modified with the last modification observed, and where", () => {
    renderWith(<RecycleBinPage view={view} />);
    expect(
      screen.getAllByText("Last modification observed in the artifact").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("Observed on the bin folder's own write time")).toBeTruthy();
    expect(screen.getByText(/There is no single "modified at" for the Recycle Bin/)).toBeTruthy();
    expect(screen.getAllByText(shown("2026-10-10T12:00:00Z")).length).toBeGreaterThan(0);
    expect(screen.getAllByText(shown("2026-10-09T08:00:00Z")).length).toBeGreaterThan(0);
    expect(screen.getByText("1 $I without $R · 1 $R without $I")).toBeTruthy();
    expect(screen.getByText(/Nothing is restored, moved or removed/)).toBeTruthy();
  });

  it("keeps each item's own times apart and says when the $R is gone", () => {
    renderWith(<RecycleBinPage view={view} />);
    const rows = Array.from(
      document.querySelectorAll('[aria-labelledby="recycle-items-title"] tbody tr'),
    );
    expect(rows).toHaveLength(2);
    // Newest deletion first.
    expect(rows[0]?.textContent).toContain("Solara.exe");
    expect(rows[0]?.textContent).toContain(shown("2026-10-08T20:00:00Z"));
    expect(rows[0]?.textContent).toContain("Catalog: solara");
    expect(rows[1]?.textContent).toContain("notes.txt");
    expect(rows[1]?.textContent).toContain("No $R");
    fireEvent.change(screen.getByLabelText("Show"), { target: { value: "catalog" } });
    expect(
      document.querySelectorAll('[aria-labelledby="recycle-items-title"] tbody tr'),
    ).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Show"), { target: { value: "no_content" } });
    expect(
      document.querySelectorAll('[aria-labelledby="recycle-items-title"] tbody tr')[0]?.textContent,
    ).toContain("notes.txt");
  });

  it("says the bin was not read, with the reason, and invents no time", () => {
    renderWith(
      <RecycleBinPage
        view={{
          ...view,
          recycle_bin: [],
          timeline: {
            ...view.timeline,
            unmeasured: [{ collector: "recycle_bin", reason: "source_absent" }],
          },
        }}
      />,
    );
    expect(screen.getByText("The Recycle Bin could not be read.")).toBeTruthy();
    expect(screen.getByText("this PC has no such record to read")).toBeTruthy();
    expect(document.querySelector("time")).toBeNull();
  });
});
