// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

import { describe, expect, it } from "vitest";
import {
  compareInstants,
  formatDuration,
  offsetOf,
  parseInstant,
  secondsBetween,
  showTime,
  timeCertainty,
  timeKind,
} from "./time";

describe("time", () => {
  it("shows a UTC value in UTC and in the zone, as DD/MM/AAAA HH:mm:ss, keeping the value received", () => {
    const shown = showTime("2026-10-16T13:05:09Z", "America/Sao_Paulo");
    expect(shown).toEqual({
      iso: "2026-10-16T13:05:09Z",
      utc: "16/10/2026 13:05:09",
      local: "16/10/2026 10:05:09",
      offset: "UTC−03:00",
      zone: "America/Sao_Paulo",
      fraction: 0,
    });
  });

  it("crosses midnight and a positive offset", () => {
    const shown = showTime("2026-01-31T20:30:00Z", "Asia/Bangkok");
    expect(shown?.local).toBe("01/02/2026 03:30:00");
    expect(shown?.offset).toBe("UTC+07:00");
  });

  it("reads an offset other than Z as the same instant", () => {
    expect(showTime("2026-10-16T10:05:09-03:00", "UTC")?.local).toBe("16/10/2026 13:05:09");
    expect(compareInstants("2026-10-16T10:05:09-03:00", "2026-10-16T13:05:09Z")).not.toBe(0);
    expect(secondsBetween("2026-10-16T10:05:09-03:00", "2026-10-16T13:05:09Z")).toBe(0);
  });

  it("applies daylight saving time of the instant, not of today", () => {
    expect(offsetOf(new Date("2026-07-01T12:00:00Z"), "Europe/Lisbon")).toBe("UTC+01:00");
    expect(offsetOf(new Date("2026-01-01T12:00:00Z"), "Europe/Lisbon")).toBe("UTC+00:00");
  });

  it("is never applied twice: a shown value is not a time it reads", () => {
    const once = showTime("2026-10-16T13:05:09Z", "America/Sao_Paulo");
    expect(once).not.toBeNull();
    expect(showTime(once?.local ?? "", "America/Sao_Paulo")).toBeNull();
    expect(showTime(once?.iso ?? "", "America/Sao_Paulo")).toEqual(once);
  });

  it("refuses what is not a real RFC 3339 instant instead of guessing", () => {
    for (const bad of [
      "",
      "16/10/2026 10:00:00",
      "2026-10-16",
      "2026-10-16T13:05:09",
      "2026-02-30T00:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-10-16T24:00:00Z",
      "2026-10-16T13:05:60Z",
      "garbage",
    ]) {
      expect(parseInstant(bad), bad).toBeNull();
      expect(showTime(bad, "UTC"), bad).toBeNull();
    }
    expect(parseInstant("2024-02-29T00:00:00Z")).not.toBeNull();
  });

  it("keeps the precision the source had", () => {
    expect(showTime("2026-10-16T13:05:09.1234567Z", "UTC")?.fraction).toBe(7);
    expect(showTime("2026-10-16T13:05:09.1234567Z", "UTC")?.utc).toBe("16/10/2026 13:05:09");
  });

  it("reads years before 100 literally", () => {
    expect(parseInstant("0050-01-01T00:00:00Z")?.getUTCFullYear()).toBe(50);
    expect(showTime("1601-01-01T00:00:00Z", "UTC")?.utc).toBe("01/01/1601 00:00:00");
  });

  it("falls back to UTC for a zone the platform does not know", () => {
    expect(showTime("2026-10-16T13:05:09Z", "Not/AZone")?.zone).toBe("UTC");
  });

  it("orders times by instant, and anything else after them", () => {
    const values = [
      "x",
      "2026-10-16T13:00:00Z",
      "2026-10-16T09:00:00-05:00",
      "2020-01-01T00:00:00Z",
    ];
    expect([...values].sort(compareInstants)).toEqual([
      "2020-01-01T00:00:00Z",
      "2026-10-16T13:00:00Z",
      "2026-10-16T09:00:00-05:00",
      "x",
    ]);
  });

  it("labels each time by what it says happened", () => {
    expect(timeKind("recycle_bin", "deleted_at")).toBe("deleted");
    expect(timeKind("recycle_bin", "content_modified")).toBe("modified");
    expect(timeKind("recycle_bin", "folder_created")).toBe("created");
    expect(timeKind("recycle_bin", "last_artifact_change")).toBe("range_end");
    expect(timeKind("windows_service", "event_at")).toBe("service_event");
    expect(timeKind("windows_service", "collected_at")).toBe("collected");
    expect(timeKind("windows_start", "started_at")).toBe("system_start");
    expect(timeKind("prefetch", "last_run")).toBe("execution");
    expect(timeKind("shortcuts", "target_accessed")).toBe("accessed");
    expect(timeKind("mft", "si_changed")).toBe("changed");
    expect(timeKind("usb_device", "last_arrival_at")).toBe("connected");
    expect(timeKind(null, "generated_at")).toBe("scan");
    expect(timeKind("x", "something_new")).toBe("recorded");
  });

  it("says how certain each kind of time is", () => {
    expect(timeCertainty("windows_service", "event_at")).toBe("exact");
    expect(timeCertainty("recycle_bin", "deleted_at")).toBe("exact");
    expect(timeCertainty("prefetch", "last_run")).toBe("approximate");
    expect(timeCertainty("recycle_bin", "oldest_deleted_at")).toBe("approximate");
    expect(timeCertainty("roblox_files", "modified")).toBe("uncertain");
    expect(timeCertainty("x", "something_new")).toBe("approximate");
  });

  it("writes durations a person reads", () => {
    expect(formatDuration(4200)).toBe("4,2 s");
    expect(formatDuration(125_000)).toBe("2 min 05 s");
    expect(formatDuration(3_723_000)).toBe("1 h 02 min 03 s");
  });
});
