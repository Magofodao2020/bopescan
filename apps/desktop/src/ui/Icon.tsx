// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Line icons drawn here, so no icon font or image is loaded (B.O.P.E, ADR 0132). Each is decorative:
// the text beside it carries the meaning.

const PATHS = {
  overview: "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z",
  scanner: "M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3M4 12h16",
  evidence: "M6 2h9l5 5v15H6zM15 2v5h5M9 13h8M9 17h8M9 9h3",
  services:
    "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1",
  recycle: "M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7M14 10v7",
  timeline: "M12 3v18M12 6h7M12 12h5M12 18h7M5 6h4M7 12h2M5 18h4",
  reports: "M6 2h12v20H6zM9 7h6M9 11h6M9 15h4",
  settings: "M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0M14 4v4M8 10v4M16 16v4",
  close: "M5 5l14 14M19 5L5 19",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 3",
  alert: "M12 3l10 18H2zM12 10v5M12 18v.5",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5v.5",
  check: "M4 12l5 5L20 6",
  stop: "M6 6h12v12H6z",
  chevron: "M9 6l6 6-6 6",
  shield: "M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg
      className={`icon ${className ?? ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
