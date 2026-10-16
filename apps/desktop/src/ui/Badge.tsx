// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// A state is a word, a shape and a colour, never a colour alone (ADR 0045, B.O.P.E ADR 0132).

export type Tone = "flag" | "warn" | "info" | "unmeasured" | "neutral";
export type Shape = "square" | "triangle" | "diamond" | "ring" | "dashed" | "circle";

function ShapeMark({ shape }: { shape: Shape }) {
  return (
    <svg className="icon" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
      <ShapePath shape={shape} />
    </svg>
  );
}

function ShapePath({ shape }: { shape: Shape }) {
  switch (shape) {
    case "square":
      return <rect x="1.5" y="1.5" width="9" height="9" fill="currentColor" />;
    case "triangle":
      return <path d="M6 1 11 11H1z" fill="currentColor" />;
    case "diamond":
      return <path d="M6 0.8 11.2 6 6 11.2 0.8 6z" fill="currentColor" />;
    case "ring":
      return <circle cx="6" cy="6" r="4.2" fill="none" stroke="currentColor" strokeWidth="1.8" />;
    case "dashed":
      return (
        <circle
          cx="6"
          cy="6"
          r="4.2"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeDasharray="2 1.6"
        />
      );
    case "circle":
      return <circle cx="6" cy="6" r="4.5" fill="currentColor" />;
  }
}

export function Badge({
  tone,
  shape,
  label,
  title,
}: {
  tone: Tone;
  shape: Shape;
  label: string;
  title?: string;
}) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      <ShapeMark shape={shape} />
      {label}
    </span>
  );
}

/** Tone and shape of a rule's evidence state. */
export const EVIDENCE_LOOK = {
  found: { tone: "flag", shape: "square" },
  not_found: { tone: "neutral", shape: "ring" },
  unmeasured: { tone: "unmeasured", shape: "dashed" },
} as const satisfies Record<string, { tone: Tone; shape: Shape }>;

/** Tone and shape of a rule's level when found. */
export const LEVEL_LOOK = {
  flag: { tone: "flag", shape: "triangle" },
  warn: { tone: "warn", shape: "diamond" },
  info: { tone: "info", shape: "ring" },
} as const satisfies Record<string, { tone: Tone; shape: Shape }>;

/** Tone and shape of a Roblox tool's status: INFO, SUSPECTED, DETECTED, CORROBORATED. */
export const STATUS_LOOK = {
  info: { tone: "info", shape: "ring" },
  suspected: { tone: "warn", shape: "diamond" },
  detected: { tone: "flag", shape: "triangle" },
  corroborated: { tone: "flag", shape: "square" },
} as const satisfies Record<string, { tone: Tone; shape: Shape }>;
