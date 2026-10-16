<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0104 — UserAssist, MuiCache and FeatureUsage

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

Three per-account Explorer sources of program use:

- `userassist`: ROT13 value names under `UserAssist\{GUID}\Count`; Win7+ 72-byte data (run count,
  focus count/time, last run FILETIME) and XP 16-byte data. Known-folder GUIDs are expanded through this
  account's environment. Bookkeeping values are skipped. Undecodable data is a gap, not a guess.
- `muicache`: `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`
  `.FriendlyAppName` / `.ApplicationCompany` values. No time.
- `feature_usage`: `Explorer\FeatureUsage\{AppSwitched,AppLaunch,ShowJumpView}` counts per program.

All three are name-only (ADR 0100). "Track app launches" off is an ordinary privacy setting.
