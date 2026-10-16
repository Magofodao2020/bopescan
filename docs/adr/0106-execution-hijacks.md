<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0106 — Execution hijacks

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`hijack` reads IFEO `Debugger` and `VerifierDlls`, `SilentProcessExit\*\MonitorProcess`,
`AppInit_DLLs` (+`LoadAppInit_DLLs`), `AppCertDlls` and Winlogon `Shell`/`Userinit`. Values equal to the
Windows defaults are not observations. Debuggers set by developer tools are a listed explanation.
