<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0127 — Permanent WMI event subscriptions through WMI's query interface

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Context

ADR 0011 kept WMI out for HVCI because one registry value did not justify it. Permanent subscriptions
have no registry equivalent; the repository file is undocumented.

## Decision

A `WmiSubscriptionSource` trait; the live host (`bope_host_windows::wmi`) joins the multithreaded
apartment on its own thread, `ConnectServer`s to `ROOT\subscription` and `ROOT\default`, sets the proxy
blanket and calls only `ExecQuery` (`SELECT * FROM __EventFilter` / `__EventConsumer` /
`__FilterToConsumerBinding`) and `IWbemClassObject::Get`. `CoInitializeSecurity` is not called (it is
process-wide). Nothing is created, changed, deleted or executed. The `wmi_subscription` collector keeps
names, queries, the program a consumer starts (never arguments), script engine/file, and for an inline
script only its length, SHA-256 and the program/script file names it mentions — never its text. Existing
programs are hashed and signature-checked. Windows' own SCM Event Log and BVT subscriptions are
`known_default`. Class `persistence`, family `wmi`.

## Consequences

The COM code compiles for Windows but was not run in this project's CI; its behaviour must be confirmed
on Windows 10/11 (docs/bope/validacao-windows.md).
