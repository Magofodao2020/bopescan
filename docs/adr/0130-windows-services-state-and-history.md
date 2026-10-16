<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0130 — Windows services: current state and System log history

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0 (interface rework)

## Context

PcaSvc, DiagTrack, DPS, SysMain and EventLog feed sources this program reads (PCA, diagnostics, SRUM,
Prefetch, every event log). A reviewer needs to know whether they run, to read the other sources, and
must not read a stopped service as cheating: tuning guides, editions, policies and updates stop them.

## Decision

- `bope_host::ServiceSource::service_status(name)`: a live host opens the Service Control Manager with
  `SC_MANAGER_CONNECT` and the service with `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG` only
  (`QueryServiceStatusEx`, `QueryServiceConfigW`); `Ok(None)` is "not installed". Status and
  configuration are two queries and either can be refused. The host stamps the moment it asked.
- `windows_service` collector (`scope: current`): one observation per service, always, with `query`
  (`ok`, `not_installed`, `access_denied`, `failed`), state, PID, start type, `disabled`, display name,
  account, program path and `collected_at`.
- `scope: history`: Service Control Manager events 7034, 7036, 7040 and 7045 of those services, read from
  `System.evtx` as a file (`bope_parsers::evtx::service_events`), matched by the key name the record holds
  (binary data of 7034/7036, `param4` of 7040) or by display name; the texts kept as recorded and a state
  or start type only when the word is recognised. One `log_span` observation carries the log's span.
  At most 400 events, newest first.
- No rule reads these observations: the services are context, never a finding. The core view shows them
  in both modes (`ReportView::services`); nothing in them is about the person.
- Not read: the history and the current state are separate gaps (`discriminator_gaps`); neither read is
  `Unmeasured`.

## Consequences

No service is started, stopped or reconfigured; no log level, audit policy or event is changed or
created. The history only holds what the System log still keeps. The SCM history parser is tested on
event data (JSON) only: no synthetic `.evtx` with Service Control Manager records exists in this
repository, and none was run on Windows during development.
