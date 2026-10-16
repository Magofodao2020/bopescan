<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0112 — Network adapters and proxies

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`net_adapter` reads the network adapter class keys (description, component id, tunnel/TAP/WireGuard
patterns), the WinHTTP proxy and the user/system `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`
variables (always emitted with `set`). No traffic is read or sent. A VPN is `info`.
