<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0114 — Firmware identity and virtual machines

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`machine_identity` reads `HKLM\HARDWARE\DESCRIPTION\System\BIOS` (vendor, product, version — never
serial numbers or UUIDs), `PEFirmwareType`, and VM hints (hypervisor vendor strings, guest services).
A VM is `info`: it explains other findings and limits what the scan can see.
