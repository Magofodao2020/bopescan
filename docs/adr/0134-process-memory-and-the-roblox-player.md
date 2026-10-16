<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0134 — Process memory and the Roblox player

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.11.0

## Decision

**Reading another process** (`ProcessMemory`, `bope-host-windows::modules`): `OpenProcess` with
`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` only; modules from `EnumProcessModulesEx`, regions
from `VirtualQueryEx` with `GetMappedFileNameW`, bytes from `ReadProcessMemory` (at most 16 MiB a call).
Nothing is written, suspended, injected or created in another process; no handle with write, operation
or thread rights is ever requested. A process that refuses is reported as refused.

**`process_modules`** (standard tier): every process's modules, assessed with the integrity classes of
ADR 0133 (routine signed Windows modules counted, not listed), private executable regions, regions that
begin with a PE header (`holds_image`), and image mappings the loader does not list.

**`roblox_memory`** (standard tier), for each Roblox player:
- *Identity* is not the name alone: `identity_checks` lists which of name, path under `Versions`,
  verifying signature and Roblox Corporation signer held, and `identity_confidence` follows from them.
  Every row carries the `pid`, so instances are never mixed.
- *Code vs file*: each module's file is laid out as the loader does, relocated to the loaded base
  (`pe::relocate`), and its executable non-writable sections compared byte by byte with memory, skipping
  the ranges the loader writes (IAT, delay IAT, `loader_written_ranges`). Differing ranges are reported
  with counts. Exported functions' first bytes are checked for a jump the file does not have
  (`memory::inline_hook`), with its target and whose memory that is (a module and its class, or
  `unbacked_private` / `unbacked_mapped`). Roblox's own image is protected and changed at run time by
  its anti-cheat; its rows say `expected_runtime_change: true` and no rule reads them as a finding.
- *Strings*: readable private and mapped memory (at most 768 MiB, 120 s) is scanned in ASCII, UTF-8
  and UTF-16LE; **only categorised strings are kept** (executor functions, injection APIs, flag
  identifiers and JSON assignments, module paths, URLs, script loaders), at most 40 per category, each
  with address, region, protection, encoding, length, owning module and method. Chat and other text are
  never kept.
- *Flags*: JSON-text assignments are reported as values (compared with the reference, ADR 0136);
  network and physics flag identifiers are reported with how many pointers in private memory point at
  them, and `value_interpretation: not_established` — no fixed offset is used, and an identifier is
  never read as an active flag or a nearby number as its value.
- A refused player is a row with `access: refused`, and every internal place is a discriminator gap;
  no player running makes them `source_absent`; a stopped read makes them `budget_spent`.

## Consequences

Roblox's anti-cheat refuses `PROCESS_VM_READ` on most machines; the evidence is then the refusal. Overlays,
recorders and security software also hook and patch; rules say so and attribute each hook's target.
