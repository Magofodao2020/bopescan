<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0128 — Names inside .rar and .7z archives, from their headers only

- Status: accepted
- Date: 2026-10-16
- Scope: B.O.P.E Scanner 0.10.0

## Decision

`bope_parsers::archive_names` lists RAR 4, RAR 5 and 7z archives through the random-read callback. RAR
file headers are read one block at a time and the packed data between them is skipped by its stated size
(at most 20 000 blocks). A 7z end header is read; when encoded, only that header is decompressed, with
`lzma-rs` 0.3.0 (MIT, `forbid(unsafe_code)`, deps `byteorder` and `crc`), LZMA or LZMA2 only, declared
size capped at 16 MiB and the output refused past the declared size, so a crafted header cannot become a
decompression bomb. Encrypted headers (RAR `-hp`, 7z AES) are reported as `encrypted_headers` with no
names; filtered or unknown methods are `partial`. At most 5 000 entries per archive, 25 archives and
25 000 reads per archive, inside `roblox_files`' 25 s budget. Nothing is extracted or executed.
