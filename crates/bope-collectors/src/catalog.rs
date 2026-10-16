// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The catalog of Roblox-related tools and the name matcher every Roblox trace goes through
//! (B.O.P.E, ADR 0118).
//!
//! One table, so that the file hunt (`roblox_files`), the change journal (`usn`), shortcuts,
//! Amcache and the correlation (`roblox_trace`) all mean the same thing by "Bloxstrap" or "an
//! executor". A match here is **a name**, never a finding: whether it matters is decided later, from
//! where the name was seen, what else points at the same tool, and whether anything shows it ran.
//!
//! # How a name is compared
//!
//! [`normalize`] lowercases a name, drops the folder part and the known extensions (and Prefetch's
//! `-XXXXXXXX.pf` hash), and produces two forms:
//!
//! - **compact**: letters and digits only — `Blox_Strap-v2.exe` → `bloxstrapv2`;
//! - **tokens**: the runs of letters and digits — `["blox", "strap", "v2"]`.
//!
//! A *distinctive* alias (long, not an ordinary word) matches when the compact form contains it. A
//! *short or ambiguous* alias (`wave`, `delta`, `synapse` — also Razer's software) matches only a whole
//! token or the whole compact name, and the match is marked `ambiguous`, so it needs Roblox context
//! before anyone reads it as that tool.
//!
//! # What is in the table
//!
//! Only names that are publicly known for the tool they are listed as. Legitimate tools are listed
//! **as** legitimate (`common_legitimate`): Bloxstrap and the FPS unlocker are used openly by many
//! players, and finding them says that, not more. No hash and no date is invented here.

/// What kind of tool a catalog entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolKind {
    /// A third-party Roblox launcher/bootstrapper (Bloxstrap and its forks).
    Bootstrapper,
    /// A tool whose job is editing Roblox `FastFlags`.
    FflagManager,
    /// A frame-rate unlocker for the Roblox client.
    FpsUnlocker,
    /// Account managers and other client utilities.
    ClientUtility,
    /// A Roblox script executor.
    Executor,
    /// A general DLL injector.
    Injector,
    /// A generic term (`executor`, `injector`, `fastflag`…) that names no specific tool.
    GenericTerm,
}

impl ToolKind {
    /// The word reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapper => "bootstrapper",
            Self::FflagManager => "fflag_manager",
            Self::FpsUnlocker => "fps_unlocker",
            Self::ClientUtility => "client_utility",
            Self::Executor => "executor",
            Self::Injector => "injector",
            Self::GenericTerm => "generic_term",
        }
    }

    /// Whether this kind is about running code in, or altering, the Roblox process.
    pub fn is_cheat_capable(self) -> bool {
        matches!(self, Self::Executor | Self::Injector)
    }
}

/// One catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tool {
    /// Stable id, lowercase.
    pub id: &'static str,
    /// The name people know it by.
    pub display: &'static str,
    /// What it is.
    pub kind: ToolKind,
    /// Distinctive aliases, compact form (letters and digits, lowercase). Matched as a substring.
    pub aliases: &'static [&'static str],
    /// Short or ordinary-word aliases, compact form. Matched only as a whole token or name.
    pub ambiguous: &'static [&'static str],
    /// Many players run it openly and for ordinary reasons.
    pub common_legitimate: bool,
    /// Tied to Roblox by the name itself (`roblox` in the tool's identity), so no context is needed.
    pub roblox_specific: bool,
}

const fn tool(
    id: &'static str,
    display: &'static str,
    kind: ToolKind,
    aliases: &'static [&'static str],
    ambiguous: &'static [&'static str],
) -> Tool {
    Tool {
        id,
        display,
        kind,
        aliases,
        ambiguous,
        common_legitimate: false,
        roblox_specific: true,
    }
}

const fn legit(mut t: Tool) -> Tool {
    t.common_legitimate = true;
    t
}

const fn general(mut t: Tool) -> Tool {
    t.roblox_specific = false;
    t
}

/// Every entry. Order is report order: launchers and `FastFlags` first, then executors, injectors and
/// generic terms.
pub static TOOLS: [Tool; 41] = [
    // Launchers / bootstrappers.
    legit(tool(
        "bloxstrap",
        "Bloxstrap",
        ToolKind::Bootstrapper,
        &["bloxstrap"],
        &[],
    )),
    legit(tool(
        "fishstrap",
        "Fishstrap",
        ToolKind::Bootstrapper,
        &["fishstrap"],
        &[],
    )),
    legit(tool(
        "voidstrap",
        "Voidstrap",
        ToolKind::Bootstrapper,
        &["voidstrap"],
        &[],
    )),
    legit(tool(
        "froststrap",
        "Froststrap",
        ToolKind::Bootstrapper,
        &["froststrap"],
        &[],
    )),
    legit(tool(
        "roblox_mod_manager",
        "Roblox Studio Mod Manager",
        ToolKind::ClientUtility,
        &[
            "robloxstudiomodmanager",
            "studiomodmanager",
            "rbxmodmanager",
        ],
        &[],
    )),
    tool(
        "roblox_launcher_generic",
        "Launcher alternativo do Roblox",
        ToolKind::Bootstrapper,
        &["robloxlauncher", "rbxlauncher", "robloxmod", "rbxmod"],
        &[],
    ),
    // FastFlags.
    tool(
        "fflag_manager",
        "Gerenciador de FastFlags",
        ToolKind::FflagManager,
        &[
            "fflagmanager",
            "flagmanager",
            "fflageditor",
            "fflagtool",
            "fflagtoolkit",
            "fastflagmanager",
            "fastflageditor",
            "fastflags",
            "fastflag",
            "fflags",
        ],
        &["fflag"],
    ),
    // Frame rate.
    legit(tool(
        "rbxfpsunlocker",
        "Roblox FPS Unlocker (rbxfpsunlocker)",
        ToolKind::FpsUnlocker,
        &["rbxfpsunlocker", "robloxfpsunlocker", "fpsunlocker"],
        &[],
    )),
    legit(tool(
        "roblox_account_manager",
        "Roblox Account Manager",
        ToolKind::ClientUtility,
        &["robloxaccountmanager", "rbxaccountmanager"],
        &[],
    )),
    // Executors whose names are distinctive.
    tool(
        "synapse_x",
        "Synapse X",
        ToolKind::Executor,
        &["synapsex", "synapsez"],
        &["synapse"],
    ),
    tool(
        "script_ware",
        "Script-Ware",
        ToolKind::Executor,
        &["scriptware"],
        &[],
    ),
    tool("krnl", "KRNL", ToolKind::Executor, &[], &["krnl"]),
    tool(
        "jjsploit",
        "JJSploit",
        ToolKind::Executor,
        &["jjsploit"],
        &[],
    ),
    tool("fluxus", "Fluxus", ToolKind::Executor, &["fluxus"], &[]),
    tool(
        "oxygen_u",
        "Oxygen U",
        ToolKind::Executor,
        &["oxygenu"],
        &[],
    ),
    tool("sirhurt", "SirHurt", ToolKind::Executor, &["sirhurt"], &[]),
    tool(
        "seliware",
        "Seliware",
        ToolKind::Executor,
        &["seliware"],
        &[],
    ),
    tool(
        "arceus_x",
        "Arceus X",
        ToolKind::Executor,
        &["arceusx"],
        &[],
    ),
    tool(
        "trigon",
        "Trigon",
        ToolKind::Executor,
        &["trigonevo"],
        &["trigon"],
    ),
    tool("krampus", "Krampus", ToolKind::Executor, &["krampus"], &[]),
    tool("valyse", "Valyse", ToolKind::Executor, &["valyse"], &[]),
    tool("zorara", "Zorara", ToolKind::Executor, &["zorara"], &[]),
    tool(
        "macsploit",
        "MacSploit",
        ToolKind::Executor,
        &["macsploit"],
        &[],
    ),
    tool(
        "calamari",
        "Calamari",
        ToolKind::Executor,
        &["calamari"],
        &[],
    ),
    tool(
        "protosmasher",
        "ProtoSmasher",
        ToolKind::Executor,
        &["protosmasher"],
        &[],
    ),
    // Executors whose names are ordinary words or other products: whole-token only, need context.
    tool("solara", "Solara", ToolKind::Executor, &[], &["solara"]),
    tool(
        "wave",
        "Wave",
        ToolKind::Executor,
        &[],
        &["wave", "getwave"],
    ),
    tool("celery", "Celery", ToolKind::Executor, &[], &["celery"]),
    tool("nihon", "Nihon", ToolKind::Executor, &[], &["nihon"]),
    tool("xeno", "Xeno", ToolKind::Executor, &[], &["xeno"]),
    tool(
        "delta",
        "Delta",
        ToolKind::Executor,
        &[],
        &["delta", "deltaexecutor"],
    ),
    tool("codex", "Codex", ToolKind::Executor, &[], &["codex"]),
    tool("evon", "Evon", ToolKind::Executor, &[], &["evon"]),
    tool(
        "velocity",
        "Velocity",
        ToolKind::Executor,
        &[],
        &["velocity"],
    ),
    tool(
        "electron_exec",
        "Electron",
        ToolKind::Executor,
        &[],
        &["electronexecutor"],
    ),
    tool("awp", "AWP", ToolKind::Executor, &[], &["awp", "awpgg"]),
    // A folder with an executor's `autoexec` + `workspace` layout whose name matches nothing above:
    // never matched by name, only assigned by the correlation (ADR 0123).
    tool(
        "unnamed_executor",
        "Executor sem nome conhecido (estrutura autoexec/workspace)",
        ToolKind::Executor,
        &[],
        &[],
    ),
    // General injectors, not Roblox-specific.
    general(tool(
        "dll_injector",
        "Injetor de DLL",
        ToolKind::Injector,
        &[
            "extremeinjector",
            "xenosinjector",
            "ghinjector",
            "dllinjector",
            "injector",
        ],
        &["inject"],
    )),
    // Generic terms from the brief.
    general(tool(
        "executor_term",
        "Termo genérico: executor",
        ToolKind::GenericTerm,
        &["executor", "exploit"],
        &[],
    )),
    general(tool(
        "client_settings_term",
        "Termo genérico: ClientSettings / bootstrapper",
        ToolKind::GenericTerm,
        &["clientappsettings", "clientsettings", "bootstrapper"],
        &[],
    )),
    general(tool(
        "strap_partial",
        "Parcial: “strap”/“trap”",
        ToolKind::GenericTerm,
        &[],
        &[],
    )),
];

/// Words that contain `strap`/`trap` and are ordinary software: never a partial match.
const STRAP_WORDS: [&str; 10] = [
    "bootstrap",
    "strapi",
    "trapcode",
    "trapeze",
    "trapezoid",
    "traplayer",
    "snmptrap",
    "trapper",
    "strapping",
    "watchstrap",
];

/// How a name matched an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchKind {
    /// `strap`/`trap` inside a name, and nothing more.
    WeakPartial,
    /// A generic term (`executor`, `fastflag`, `injector`…).
    GenericTerm,
    /// A whole-token match of a short or ordinary-word alias.
    AmbiguousAlias,
    /// A distinctive alias.
    KnownTool,
}

impl MatchKind {
    /// The word reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeakPartial => "weak_partial",
            Self::GenericTerm => "generic_term",
            Self::AmbiguousAlias => "ambiguous_alias",
            Self::KnownTool => "known_tool",
        }
    }
}

/// One match of a name against the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// The entry.
    pub tool: &'static Tool,
    /// How it matched.
    pub kind: MatchKind,
    /// The alias, compact form, that matched (`strap` or `trap` for a partial).
    pub alias: &'static str,
}

/// A name in its two compared forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// Letters and digits only, lowercase.
    pub compact: String,
    /// Runs of letters and digits, lowercase.
    pub tokens: Vec<String>,
}

/// Extensions dropped before comparing, longest first where one ends another.
const EXTENSIONS: [&str; 16] = [
    ".exe", ".dll", ".lnk", ".zip", ".rar", ".7z", ".json", ".lua", ".luau", ".txt", ".bat",
    ".ps1", ".ahk", ".msi", ".bak", ".tmp",
];

/// The last path segment of `name`, without known extensions or a Prefetch hash suffix, in its two
/// compared forms.
pub fn normalize(name: &str) -> Normalized {
    let last = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let mut stem = last.to_lowercase();
    // `BLOXSTRAP.EXE-1A2B3C4D.pf`: Prefetch's own suffix first.
    if let Some(cut) = prefetch_suffix(&stem) {
        stem.truncate(cut);
    }
    loop {
        let before = stem.len();
        for ext in EXTENSIONS {
            if stem.len() > ext.len() && stem.ends_with(ext) {
                stem.truncate(stem.len() - ext.len());
                break;
            }
        }
        if stem.len() == before {
            break;
        }
    }
    let tokens: Vec<String> = stem
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
    Normalized {
        compact: tokens.concat(),
        tokens,
    }
}

/// Where `-XXXXXXXX.pf` starts, when the name ends with it.
fn prefetch_suffix(name: &str) -> Option<usize> {
    let body = name.strip_suffix(".pf")?;
    let (head, hash) = body.rsplit_once('-')?;
    (hash.len() == 8 && hash.chars().all(|c| c.is_ascii_hexdigit())).then_some(head.len())
}

/// Every catalog entry `name` matches, strongest first, one per entry.
pub fn match_name(name: &str) -> Vec<Match> {
    let n = normalize(name);
    if n.compact.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<Match> = Vec::new();
    for tool in &TOOLS {
        let mut best: Option<Match> = None;
        for alias in tool.aliases {
            if n.compact.contains(alias) {
                let kind = if tool.kind == ToolKind::GenericTerm {
                    MatchKind::GenericTerm
                } else {
                    MatchKind::KnownTool
                };
                best = Some(Match { tool, kind, alias });
                break;
            }
        }
        if best.is_none() {
            for alias in tool.ambiguous {
                let whole = n.compact == *alias || n.tokens.iter().any(|t| t == alias);
                if whole {
                    best = Some(Match {
                        tool,
                        kind: MatchKind::AmbiguousAlias,
                        alias,
                    });
                    break;
                }
            }
        }
        if let Some(m) = best {
            found.push(m);
        }
    }
    // A generic term inside a known tool's name (`rbxfpsunlocker` holds `fpsunlocker`; `bloxstrap`
    // holds `strap`) adds nothing: the more specific entry stands for the name.
    let specific = found
        .iter()
        .any(|m| m.kind >= MatchKind::AmbiguousAlias && m.tool.kind != ToolKind::GenericTerm);
    if specific {
        found.retain(|m| m.kind != MatchKind::GenericTerm || m.tool.id == "executor_term");
    }
    if found.is_empty()
        && let Some(partial) = strap_partial(&n.compact)
    {
        found.push(Match {
            tool: strap_entry(),
            kind: MatchKind::WeakPartial,
            alias: partial,
        });
    }
    found.sort_by_key(|m| std::cmp::Reverse(m.kind));
    found
}

fn strap_entry() -> &'static Tool {
    TOOLS
        .iter()
        .find(|t| t.id == "strap_partial")
        .unwrap_or(&TOOLS[TOOLS.len() - 1])
}

/// `strap` or `trap` inside `compact`, unless every occurrence is part of an ordinary word.
fn strap_partial(compact: &str) -> Option<&'static str> {
    let mut rest = compact.to_owned();
    for word in STRAP_WORDS {
        rest = rest.replace(word, "");
    }
    if rest.contains("strap") {
        Some("strap")
    } else if rest.contains("trap") {
        Some("trap")
    } else {
        None
    }
}

/// The entry with `id`.
pub fn by_id(id: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.id == id)
}

/// Whether a path itself places a name in a Roblox context: a Roblox folder, a launcher's folder or a
/// path that names Roblox.
pub fn path_mentions_roblox(path: &str) -> bool {
    let lower = path.to_lowercase();
    [
        "roblox",
        "rbx",
        "bloxstrap",
        "fishstrap",
        "voidstrap",
        "froststrap",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(name: &str) -> Vec<(&'static str, MatchKind)> {
        match_name(name)
            .into_iter()
            .map(|m| (m.tool.id, m.kind))
            .collect()
    }

    #[test]
    fn bloxstrap_variants_all_match() {
        for name in [
            "Bloxstrap.exe",
            r"C:\Users\a\Downloads\BloxStrap-v2.8.1.exe",
            "blox strap.lnk",
            "blox_strap",
            "BLOX-STRAP.zip",
            "BLOXSTRAP.EXE-1A2B3C4D.pf",
        ] {
            assert_eq!(
                ids(name).first(),
                Some(&("bloxstrap", MatchKind::KnownTool)),
                "{name}"
            );
        }
    }

    #[test]
    fn fflag_manager_variants_match() {
        for name in [
            "FFlagManager.exe",
            "fflag-manager",
            "FFlag_Manager_v3.zip",
            "FlagManager.exe",
            "FastFlags Editor.exe",
            "fflags.json",
        ] {
            assert_eq!(
                ids(name).first().map(|m| m.0),
                Some("fflag_manager"),
                "{name}"
            );
        }
        // `fflag` alone is a whole token, so it is ambiguous, not distinctive.
        assert_eq!(
            ids("fflag.txt"),
            vec![("fflag_manager", MatchKind::AmbiguousAlias)]
        );
    }

    #[test]
    fn fps_unlocker_is_the_specific_tool_not_the_generic_term() {
        assert_eq!(
            ids("rbxfpsunlocker.exe"),
            vec![("rbxfpsunlocker", MatchKind::KnownTool)]
        );
        assert_eq!(ids("fps-unlocker.exe")[0].0, "rbxfpsunlocker");
    }

    #[test]
    fn strap_and_trap_are_weak_partials_and_ordinary_words_are_not() {
        assert_eq!(
            ids("MyStrapLauncher.exe"),
            vec![("strap_partial", MatchKind::WeakPartial)]
        );
        assert_eq!(
            ids("Trap.exe"),
            vec![("strap_partial", MatchKind::WeakPartial)]
        );
        // Ordinary software that holds the letters.
        assert!(ids("bootstrap.min.css").is_empty());
        // Windows' own kernel holds the letters of an executor's name.
        assert!(ids("ntoskrnl.exe").is_empty());
        assert!(ids("trigonometry.pdf").is_empty());
        assert!(ids("strapi-admin").is_empty());
        assert!(ids("Trapcode Particular").is_empty());
        // A known tool does not also report the partial.
        assert_eq!(ids("Fishstrap.exe").len(), 1);
    }

    #[test]
    fn ambiguous_names_need_a_whole_token() {
        assert_eq!(
            ids("Solara.exe"),
            vec![("solara", MatchKind::AmbiguousAlias)]
        );
        assert!(ids("Solaraway.exe").is_empty());
        assert!(ids("microwave.exe").is_empty());
        // Razer Synapse is `synapse` as a token: ambiguous, never Synapse X.
        assert_eq!(
            ids(r"C:\Program Files (x86)\Razer\Synapse3\WPFUI\Framework\Razer Synapse 3 Host\Razer Synapse 3.exe")
                .first()
                .map(|m| m.1),
            Some(MatchKind::AmbiguousAlias)
        );
        assert_eq!(ids("SynapseX.exe")[0], ("synapse_x", MatchKind::KnownTool));
    }

    #[test]
    fn generic_terms_from_the_brief() {
        assert_eq!(ids("Roblox Executor.exe")[0].0, "executor_term");
        assert_eq!(ids("injector.exe")[0].0, "dll_injector");
        assert_eq!(ids("ClientAppSettings.json")[0].0, "client_settings_term");
        assert_eq!(ids("roblox mod.zip")[0].0, "roblox_launcher_generic");
        assert_eq!(ids("Roblox Launcher.exe")[0].0, "roblox_launcher_generic");
        assert_eq!(ids("RobloxPlayerBeta.exe"), vec![]);
        assert_eq!(ids("notepad.exe"), vec![]);
    }

    #[test]
    fn ids_are_unique_and_aliases_compact() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in &TOOLS {
            assert!(seen.insert(tool.id), "{}", tool.id);
            for alias in tool.aliases.iter().chain(tool.ambiguous) {
                assert!(
                    alias
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                    "{alias}"
                );
            }
        }
        assert!(by_id("strap_partial").is_some());
        assert!(path_mentions_roblox(r"C:\Users\a\AppData\Local\Roblox\x"));
    }
}
