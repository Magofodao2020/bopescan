// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Browser extensions and what they may touch (B.O.P.E, ADR 0109). **Full scan only**: a player agrees
//! to it before the scan starts.
//!
//! Chromium browsers (Chrome, Edge, Brave, Opera, Opera GX, Vivaldi): every profile's
//! `Extensions\<id>\<version>\manifest.json`. Firefox: every profile's `extensions.json`. From each
//! manifest it keeps the extension's id, name and version and **only** these facts about its
//! permissions:
//!
//! - `roblox_access` — a host permission or content-script pattern that covers `roblox.com` (or every
//!   site);
//! - `all_sites` — `<all_urls>` or a pattern for every host;
//! - `user_scripts` — the `userScripts` permission, which lets the extension run code the user supplies
//!   (Tampermonkey, Violentmonkey and similar);
//! - `debugger` — the `debugger` permission, which lets it control pages through `DevTools`.
//!
//! **Never read**: history, cookies, saved passwords, form data, sessions, local storage, the scripts a
//! userscript manager holds, or any page content. Many extensions that customise Roblox's website
//! (themes, trade helpers, server finders) need `roblox_access`; that is not a cheat.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, Observation, ScanTier, UnmeasuredReason};
use bope_host::{Host, Platform};
use serde_json::Value;

use crate::common::{Fields, env_folder, join, unmeasured};
use crate::{Collector, Field};

const ID: &str = "browser_ext";

/// Chromium browsers: name, environment variable, path below it to `User Data`.
pub const CHROMIUM: [(&str, &str, &str); 6] = [
    ("chrome", "LOCALAPPDATA", r"Google\Chrome\User Data"),
    ("edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data"),
    (
        "brave",
        "LOCALAPPDATA",
        r"BraveSoftware\Brave-Browser\User Data",
    ),
    ("vivaldi", "LOCALAPPDATA", r"Vivaldi\User Data"),
    ("opera", "APPDATA", r"Opera Software\Opera Stable"),
    ("opera_gx", "APPDATA", r"Opera Software\Opera GX Stable"),
];

static FIELDS: [Field; 10] = [
    Field::boolean("all_sites"),
    Field::text("browser"),
    Field::boolean("debugger"),
    Field::boolean("enabled"),
    Field::text("extension_id"),
    Field::text("name"),
    Field::text("profile"),
    Field::boolean("roblox_access"),
    Field::boolean("user_scripts"),
    Field::text("version"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::Partial,
];

/// The `browser_ext` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserExt;

/// What a set of URL patterns and permissions says about Roblox and about every site.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    /// A pattern covers `roblox.com` or every site.
    pub roblox: bool,
    /// A pattern covers every site.
    pub all: bool,
}

/// Reads URL match patterns.
pub fn reach<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Reach {
    let mut reach = Reach::default();
    for pattern in patterns {
        let p = pattern.trim().to_ascii_lowercase();
        let host = p
            .split_once("://")
            .map_or(p.as_str(), |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        let every = p == "<all_urls>" || host == "*" || p == "*://*/*";
        if every {
            reach.all = true;
            reach.roblox = true;
        }
        let bare = host.trim_start_matches("*.");
        if bare == "roblox.com" || bare.ends_with(".roblox.com") {
            reach.roblox = true;
        }
    }
    reach
}

fn strings(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Facts from one Chromium `manifest.json`.
pub fn chromium_manifest(json: &Value) -> (Option<String>, Option<String>, Reach, bool, bool) {
    let permissions = strings(json.get("permissions"));
    let mut patterns: Vec<&str> = strings(json.get("host_permissions"));
    patterns.extend(strings(json.get("optional_host_permissions")));
    // Manifest V2 put host patterns among the permissions.
    patterns.extend(
        permissions
            .iter()
            .filter(|p| p.contains("://") || **p == "<all_urls>"),
    );
    if let Some(scripts) = json.get("content_scripts").and_then(Value::as_array) {
        for script in scripts {
            patterns.extend(strings(script.get("matches")));
        }
    }
    let reach = reach(patterns);
    let user_scripts = permissions.contains(&"userScripts");
    let debugger = permissions.contains(&"debugger");
    let name = json.get("name").and_then(Value::as_str).map(str::to_owned);
    let version = json
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (name, version, reach, user_scripts, debugger)
}

fn chromium(
    host: &dyn Host,
    browser: &str,
    user_data: &str,
    out: &mut Vec<Observation>,
) -> Result<(), ()> {
    let Ok(listing) = host.list_dir(user_data) else {
        return Err(());
    };
    let Some(profiles) = listing else {
        return Ok(());
    };
    for profile in profiles.iter().filter(|p| !p.is_file) {
        let ext_dir = join(&join(user_data, &profile.name), "Extensions");
        let Ok(Some(ids)) = host.list_dir(&ext_dir) else {
            continue;
        };
        for id in ids.iter().filter(|e| !e.is_file && e.name.len() == 32) {
            let id_dir = join(&ext_dir, &id.name);
            let Ok(Some(versions)) = host.list_dir(&id_dir) else {
                continue;
            };
            // The newest version folder by name is the one in use.
            let Some(version) = versions
                .iter()
                .filter(|v| !v.is_file)
                .map(|v| v.name.clone())
                .max()
            else {
                continue;
            };
            let manifest = join(&join(&id_dir, &version), "manifest.json");
            let json = match host.read_file(&manifest) {
                Ok(Some(bytes)) => serde_json::from_slice::<Value>(strip_bom(&bytes)).ok(),
                _ => None,
            };
            let mut fields = Fields::new()
                .with("browser", browser)
                .with("profile", profile.name.clone())
                .with("extension_id", id.name.clone());
            if let Some(json) = json {
                let (name, ver, reach, user_scripts, debugger) = chromium_manifest(&json);
                fields = fields
                    .maybe("name", name)
                    .maybe("version", ver)
                    .with("roblox_access", reach.roblox)
                    .with("all_sites", reach.all)
                    .with("user_scripts", user_scripts)
                    .with("debugger", debugger);
            }
            out.push(fields.observe(ID));
        }
    }
    Ok(())
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

fn firefox(host: &dyn Host, out: &mut Vec<Observation>) -> Result<(), ()> {
    let Some(roaming) = env_folder(host, "APPDATA") else {
        return Ok(());
    };
    let profiles_dir = join(&roaming, r"Mozilla\Firefox\Profiles");
    let Ok(listing) = host.list_dir(&profiles_dir) else {
        return Err(());
    };
    let Some(profiles) = listing else {
        return Ok(());
    };
    for profile in profiles.iter().filter(|p| !p.is_file) {
        let path = join(&join(&profiles_dir, &profile.name), "extensions.json");
        let Ok(Some(bytes)) = host.read_file(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_slice::<Value>(strip_bom(&bytes)) else {
            continue;
        };
        for addon in json
            .get("addons")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if addon.get("type").and_then(Value::as_str) != Some("extension") {
                continue;
            }
            if addon.get("location").and_then(Value::as_str) == Some("app-builtin")
                || addon.get("location").and_then(Value::as_str) == Some("app-system-defaults")
            {
                continue;
            }
            let user = addon.get("userPermissions");
            let permissions = strings(user.and_then(|u| u.get("permissions")));
            let mut patterns = strings(user.and_then(|u| u.get("origins")));
            if let Some(scripts) = addon
                .get("contentScripts")
                .or_else(|| addon.get("content_scripts"))
            {
                for script in scripts.as_array().into_iter().flatten() {
                    patterns.extend(strings(script.get("matches")));
                }
            }
            let reach = reach(patterns);
            out.push(
                Fields::new()
                    .with("browser", "firefox")
                    .with("profile", profile.name.clone())
                    .maybe("extension_id", addon.get("id").and_then(Value::as_str))
                    .maybe(
                        "name",
                        addon
                            .get("defaultLocale")
                            .and_then(|l| l.get("name"))
                            .and_then(Value::as_str),
                    )
                    .maybe("version", addon.get("version").and_then(Value::as_str))
                    .maybe("enabled", addon.get("active").and_then(Value::as_bool))
                    .with("roblox_access", reach.roblox)
                    .with("all_sites", reach.all)
                    .with("user_scripts", permissions.contains(&"userScripts"))
                    .with("debugger", false)
                    .observe(ID),
            );
        }
    }
    Ok(())
}

impl Collector for BrowserExt {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn tier(&self) -> ScanTier {
        ScanTier::Full
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let mut observations = Vec::new();
        let mut failed = false;
        for (browser, variable, relative) in CHROMIUM {
            let Some(base) = env_folder(host, variable) else {
                continue;
            };
            failed |= chromium(host, browser, &join(&base, relative), &mut observations).is_err();
        }
        failed |= firefox(host, &mut observations).is_err();
        let mut gaps = BTreeMap::new();
        if failed {
            gaps.insert("extension_id".to_owned(), UnmeasuredReason::Partial);
        }
        crate::common::measured(ID, observations, gaps)
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn patterns_are_read_for_roblox_and_for_every_site() {
        assert_eq!(
            reach(["https://www.roblox.com/*"]),
            Reach {
                roblox: true,
                all: false
            }
        );
        assert_eq!(
            reach(["*://*.roblox.com/games/*"]),
            Reach {
                roblox: true,
                all: false
            }
        );
        assert_eq!(
            reach(["<all_urls>"]),
            Reach {
                roblox: true,
                all: true
            }
        );
        assert_eq!(
            reach(["https://notroblox.com/*", "https://example.com/*"]),
            Reach::default()
        );
    }

    #[test]
    fn chromium_and_firefox_extensions_are_listed_with_their_reach_only() {
        let host = FixtureHost::from_yaml_str(
            r#"platform: windows
env:
  LOCALAPPDATA: 'C:\Users\a\AppData\Local'
  APPDATA: 'C:\Users\a\AppData\Roaming'
filesystem:
  'C:\Users\a\AppData\Local\Google\Chrome\User Data':
    - { name: Default, directory: true }
    - { name: 'Local State' }
  'C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions':
    - { name: dhdgffkkebhmkfjojejmpbldmpobfkfo, directory: true }
    - { name: aaaabbbbccccddddeeeeffffgggghhhh, directory: true }
  'C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\dhdgffkkebhmkfjojejmpbldmpobfkfo':
    - { name: 5.0.0_0, directory: true }
    - { name: 5.1.0_0, directory: true }
  'C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\dhdgffkkebhmkfjojejmpbldmpobfkfo\5.1.0_0':
    - name: manifest.json
      content: '{"name":"Tampermonkey","version":"5.1.0","permissions":["userScripts","storage"],"host_permissions":["<all_urls>"]}'
  'C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\aaaabbbbccccddddeeeeffffgggghhhh':
    - { name: 1.0_0, directory: true }
  'C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\aaaabbbbccccddddeeeeffffgggghhhh\1.0_0':
    - name: manifest.json
      content: '{"name":"Theme","version":"1.0","content_scripts":[{"matches":["https://www.roblox.com/*"]}]}'
  'C:\Users\a\AppData\Roaming\Mozilla\Firefox\Profiles':
    - { name: abc.default-release, directory: true }
  'C:\Users\a\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release':
    - name: extensions.json
      content: '{"addons":[{"id":"x@y","type":"extension","location":"app-profile","version":"2","active":true,"defaultLocale":{"name":"Helper"},"userPermissions":{"permissions":["storage"],"origins":["*://*.roblox.com/*"]}},{"id":"b@s","type":"extension","location":"app-builtin"}]}'
"#,
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured {
            observations, gaps, ..
        } = BrowserExt.collect(&host)
        else {
            panic!("measured");
        };
        assert!(gaps.is_empty());
        assert_eq!(observations.len(), 3, "{observations:?}");
        let tm = observations
            .iter()
            .find(|o| o.fields.get("name") == Some(&"Tampermonkey".into()))
            .unwrap();
        assert_eq!(tm.fields["version"], "5.1.0");
        assert_eq!(tm.fields["user_scripts"], true);
        assert_eq!(tm.fields["all_sites"], true);
        let theme = observations
            .iter()
            .find(|o| o.fields.get("name") == Some(&"Theme".into()))
            .unwrap();
        assert_eq!(theme.fields["roblox_access"], true);
        assert_eq!(theme.fields["all_sites"], false);
        let ff = observations
            .iter()
            .find(|o| o.fields["browser"] == "firefox")
            .unwrap();
        assert_eq!(ff.fields["roblox_access"], true);
        assert_eq!(ff.fields["enabled"], true);
    }
}
