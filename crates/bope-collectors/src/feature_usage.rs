// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! `FeatureUsage`: what the Windows 10 and 11 taskbar counts about programs (B.O.P.E, ADR 0104).
//!
//! Under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage`, the subkeys
//! `AppSwitched` (a program's taskbar button was used to switch to it), `AppLaunch` (a pinned program
//! was started from the taskbar) and `ShowJumpView` (its jump list was opened) hold one `REG_DWORD`
//! counter per program, named by its path or by its application user-model id. No time is stored.
//!
//! What it shows is that a program **had a window on the taskbar** for this account at some point —
//! a program that ran but never showed a taskbar button is not counted. The key does not exist before
//! Windows 10 1903.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field, location};

const ID: &str = "feature_usage";

/// The key whose subkeys are read.
pub const ROOT: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage";

/// Subkey, value of `kind`.
pub const KINDS: [(&str, &str); 3] = [
    ("AppSwitched", "app_switched"),
    ("AppLaunch", "app_launch"),
    ("ShowJumpView", "show_jump_view"),
];

static FIELDS: [Field; 5] = [
    Field::number("count"),
    Field::text("kind"),
    Field::text("location_kind"),
    Field::text("name"),
    Field::text("path"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::SourceAbsent,
    UnmeasuredReason::ReadFailed,
];

/// The `feature_usage` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureUsage;

impl Collector for FeatureUsage {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        match host.subkeys(ROOT) {
            Ok(Some(_)) => {}
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        }
        let mut observations = Vec::new();
        for (subkey, kind) in KINDS {
            let key = format!(r"{ROOT}\{subkey}");
            let names = match host.value_names(&key) {
                Ok(Some(names)) => names,
                Ok(None) => continue,
                Err(error) => return unmeasured(ID, reason(host, &error)),
            };
            for name in names {
                let count = match host.read_value(&key, &name) {
                    Ok(Some(RegistryData::Dword(n))) => Some(u64::from(n)),
                    Ok(Some(RegistryData::Qword(n))) => Some(n),
                    _ => None,
                };
                observations.push(
                    Fields::new()
                        .with("kind", kind)
                        .with(location::FIELD, location::classify(&name).as_str())
                        .with("name", location::last_segment(&name))
                        .maybe("count", count)
                        .with("path", name.clone())
                        .observe(ID),
                );
            }
        }
        measured(ID, observations, BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn counters_are_listed_per_kind_with_their_count() {
        let root = ROOT.replace('\\', "\\\\");
        let yaml = format!(
            "platform: windows\nregistry:\n  \"{root}\":\n    Dummy: 0\n  \"{root}\\\\AppSwitched\":\n    'C:\\Users\\a\\Desktop\\macro.exe': 12\n    'Microsoft.Windows.Explorer': 3\n  \"{root}\\\\AppLaunch\": {{}}\n"
        );
        let host = FixtureHost::from_yaml_str(&yaml, "inline").unwrap();
        let CollectorRun::Measured { observations, .. } = FeatureUsage.collect(&host) else {
            panic!("measured");
        };
        assert_eq!(observations.len(), 2);
        let macro_tool = &observations[0];
        assert_eq!(macro_tool.fields["kind"], "app_switched");
        assert_eq!(macro_tool.fields["count"], 12);
        assert_eq!(macro_tool.fields["location_kind"], "user_desktop");
        assert_eq!(observations[1].fields["location_kind"], "unknown");
    }
}
