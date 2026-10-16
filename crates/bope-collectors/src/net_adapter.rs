// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Network adapters Windows has a driver for, and the machine-wide proxy settings `net_config` does
//! not read (B.O.P.E, ADR 0112). `place` is the discriminator:
//!
//! - **`adapter`** — every subkey of the network adapter class
//!   `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`: its driver
//!   description, component id and provider, whether it is a software adapter (no `PCI\` or `USB\`
//!   component and not one of Microsoft's own `ms_` miniports) and whether its description names a
//!   tunnel or VPN driver (TAP, TUN, Wintun, `WireGuard`, `OpenVPN`, `ZeroTier`, Hamachi, Radmin).
//! - **`winhttp_proxy`** — whether `netsh winhttp set proxy` stored a proxy for services
//!   (`Internet Settings\Connections\WinHttpSettings` longer than the "direct" record).
//! - **`proxy_variable`** — which of `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` this
//!   program's environment holds — the names only, never the values.
//!
//! An adapter here is a driver that is installed, not a connection that was used: Windows keeps the
//! class entry after a VPN client is uninstalled, and a VPN, a virtual machine or a tunnel is no
//! evidence of cheating. No address, network name or connection history is read.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, reason, unmeasured};
use crate::{Collector, Field};

const ID: &str = "net_adapter";

/// The network adapter device class.
pub const CLASS_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
/// Where `netsh winhttp` stores its proxy.
pub const WINHTTP_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

const TUNNEL_WORDS: [&str; 9] = [
    "tap",
    "tun",
    "wintun",
    "wireguard",
    "openvpn",
    "zerotier",
    "hamachi",
    "radmin",
    "vpn",
];

static FIELDS: [Field; 8] = [
    Field::text("component_id"),
    Field::text("description"),
    Field::text("place"),
    Field::text("provider"),
    Field::boolean("set"),
    Field::boolean("software_adapter"),
    Field::boolean("tunnel_like"),
    Field::text("variable"),
];

static REASONS: [UnmeasuredReason; 4] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
];

/// The `net_adapter` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetAdapter;

/// Whether a driver description names a tunnel or VPN driver, by whole words.
pub fn tunnel_like(description: &str) -> bool {
    description
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| TUNNEL_WORDS.iter().any(|w| word.eq_ignore_ascii_case(w)))
}

fn text(host: &dyn Host, key: &str, value: &str) -> Option<String> {
    match host.read_value(key, value) {
        Ok(Some(RegistryData::Text(t))) if !t.trim().is_empty() => Some(t),
        _ => None,
    }
}

impl Collector for NetAdapter {
    fn id(&self) -> &'static str {
        ID
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn unmeasured_reasons(&self) -> &'static [UnmeasuredReason] {
        &REASONS
    }

    fn discriminator(&self) -> Option<&'static str> {
        Some("place")
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let mut observations = Vec::new();
        let subkeys = match host.subkeys(CLASS_KEY) {
            Ok(keys) => keys.unwrap_or_default(),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        };
        for subkey in subkeys
            .iter()
            .filter(|k| k.chars().all(|c| c.is_ascii_digit()))
        {
            let key = format!(r"{CLASS_KEY}\{subkey}");
            let description = text(host, &key, "DriverDesc");
            let component = text(host, &key, "ComponentId");
            if description.is_none() && component.is_none() {
                continue;
            }
            let lower = component
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let hardware = lower.starts_with(r"pci\")
                || lower.starts_with(r"usb\")
                || lower.starts_with("pci_");
            let microsoft = lower.starts_with("ms_");
            observations.push(
                Fields::new()
                    .with("place", "adapter")
                    .with(
                        "software_adapter",
                        !hardware && !microsoft && !lower.is_empty(),
                    )
                    .with(
                        "tunnel_like",
                        description.as_deref().is_some_and(tunnel_like) || tunnel_like(&lower),
                    )
                    .maybe("description", description)
                    .maybe("component_id", component)
                    .maybe("provider", text(host, &key, "ProviderName"))
                    .observe(ID),
            );
        }
        let winhttp = match host.read_bytes(WINHTTP_KEY, "WinHttpSettings") {
            Ok(Some(bytes)) => Some(winhttp_proxy_set(&bytes)),
            Ok(None) => Some(false),
            Err(_) => None,
        };
        observations.push(
            Fields::new()
                .with("place", "winhttp_proxy")
                .maybe("set", winhttp)
                .observe(ID),
        );
        for variable in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
            observations.push(
                Fields::new()
                    .with("place", "proxy_variable")
                    .with("variable", variable)
                    .with("set", host.env_var(variable).is_some_and(|v| !v.is_empty()))
                    .observe(ID),
            );
        }
        let discriminator_gaps = if winhttp.is_none() {
            vec![bope_core::model::DiscriminatorGaps {
                discriminator: "place".to_owned(),
                value: serde_json::Value::from("winhttp_proxy"),
                gaps: BTreeMap::from([("set".to_owned(), UnmeasuredReason::ReadFailed)]),
            }]
        } else {
            Vec::new()
        };
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

/// Whether a `WinHttpSettings` record names a proxy. The record starts with a version, a counter and a
/// flags word; flag `0x2` is "use a proxy server", and the direct-access record has flags `0x1`.
pub fn winhttp_proxy_set(bytes: &[u8]) -> bool {
    bytes
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .is_some_and(|flags| flags & 0x2 != 0)
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn tunnel_words_are_whole_words() {
        assert!(tunnel_like("TAP-Windows Adapter V9"));
        assert!(tunnel_like("WireGuard Tunnel"));
        assert!(tunnel_like("wintun"));
        assert!(!tunnel_like("Intel(R) Ethernet Connection I219-V"));
        assert!(!tunnel_like("Realtek Gaming Tunable Adapter"));
    }

    #[test]
    fn adapters_and_proxy_settings_are_reported_without_values() {
        let class = CLASS_KEY.replace('\\', "\\\\");
        let winhttp = WINHTTP_KEY.replace('\\', "\\\\");
        let host = FixtureHost::from_yaml_str(
            &format!(
                "platform: windows\nenv:\n  HTTPS_PROXY: 'http://secret:8080'\nregistry:\n  \"{class}\\\\0001\":\n    DriverDesc: 'Intel(R) Ethernet Connection'\n    ComponentId: 'PCI\\\\VEN_8086&DEV_15BC'\n  \"{class}\\\\0007\":\n    DriverDesc: 'TAP-Windows Adapter V9'\n    ComponentId: 'tap0901'\n    ProviderName: 'TAP-Windows Provider V9'\n  \"{class}\\\\0010\":\n    DriverDesc: 'WAN Miniport (IP)'\n    ComponentId: 'ms_ndiswanip'\n  \"{class}\\\\Properties\":\n    x: 1\n  \"{winhttp}\":\n    WinHttpSettings: {{ hex: '1800000000000000030000000e0000007072' }}\n"
            ),
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = NetAdapter.collect(&host) else {
            panic!("measured");
        };
        let adapters: Vec<_> = observations
            .iter()
            .filter(|o| o.fields["place"] == "adapter")
            .collect();
        assert_eq!(adapters.len(), 3);
        let tap = adapters
            .iter()
            .find(|o| o.fields["component_id"] == "tap0901")
            .unwrap();
        assert_eq!(tap.fields["software_adapter"], true);
        assert_eq!(tap.fields["tunnel_like"], true);
        let intel = adapters
            .iter()
            .find(|o| o.fields["description"] == "Intel(R) Ethernet Connection")
            .unwrap();
        assert_eq!(intel.fields["software_adapter"], false);
        let wan = adapters
            .iter()
            .find(|o| o.fields["component_id"] == "ms_ndiswanip")
            .unwrap();
        assert_eq!(wan.fields["software_adapter"], false);
        let proxy = observations
            .iter()
            .find(|o| o.fields["place"] == "winhttp_proxy")
            .unwrap();
        assert_eq!(proxy.fields["set"], true);
        let all = format!("{observations:?}");
        assert!(!all.contains("secret"));
        assert!(
            observations
                .iter()
                .any(|o| o.fields.get("variable") == Some(&"HTTPS_PROXY".into())
                    && o.fields["set"] == true)
        );
        assert!(
            observations
                .iter()
                .any(|o| o.fields.get("variable") == Some(&"HTTP_PROXY".into())
                    && o.fields["set"] == false)
        );
    }
}
