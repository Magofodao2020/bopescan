// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! What the firmware says the machine is, and whether that looks like a virtual machine
//! (B.O.P.E, ADR 0114).
//!
//! `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, which Windows fills from the SMBIOS tables at each start:
//! system manufacturer and product, board maker and product, BIOS vendor, version and release date.
//! `HKLM\SYSTEM\CurrentControlSet\Control\PEFirmwareType` says whether Windows started through UEFI
//! (2) or legacy BIOS (1). `vm_hint` is set when a manufacturer or product string names a hypervisor
//! vendor, and `guest_services` lists the virtual-machine guest drivers that are registered as
//! services.
//!
//! **What it cannot show.** A query inside Windows reads what the firmware **reports**; it cannot
//! prove the firmware's integrity, and SMBIOS strings can be set to anything by whoever controls the
//! firmware or the hypervisor. A virtual machine is no evidence of cheating, and a physical PC can be
//! made to report another maker.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, UnmeasuredReason};
use bope_host::{Host, Platform, RegistryData};

use crate::common::{Fields, measured, reason, unmeasured};
use crate::{Collector, Field};

const ID: &str = "machine_identity";

/// The SMBIOS summary Windows keeps.
pub const BIOS_KEY: &str = r"HKLM\HARDWARE\DESCRIPTION\System\BIOS";
/// Where the firmware type is kept.
pub const CONTROL_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control";

const VM_WORDS: [&str; 9] = [
    "vmware",
    "virtualbox",
    "innotek",
    "qemu",
    "xen",
    "parallels",
    "kvm",
    "bochs",
    "virtual machine",
];

/// Services registered by virtual-machine guest tools.
pub const GUEST_SERVICES: [&str; 8] = [
    "VBoxGuest",
    "VBoxSF",
    "VBoxService",
    "vmci",
    "vmhgfs",
    "VMTools",
    "vm3dmp",
    "QEMU-GA",
];

static FIELDS: [Field; 10] = [
    Field::text("bios_release_date"),
    Field::text("bios_vendor"),
    Field::text("bios_version"),
    Field::text("board_maker"),
    Field::text("board_product"),
    Field::text("firmware_type"),
    Field::text("guest_services"),
    Field::text("manufacturer"),
    Field::text("product"),
    Field::boolean("vm_hint"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::SourceAbsent,
];

/// The `machine_identity` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachineIdentity;

/// Whether an SMBIOS string names a hypervisor vendor.
pub fn names_hypervisor(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    VM_WORDS.iter().any(|w| lower.contains(w))
}

impl Collector for MachineIdentity {
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
        let read = |value: &str| -> Result<Option<String>, bope_host::SourceError> {
            Ok(match host.read_value(BIOS_KEY, value)? {
                Some(RegistryData::Text(t)) if !t.trim().is_empty() => Some(t.trim().to_owned()),
                _ => None,
            })
        };
        match host.value_names(BIOS_KEY) {
            Ok(Some(_)) => {}
            Ok(None) => return unmeasured(ID, UnmeasuredReason::SourceAbsent),
            Err(error) => return unmeasured(ID, reason(host, &error)),
        }
        let values = (|| {
            Ok::<_, bope_host::SourceError>((
                read("SystemManufacturer")?,
                read("SystemProductName")?,
                read("BaseBoardManufacturer")?,
                read("BaseBoardProduct")?,
                read("BIOSVendor")?,
                read("BIOSVersion")?,
                read("BIOSReleaseDate")?,
            ))
        })();
        let (manufacturer, product, board_maker, board_product, vendor, version, date) =
            match values {
                Ok(v) => v,
                Err(error) => return unmeasured(ID, reason(host, &error)),
            };
        let vm_hint = [&manufacturer, &product, &board_maker, &vendor]
            .iter()
            .any(|v| v.as_deref().is_some_and(names_hypervisor));
        let firmware_type = match host.read_u32(CONTROL_KEY, "PEFirmwareType") {
            Ok(Some(1)) => Some("bios"),
            Ok(Some(2)) => Some("uefi"),
            _ => None,
        };
        let guests: Vec<&str> = GUEST_SERVICES
            .iter()
            .copied()
            .filter(|s| {
                host.subkeys(&format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{s}"))
                    .ok()
                    .flatten()
                    .is_some()
            })
            .collect();
        let observation = Fields::new()
            .maybe("manufacturer", manufacturer)
            .maybe("product", product)
            .maybe("board_maker", board_maker)
            .maybe("board_product", board_product)
            .maybe("bios_vendor", vendor)
            .maybe("bios_version", version)
            .maybe("bios_release_date", date)
            .maybe("firmware_type", firmware_type)
            .with("vm_hint", vm_hint || !guests.is_empty())
            .maybe(
                "guest_services",
                (!guests.is_empty()).then(|| guests.join(", ")),
            )
            .observe(ID);
        measured(ID, vec![observation], BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn a_physical_pc_and_a_virtual_one_are_told_apart_by_their_strings() {
        let bios = BIOS_KEY.replace('\\', "\\\\");
        let physical = FixtureHost::from_yaml_str(
            &format!("platform: windows\nregistry:\n  \"{bios}\":\n    SystemManufacturer: 'Micro-Star International Co., Ltd.'\n    SystemProductName: 'MS-7C56'\n    BIOSVendor: 'American Megatrends International, LLC.'\n    BIOSVersion: 'A.60'\n    BIOSReleaseDate: '05/12/2024'\n  \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\":\n    PEFirmwareType: 2\n"),
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = MachineIdentity.collect(&physical) else {
            panic!("measured");
        };
        assert_eq!(observations[0].fields["vm_hint"], false);
        assert_eq!(observations[0].fields["firmware_type"], "uefi");
        assert_eq!(observations[0].fields["bios_version"], "A.60");

        let virtual_pc = FixtureHost::from_yaml_str(
            &format!("platform: windows\nregistry:\n  \"{bios}\":\n    SystemManufacturer: 'innotek GmbH'\n    SystemProductName: 'VirtualBox'\n  \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\VBoxGuest\\\\Parameters\":\n    x: 1\n  \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\VBoxGuest\":\n    Start: 0\n"),
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured { observations, .. } = MachineIdentity.collect(&virtual_pc)
        else {
            panic!("measured");
        };
        assert_eq!(observations[0].fields["vm_hint"], true);
        assert_eq!(observations[0].fields["guest_services"], "VBoxGuest");
    }
}
