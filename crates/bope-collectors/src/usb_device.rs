// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of
// scope — see AGENTS.md.

//! USB and HID devices Windows remembers, present or not, from three independent places
//! (B.O.P.E, ADR 0103). `source` is the discriminator:
//!
//! - **`device_list`** — the Plug and Play manager's list for the `USB` and `HID` enumerators
//!   (`bope_host::DeviceSource`): the model (vendor and product id, never the serial number), whether
//!   it is connected now, and its first-install, last-arrival and last-removal times.
//! - **`usbstor`** — the model names under `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB storage
//!   ever attached. The instance subkeys, which hold serial numbers, are not read.
//! - **`setupapi`** — `%SystemRoot%\INF\setupapi.dev.log`: each "Device Install" section for a `USB\`
//!   or `HID\` device with the time the log wrote. **That time is local time with no zone**; it is
//!   reported as text (`logged_local_time`), never converted, because the zone the PC had then is not
//!   recorded.
//!
//! `maker` names a vendor id from [`DEV_BOARD_VENDORS`] — makers of microcontroller and development
//! boards (Arduino, `SparkFun`, Adafruit, Raspberry Pi, Teensy's shared id, Espressif and the USB-serial
//! chips clone boards use). Such a board **enumerating as a keyboard or mouse** (`bus: hid`) is what an
//! input-automation device looks like — and also what a hand-built keyboard, a flight-simulator
//! button box or a macro pad looks like. A vendor id is whatever the device's firmware says; it can
//! be copied from any other device, so a board that claims to be a branded mouse is not seen here.
//! Windows does not log the keys a keyboard sends, so nothing here says what any device typed.

use std::collections::BTreeMap;

use bope_core::model::{CollectorRun, DiscriminatorGaps, Observation, UnmeasuredReason};
use bope_host::{DeviceBus, DeviceRecord, Host, Platform};

use crate::common::{Fields, env_folder, unmeasured};
use crate::{Collector, Field};

const ID: &str = "usb_device";
const DISCRIMINATOR: &str = "source";

/// The key whose subkeys name USB storage models.
pub const USBSTOR_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR";

/// Vendor ids of microcontroller and development-board makers, and of the USB-serial chips clone
/// boards carry, with the maker's name. Each is the vendor's registered USB-IF id.
pub const DEV_BOARD_VENDORS: [(&str, &str); 14] = [
    ("03EB", "Atmel / Microchip"),
    ("0483", "STMicroelectronics"),
    ("10C4", "Silicon Labs (CP210x)"),
    ("1209", "pid.codes (open hardware)"),
    ("16C0", "Van Ooijen / V-USB (Teensy, DigiSpark clones)"),
    ("16D0", "MCS Electronics (Digispark)"),
    ("1A86", "QinHeng (CH340)"),
    ("1B4F", "SparkFun"),
    ("1FC9", "NXP"),
    ("239A", "Adafruit"),
    ("2341", "Arduino"),
    ("2A03", "Arduino (arduino.org)"),
    ("2E8A", "Raspberry Pi (RP2040)"),
    ("303A", "Espressif"),
];

static FIELDS: [Field; 13] = [
    Field::text("bus"),
    Field::boolean("dev_board_vendor"),
    Field::timestamp("first_install"),
    Field::timestamp("last_arrival"),
    Field::timestamp("last_removal"),
    Field::text("logged_local_time"),
    Field::text("maker"),
    Field::text("model_id"),
    Field::text("pid"),
    Field::boolean("present"),
    Field::text("service"),
    Field::text("source"),
    Field::text("vid"),
];

static REASONS: [UnmeasuredReason; 5] = [
    UnmeasuredReason::NotWindows,
    UnmeasuredReason::NotAdmin,
    UnmeasuredReason::AccessDenied,
    UnmeasuredReason::ReadFailed,
    UnmeasuredReason::SourceAbsent,
];

/// The `usb_device` collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbDevice;

/// The four hex digits after `VID_` and `PID_` in a model id, upper case.
pub fn vid_pid(model_id: &str) -> (Option<String>, Option<String>) {
    let field = |prefix: &str| {
        model_id
            .split(['\\', '&'])
            .find_map(|part| {
                let upper = part.to_ascii_uppercase();
                upper
                    .strip_prefix(prefix)
                    .map(|v| v.chars().take(4).collect::<String>())
            })
            .filter(|v| v.len() == 4 && v.chars().all(|c| c.is_ascii_hexdigit()))
    };
    (field("VID_"), field("PID_"))
}

/// The maker of a development-board vendor id.
pub fn dev_board_maker(vid: &str) -> Option<&'static str> {
    DEV_BOARD_VENDORS
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(vid))
        .map(|(_, maker)| *maker)
}

fn model_fields(source: &str, bus: &str, model_id: &str) -> Fields {
    let (vid, pid) = vid_pid(model_id);
    let maker = vid.as_deref().and_then(dev_board_maker);
    Fields::new()
        .with(DISCRIMINATOR, source)
        .with("bus", bus)
        .with("model_id", model_id.to_owned())
        .with("dev_board_vendor", maker.is_some())
        .maybe("maker", maker)
        .maybe("vid", vid)
        .maybe("pid", pid)
}

fn device_observation(bus: &str, device: &DeviceRecord) -> Observation {
    model_fields("device_list", bus, &device.model_id)
        .with("present", device.present)
        .maybe("service", device.service.clone())
        .time("first_install", device.first_install)
        .time("last_arrival", device.last_arrival)
        .time("last_removal", device.last_removal)
        .observe(ID)
}

/// One "Device Install" section of `setupapi.dev.log`: the device id it names and the local time the
/// section started, as written (`YYYY/MM/DD HH:MM:SS.mmm`).
pub fn setupapi_installs(log: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;
    for line in log.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix(">>>  [Device Install") {
            pending = rest
                .split_once(" - ")
                .map(|(_, id)| id.trim_end().trim_end_matches(']').trim().to_owned());
        } else if let Some(rest) = line.strip_prefix(">>>  Section start ") {
            if let Some(id) = pending.take() {
                out.push((id, rest.trim().to_owned()));
            }
        } else if line.starts_with(">>>  [") {
            pending = None;
        }
    }
    out
}

impl Collector for UsbDevice {
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
        Some(DISCRIMINATOR)
    }

    fn collect(&self, host: &dyn Host) -> CollectorRun {
        if host.platform() != Platform::Windows {
            return unmeasured(ID, UnmeasuredReason::NotWindows);
        }
        let mut observations = Vec::new();
        let mut place_gaps: BTreeMap<&'static str, UnmeasuredReason> = BTreeMap::new();

        for (bus, name) in [(DeviceBus::Usb, "usb"), (DeviceBus::Hid, "hid")] {
            match host.devices(bus) {
                Ok(devices) => {
                    // One row per model and presence: several interfaces of one device share a model.
                    let mut seen = std::collections::BTreeSet::new();
                    for device in devices {
                        if seen.insert((device.model_id.clone(), device.present)) {
                            observations.push(device_observation(name, &device));
                        }
                    }
                }
                Err(error) => {
                    place_gaps
                        .entry("device_list")
                        .or_insert_with(|| crate::common::reason(host, &error));
                }
            }
        }

        match host.subkeys(USBSTOR_KEY) {
            Ok(Some(models)) => {
                for model in models {
                    observations.push(
                        Fields::new()
                            .with(DISCRIMINATOR, "usbstor")
                            .with("bus", "usbstor")
                            .with("model_id", format!(r"USBSTOR\{model}"))
                            .observe(ID),
                    );
                }
            }
            Ok(None) => {}
            Err(error) => {
                place_gaps.insert("usbstor", crate::common::reason(host, &error));
            }
        }

        let log_path = env_folder(host, "SystemRoot")
            .or_else(|| env_folder(host, "WinDir"))
            .map(|root| format!(r"{root}\INF\setupapi.dev.log"));
        match log_path.map(|p| host.read_file(&p)) {
            Some(Ok(Some(bytes))) => {
                let text = String::from_utf8_lossy(&bytes);
                for (id, time) in setupapi_installs(&text) {
                    let bus = if id.to_ascii_uppercase().starts_with(r"USB\") {
                        DeviceBus::Usb
                    } else if id.to_ascii_uppercase().starts_with(r"HID\") {
                        DeviceBus::Hid
                    } else {
                        continue;
                    };
                    let Some(model) = bope_host::device_model_id(bus, &id) else {
                        continue;
                    };
                    let bus_name = if bus == DeviceBus::Usb { "usb" } else { "hid" };
                    observations.push(
                        model_fields("setupapi", bus_name, &model)
                            .with("logged_local_time", time)
                            .observe(ID),
                    );
                }
            }
            Some(Ok(None)) => {}
            Some(Err(error)) => {
                place_gaps.insert("setupapi", crate::common::reason(host, &error));
            }
            None => {
                place_gaps.insert("setupapi", UnmeasuredReason::ReadFailed);
            }
        }

        let discriminator_gaps = place_gaps
            .into_iter()
            .map(|(place, reason)| DiscriminatorGaps {
                discriminator: DISCRIMINATOR.to_owned(),
                value: serde_json::Value::from(place),
                gaps: FIELDS
                    .iter()
                    .filter(|f| f.name != DISCRIMINATOR)
                    .map(|f| (f.name.to_owned(), reason))
                    .collect(),
            })
            .collect();
        CollectorRun::Measured {
            collector: ID.to_owned(),
            observations,
            gaps: BTreeMap::new(),
            discriminator_gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use bope_host::FixtureHost;

    use super::*;

    #[test]
    fn vendor_and_product_are_read_from_any_model_id() {
        assert_eq!(
            vid_pid(r"HID\VID_2341&PID_8036&MI_02&COL01"),
            (Some("2341".to_owned()), Some("8036".to_owned()))
        );
        assert_eq!(vid_pid(r"USBSTOR\Disk&Ven_X"), (None, None));
        assert_eq!(dev_board_maker("2341"), Some("Arduino"));
        assert_eq!(dev_board_maker("046D"), None);
    }

    #[test]
    fn setupapi_sections_pair_a_device_with_its_local_start_time() {
        let log = "[Boot Session: 2026/10/01 08:00:00.000]\n\n>>>  [Device Install (Hardware initiated) - USB\\VID_2341&PID_8036\\HIDPC0]\n>>>  Section start 2026/10/14 21:03:11.420\n     ump: Creating Install Process: DrvInst.exe\n<<<  Section end 2026/10/14 21:03:12.000\n>>>  [Setup Online Device Install]\n>>>  Section start 2026/10/14 21:04:00.000\n";
        assert_eq!(
            setupapi_installs(log),
            vec![(
                r"USB\VID_2341&PID_8036\HIDPC0".to_owned(),
                "2026/10/14 21:03:11.420".to_owned()
            )]
        );
    }

    #[test]
    fn three_sources_are_read_and_serials_never_reach_a_model() {
        let host = FixtureHost::from_yaml_str(
            r#"platform: windows
env:
  SystemRoot: 'C:\Windows'
devices:
  - { id: 'USB\VID_046D&PID_C52B\SERIAL123', present: true, first_install: '2026-01-01T00:00:00Z' }
  - { id: 'HID\VID_2341&PID_8036&MI_02\7&1&0&0000', present: false, last_removal: '2026-10-14T22:00:00Z' }
registry:
  'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\4C530001': { HardwareID: x }
filesystem:
  'C:\Windows\INF':
    - name: setupapi.dev.log
      content: ">>>  [Device Install (Hardware initiated) - HID\\VID_2341&PID_8036&MI_02\\7&1&0&0000]\n>>>  Section start 2026/10/14 21:03:11.420\n"
"#,
            "inline",
        )
        .unwrap();
        let CollectorRun::Measured {
            observations,
            discriminator_gaps,
            ..
        } = UsbDevice.collect(&host)
        else {
            panic!("measured");
        };
        assert!(discriminator_gaps.is_empty(), "{discriminator_gaps:?}");
        let all = format!("{observations:?}");
        assert!(
            !all.contains("SERIAL123") && !all.contains("4C530001"),
            "{all}"
        );
        let board = observations
            .iter()
            .find(|o| o.fields["source"] == "device_list" && o.fields["bus"] == "hid")
            .unwrap();
        assert_eq!(board.fields["dev_board_vendor"], true);
        assert_eq!(board.fields["maker"], "Arduino");
        assert_eq!(board.fields["present"], false);
        assert!(observations.iter().any(|o| o.fields["source"] == "usbstor"
            && o.fields["model_id"] == r"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00"));
        let logged = observations
            .iter()
            .find(|o| o.fields["source"] == "setupapi")
            .unwrap();
        assert_eq!(
            logged.fields["logged_local_time"],
            "2026/10/14 21:03:11.420"
        );
        assert_eq!(logged.fields["model_id"], r"HID\VID_2341&PID_8036&MI_02");
    }
}
