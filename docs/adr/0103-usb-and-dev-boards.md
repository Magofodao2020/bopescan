<!--
SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

# ADR 0103 — USB devices, HID dev boards and setupapi

- Status: accepted
- Date: 2026-10-15
- Scope: B.O.P.E Scanner (modified version of aeterna-rongroi 0.9.0)

## Decision

`usb_device` reads the device list (`DeviceBus::Usb`), `USBSTOR` and `C:\Windows\INF\setupapi.dev.log`
(install section headers and local time text only). It flags vendor IDs of 14 development-board vendors
(Arduino, Teensy/PJRC, Raspberry Pi RP2040, Adafruit, SparkFun, Espressif, WCH, …) when the device also
exposes a HID keyboard/mouse interface — the BadUSB / hardware-macro pattern. A dev board alone is `info`.
Firmware that imitates an ordinary mouse cannot be told apart; that is a documented limit.
