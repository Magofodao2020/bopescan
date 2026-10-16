// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! Text output of the CLI in Portuguese (Brazil), English and Thai.

use std::fmt::Write as _;

use bope_core::bundle::Bundle;
use bope_core::model::{BootTime, EvidenceState, Observation, ScanTier, UnmeasuredReason};
use bope_core::view::{EntrySource, ReportView, RowBand, Timeline};
use clap::ValueEnum;

/// Output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Lang {
    /// Portuguese (Brazil), B.O.P.E Scanner's default.
    #[value(name = "pt-br", alias = "pt")]
    Pt,
    /// English.
    En,
    /// Thai.
    Th,
}

impl Lang {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Pt => "pt-BR",
            Self::En => "en",
            Self::Th => "th",
        }
    }
}

const UNOFFICIAL: &str = "UNOFFICIAL BUILD";

fn text(lang: Lang, key: &str) -> &'static str {
    if lang == Lang::Pt {
        return crate::pt::text(key).unwrap_or_else(|| text(Lang::En, key));
    }
    match (lang, key) {
        (Lang::En, "unofficial") => {
            "not built by the aeterna-rongroi release workflow. Do not rely on this result."
        }
        (Lang::Th, "unofficial") => "ไม่ได้สร้างจากระบบ release ของ aeterna-rongroi อย่าเชื่อผลตรวจนี้",
        (Lang::En, "official") => "official build",
        (Lang::Th, "official") => "build ทางการ",
        (Lang::En, "found") => "FOUND",
        (Lang::Th, "found") => "เจอ",
        (Lang::En, "not_found") => "NOT FOUND",
        (Lang::Th, "not_found") => "ไม่เจอ",
        (Lang::En, "unmeasured_expected") => "NOT MEASURED (expected here)",
        (Lang::Th, "unmeasured_expected") => "ยังไม่ได้วัด (เป็นเรื่องปกติของเครื่องนี้)",
        (Lang::En, "unmeasured_unexpected") => "NOT MEASURED (not expected)",
        (Lang::Th, "unmeasured_unexpected") => "ยังไม่ได้วัด (ไม่ได้คาดไว้)",
        // The rule's own description, beside every state: it says what the check means and what it
        // does not prove, which is the sentence that stops a single row being read as a verdict.
        (Lang::En, "description") => "About this check",
        (Lang::Th, "description") => "เกี่ยวกับการตรวจนี้",
        // NIST SP 800-86 section 3.4's alternative explanations, beside a `found` row only.
        (Lang::En, "falsepositives") => "Ordinary things that also produce this",
        (Lang::Th, "falsepositives") => "เรื่องปกติที่ทำให้เกิดผลแบบนี้ได้เหมือนกัน",
        (Lang::En, "scope_not_admin") => {
            "Scope: {n} check(s) could not be answered because this scan does not have administrator \
             rights. Running it again as administrator answers them."
        }
        (Lang::Th, "scope_not_admin") => {
            "ขอบเขตการตรวจ: มี {n} รายการที่ตอบไม่ได้เพราะการสแกนครั้งนี้ไม่มีสิทธิ์ผู้ดูแลระบบ \
             เปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบแล้วจะตอบได้"
        }
        // The same shape as the line above and for the same reason: one fact about how far the scan
        // got, said once, rather than a row per rule it stopped (ADR 0030).
        (Lang::En, "scope_not_attempted") => {
            "Scope: {n} check(s) could not be answered because this program stopped reading before \
             it reached what they ask about. That is this program's limit, not a finding about \
             this PC."
        }
        (Lang::Th, "scope_not_attempted") => {
            "ขอบเขตการตรวจ: มี {n} รายการที่ตอบไม่ได้เพราะโปรแกรมหยุดอ่านก่อนจะถึงส่วนที่รายการนั้นถาม \
             เป็นข้อจำกัดของโปรแกรมนี้เอง ไม่ใช่สิ่งที่ตรวจเจอในเครื่องนี้"
        }
        // The same shape again: one fact about which scan the player chose (ADR 0052).
        (Lang::En, "scope_not_consented") => {
            "Scope: {n} check(s) were not answered because they read only in a full scan, and the \
             standard scan was chosen. A full scan asks before it starts."
        }
        (Lang::Th, "scope_not_consented") => {
            "ขอบเขตการตรวจ: มี {n} รายการที่ไม่ได้ตอบ เพราะอ่านเฉพาะการสแกนแบบ Full และครั้งนี้เลือกการสแกนแบบมาตรฐาน \
             การสแกนแบบ Full จะถามก่อนเริ่มทุกครั้ง"
        }
        // Context for reading every time below it, never a finding: the sentence after the time is
        // what stops "started three days ago" being read as something the player did (ADR 0039).
        (Lang::En, "boot_time") => {
            "Windows start: {at}, {since} before this scan. Not reset by \"Shut down\" with Fast \
             Startup (the Windows default), sleep or hibernation; reset by a restart."
        }
        (Lang::Th, "boot_time") => {
            "Windows เริ่มทำงาน: {at} ({since} ก่อนการสแกนนี้) การกด \"Shut down\" ขณะเปิด Fast Startup \
             (ค่าเริ่มต้นของ Windows) การ sleep และการ hibernate ไม่ทำให้ค่านี้เริ่มใหม่ การ restart ทำให้เริ่มใหม่"
        }
        (Lang::En, "boot_time_unmeasured") => "Windows start: not measured — {reason}",
        (Lang::Th, "boot_time_unmeasured") => "Windows เริ่มทำงาน: ยังไม่ได้วัด — {reason}",
        (Lang::En, "own_traces") => "own traces (excluded)",
        (Lang::Th, "own_traces") => "ร่องรอยของโปรแกรมนี้เอง (แยกออกแล้ว)",
        (Lang::En, "own_traces_note") => {
            "what this program itself left in what was read; not evidence about this PC"
        }
        (Lang::Th, "own_traces_note") => "สิ่งที่โปรแกรมนี้ทิ้งไว้เองในสิ่งที่อ่านมา ไม่ใช่หลักฐานเกี่ยวกับเครื่องนี้",
        (Lang::En, "unmatched") => "unmatched observations",
        (Lang::Th, "unmatched") => "สิ่งที่เห็นแต่ไม่ตรง rule ใดเลย",
        (Lang::En, "unmatched_note") => {
            "what the collectors saw that no rule matched; these are things that were seen, not findings"
        }
        (Lang::Th, "unmatched_note") => {
            "สิ่งที่ collector เห็นแต่ไม่มี rule ไหนตรงเลย เป็นสิ่งที่เห็น ไม่ใช่สิ่งที่ตรวจเจอ"
        }
        (Lang::En, "footer") => "Evidence only. This report cannot prove that a PC is clean.",
        (Lang::Th, "footer") => "เป็นหลักฐานประกอบเท่านั้น รายงานนี้พิสูจน์ไม่ได้ว่าเครื่องสะอาด",
        // Three counts of what this view lists, never one number (ADR 0045).
        (Lang::En, "listed") => {
            "Listed: {found} found · {not_found} not found · {unmeasured} not measured"
        }
        (Lang::Th, "listed") => {
            "รายการที่แสดง: เจอ {found} · ไม่เจอ {not_found} · ยังไม่ได้วัด {unmeasured}"
        }
        (Lang::En, "code") => "Code: {url}",
        (Lang::Th, "code") => "โค้ด: {url}",
        (Lang::En, "code_unknown") => {
            "Code: {url} (the code this build was made from is not known)"
        }
        (Lang::Th, "code_unknown") => "โค้ด: {url} (ไม่รู้ว่า build นี้สร้างจากโค้ดของ commit ไหน)",
        (Lang::En, "elevated_yes") => "administrator",
        (Lang::Th, "elevated_yes") => "สิทธิ์ผู้ดูแลระบบ",
        (Lang::En, "elevated_no") => "standard user",
        (Lang::Th, "elevated_no") => "ผู้ใช้ทั่วไป",
        (_, "elevated_unknown") => "?",
        _ => text_elevate(lang, key),
    }
}

/// Text for the elevation and consent flow, kept apart from [`text`] so that function stays under
/// clippy's line limit.
fn text_elevate(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::En, "elevate_started") => {
            "Starting again with administrator rights. The new window does the scan."
        }
        (Lang::Th, "elevate_started") => "กำลังเปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบ หน้าต่างใหม่จะเป็นตัวสแกน",
        (Lang::En, "elevate_declined") => {
            "The administrator prompt was declined. Nothing was scanned."
        }
        (Lang::Th, "elevate_declined") => "ไม่ได้อนุญาตสิทธิ์ผู้ดูแลระบบ ยังไม่ได้สแกนอะไร",
        (Lang::En, "elevate_failed") => "could not start again with administrator rights",
        (Lang::Th, "elevate_failed") => "เปิดใหม่ด้วยสิทธิ์ผู้ดูแลระบบไม่สำเร็จ",
        (Lang::En, "elevate_not_windows") => {
            "Administrator rights are a Windows idea; --elevate does nothing on this system."
        }
        // The elevated copy runs in a console window of its own, which Windows closes the moment
        // the process exits (ADR 0012, amended).
        (Lang::En, "pause_at_exit") => "Press Enter to close this window.",
        (Lang::Th, "pause_at_exit") => "กด Enter เพื่อปิดหน้าต่างนี้",
        (Lang::Th, "elevate_not_windows") => "สิทธิ์ผู้ดูแลระบบเป็นเรื่องของ Windows --elevate ไม่มีผลบนระบบนี้",
        _ => text_timeline(lang, key),
    }
}

/// Text for the timeline section (ADR 0051).
fn text_timeline(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        // The same word in both languages, as the Thai text uses it.
        (_, "timeline") => "timeline",
        // What the section never says, said above it (ADR 0051 decision 6).
        (Lang::En, "timeline_note") => {
            "the times this report holds, oldest first. An order of recorded times is not an order of \
             events, and a record that is absent was not necessarily removed. A time a folder listing \
             reports is what the file system says, which the program that wrote the file can set."
        }
        (Lang::Th, "timeline_note") => {
            "เวลาที่รายงานนี้มี เรียงจากเก่าไปใหม่ ลำดับของเวลาที่ถูกบันทึกไม่ใช่ลำดับของเหตุการณ์ \
             และบันทึกที่ไม่มีอยู่ไม่ได้แปลว่าถูกลบ เวลาที่ได้จากการอ่านรายชื่อไฟล์ในโฟลเดอร์เป็นเวลาที่ระบบไฟล์รายงาน \
             ซึ่งโปรแกรมที่เขียนไฟล์ตั้งเองได้"
        }
        (Lang::En, "coverage") => "can show",
        (Lang::Th, "coverage") => "ครอบคลุมช่วง",
        (Lang::En, "coverage_note") => {
            "nothing can be read from a source outside the span it can show"
        }
        (Lang::Th, "coverage_note") => "นอกช่วงที่แหล่งหนึ่งครอบคลุม แหล่งนั้นไม่ได้บอกอะไรเลย",
        (Lang::En, "not_measured") => "not measured",
        (Lang::Th, "not_measured") => "ยังไม่ได้วัด",
        (Lang::En, "scan_time") => "this scan ran",
        (Lang::Th, "scan_time") => "เวลาที่สแกน",
        (Lang::En, "boot_anchor") => "Windows started",
        (Lang::Th, "boot_anchor") => "Windows เริ่มทำงานครั้งล่าสุด",
        (Lang::En, "selectors") => "What the selected times mean",
        (Lang::Th, "selectors") => "ความหมายของเวลาที่ถูกเลือกมาแสดง",
        (Lang::En, "selector_causes") => "Ordinary things behind these times",
        (Lang::Th, "selector_causes") => "เรื่องปกติที่อยู่เบื้องหลังเวลาเหล่านี้",
        // The span a row's count is for, beside the row (ADR 0047, amendment of 2026-09-30).
        (Lang::En, "row_band_found") => {
            "The source held only {from} to {to} when it was read; what is counted here is from that span."
        }
        (Lang::Th, "row_band_found") => "ตอนที่อ่าน แหล่งนี้มีข้อมูลแค่ช่วง {from} ถึง {to} สิ่งที่นับได้ที่นี่มาจากช่วงนี้",
        (Lang::En, "row_band_not_found") => {
            "Nothing within this span: {from} to {to}, what the source held when it was read. Nothing \
             before it was seen."
        }
        (Lang::Th, "row_band_not_found") => {
            "ไม่มีอะไรในช่วงนี้: {from} ถึง {to} ซึ่งเป็นช่วงที่แหล่งนี้มีข้อมูลตอนที่อ่าน ก่อนหน้านั้นมองไม่เห็นเลย"
        }
        (Lang::En, "row_band_none") => {
            "The source held no record when it was read, so there is no span in which anything could \
             be seen."
        }
        (Lang::Th, "row_band_none") => "ตอนที่อ่าน แหล่งนี้ไม่มี record เลย จึงไม่มีช่วงที่จะเห็นอะไรได้",
        _ => "",
    }
}

/// The words about which scan ran and what the player agreed to show (ADR 0052), apart from [`text`]
/// so neither table grows past what one screen can check.
fn scan_text(lang: Lang, key: &str) -> &'static str {
    if lang == Lang::Pt {
        return crate::pt::text(key).unwrap_or_else(|| scan_text(Lang::En, key));
    }
    match (lang, key) {
        (Lang::En, "tier_standard") => "standard scan",
        (Lang::Th, "tier_standard") => "สแกนแบบมาตรฐาน",
        (Lang::En, "tier_full") => "full scan",
        (Lang::Th, "tier_full") => "สแกนแบบ Full",
        (Lang::En, "full_declined") => {
            "Standard scan: the sources only a full scan reads are not read."
        }
        (Lang::Th, "full_declined") => "สแกนแบบมาตรฐาน: ไม่อ่านแหล่งข้อมูลที่อ่านเฉพาะการสแกนแบบ Full",
        _ => "",
    }
}

/// The one line a non-expert reads beside an unmeasured result.
///
/// Two rules, both borrowed and both about not letting a state read as an accusation (ADR 0030):
/// name the thing that was not seen and never the person, and say it about the record or about this
/// program rather than about the machine's owner. The same fourteen strings are in
/// `apps/desktop/src/locales/<lang>/report.json` under `reason.*`; the CLI does not load those files,
/// so the two are kept in step by `every_reason_has_a_word_in_both_languages` here and by
/// `check-locales` there.
pub(crate) fn reason(lang: Lang, reason: UnmeasuredReason) -> &'static str {
    match (lang, reason) {
        (Lang::Pt, reason) => bope_core::export::reason_label(reason),
        (Lang::En, UnmeasuredReason::NotWindows) => "not running on Windows",
        (Lang::Th, UnmeasuredReason::NotWindows) => "ไม่ได้รันบน Windows",
        (Lang::En, UnmeasuredReason::NotOnThisOs) => {
            "this version of Windows does not keep this record"
        }
        (Lang::Th, UnmeasuredReason::NotOnThisOs) => "Windows รุ่นนี้ไม่ได้เก็บข้อมูลส่วนนี้",
        (Lang::En, UnmeasuredReason::NotAdmin) => {
            "Windows would not show this without administrator rights"
        }
        (Lang::Th, UnmeasuredReason::NotAdmin) => "ต้องมีสิทธิ์ผู้ดูแลระบบ Windows จึงจะให้อ่าน",
        (Lang::En, UnmeasuredReason::NotAttempted) => {
            "this was not read — the scan stopped before reaching it"
        }
        (Lang::Th, UnmeasuredReason::NotAttempted) => "ไม่ได้อ่านส่วนนี้ เพราะการสแกนหยุดก่อนจะถึง",
        (Lang::En, UnmeasuredReason::AccessDenied) => "Windows refused to open this",
        (Lang::Th, UnmeasuredReason::AccessDenied) => "Windows ไม่อนุญาตให้เปิดอ่าน",
        (Lang::En, UnmeasuredReason::ServiceDisabled) => {
            "the Windows service that writes this record is switched off"
        }
        (Lang::Th, UnmeasuredReason::ServiceDisabled) => "บริการของ Windows ที่เขียนข้อมูลนี้ถูกปิดอยู่",
        (Lang::En, UnmeasuredReason::SourceAbsent) => "this PC has no such record to read",
        (Lang::Th, UnmeasuredReason::SourceAbsent) => "เครื่องนี้ไม่มีข้อมูลส่วนนี้ให้อ่าน",
        (Lang::En, UnmeasuredReason::SourceEmpty) => {
            "the place this is kept is there and holds nothing"
        }
        (Lang::Th, UnmeasuredReason::SourceEmpty) => "มีที่เก็บข้อมูลอยู่ แต่ว่างเปล่า",
        (Lang::En, UnmeasuredReason::Partial) => "part of this was read and part of it was not",
        (Lang::Th, UnmeasuredReason::Partial) => "อ่านได้บางส่วน ไม่ครบ",
        (Lang::En, UnmeasuredReason::BudgetSpent) => {
            "this program stopped reading before it finished"
        }
        (Lang::Th, UnmeasuredReason::BudgetSpent) => "โปรแกรมนี้หยุดอ่านก่อนจะครบ",
        (Lang::En, UnmeasuredReason::ReadFailed) => "this could not be read",
        (Lang::Th, UnmeasuredReason::ReadFailed) => "อ่านข้อมูลนี้ไม่ได้",
        (Lang::En, UnmeasuredReason::CollectorUnavailable) => "this build does not read that",
        (Lang::Th, UnmeasuredReason::CollectorUnavailable) => "build นี้ยังไม่ได้อ่านส่วนนี้",
        (Lang::En, UnmeasuredReason::NotConsented) => {
            "only a full scan reads this, and this was the standard scan"
        }
        (Lang::Th, UnmeasuredReason::NotConsented) => {
            "ส่วนนี้อ่านเฉพาะการสแกนแบบ Full และครั้งนี้เป็นการสแกนแบบมาตรฐาน"
        }
        // One drive's journal is read, by design, so nothing failed (ADR 0047, amendment of 2026-09-30).
        (Lang::En, UnmeasuredReason::OtherVolume) => {
            "this is on another drive, and this program reads only the system drive's change journal"
        }
        (Lang::Th, UnmeasuredReason::OtherVolume) => {
            "ส่วนนี้อยู่บนไดรฟ์อื่น และโปรแกรมนี้อ่าน change journal ของไดรฟ์ระบบเท่านั้น"
        }
    }
}

/// What a full scan reads beyond the standard one, in the words `PRIVACY.md` uses (ADR 0052, ADR 0055).
fn full_reads(lang: Lang) -> [&'static str; 7] {
    match lang {
        Lang::Pt => crate::pt::FULL_READS,
        Lang::En => [
            "the name of each server cache folder FiveM for GTA V Enhanced keeps — one per server \
             this PC joined — with when it was created and last changed. What the name is made from is \
             not known; it stays the same for that server on this PC, so it can match two reports of \
             this PC",
            "the words in PowerShell's commands, kept only as kinds — whether a command downloaded \
             something and ran it, told Microsoft Defender to look away, cleared a log or history, or \
             named FiveM — from the history of commands typed into a PowerShell window, the scripts \
             Windows PowerShell flagged as suspicious, and the command lines it was started with, with \
             how many and when. No command is kept or shown; the one thing kept is the name of a website \
             a command downloaded from",
            "the extensions in each Chrome, Edge, Brave, Opera, Vivaldi and Firefox profile: id, name, \
             version and whether they can reach roblox.com or every site, run user scripts or control \
             DevTools — never history, cookies, passwords or what a page holds",
            "in Downloads, Desktop and Documents, one level deep: programs, archives and scripts by \
             name and time, with SHA-256, signature and the Mark of the Web Windows attached when they \
             were downloaded, with the website's name, which \
             executor-only functions each .lua script calls, never its text, and the names of AutoHotkey, \
             AutoIt and other macro files",
            "Explorer's lists: programs started from the Run box (RunMRU, never their arguments), \
             folders typed in the address bar (TypedPaths), recently opened programs, scripts and \
             archives (RecentDocs, only those file types) and the programs that last used an Open or \
             Save dialog",
            "the NTFS Master File Table of the Windows drive, read raw and read-only: every file record's \
             name passes through memory once and only names matching the Roblox tool catalog are kept, \
             with their folder, NTFS times and whether the record is still in use or was freed by a \
             deletion — never a file's content",
            "folders Explorer remembers (ShellBags) and the files the Open/Save dialog remembers \
             (OpenSavePidlMRU): only paths with a name matching the Roblox tool catalog or naming Roblox",
        ],
        Lang::Th => [
            "ชื่อโฟลเดอร์ cache ของแต่ละเซิร์ฟเวอร์ที่ FiveM for GTA V Enhanced เก็บไว้ \
             หนึ่งโฟลเดอร์ต่อหนึ่งเซิร์ฟเวอร์ที่เครื่องนี้เคยเข้า พร้อมเวลาที่สร้างกับเวลาที่แก้ไขล่าสุด \
             ยังไม่รู้ว่าชื่อนี้คำนวณมาจากอะไร แต่ชื่อของเซิร์ฟเวอร์เดิมบนเครื่องนี้จะเหมือนเดิม \
             จึงจับคู่รายงานสองฉบับจากเครื่องนี้ได้",
            "คำในคำสั่ง PowerShell โดยเก็บไว้แค่เป็นชนิด — คำสั่งนั้นดาวน์โหลดแล้วรันอะไรหรือไม่ สั่งให้ Microsoft Defender \
             มองข้ามบางอย่างหรือไม่ ล้าง log หรือประวัติหรือไม่ หรือพูดถึง FiveM หรือไม่ — จากประวัติคำสั่งที่พิมพ์ในหน้าต่าง \
             PowerShell, script ที่ Windows PowerShell ตั้งธงว่าน่าสงสัย และ command line ที่ใช้เปิดมัน พร้อมจำนวนและเวลา \
             ไม่เก็บและไม่แสดงคำสั่งใด ๆ สิ่งเดียวที่เก็บคือชื่อเว็บไซต์ที่คำสั่งดาวน์โหลดมา",
            "extension ในแต่ละโปรไฟล์ของ Chrome, Edge, Brave, Opera, Vivaldi และ Firefox: id ชื่อ เวอร์ชัน \
             และเข้าถึง roblox.com หรือทุกเว็บได้หรือไม่ รัน user script หรือควบคุม DevTools ได้หรือไม่ \
             ไม่อ่านประวัติ คุกกี้ รหัสผ่าน หรือเนื้อหาของหน้าเว็บ",
            "ใน Downloads, Desktop และ Documents ลึกหนึ่งชั้น: โปรแกรม ไฟล์บีบอัด และ script ตามชื่อและเวลา \
             พร้อม SHA-256 ลายเซ็น และ Mark of the Web ที่ Windows แนบตอนดาวน์โหลด พร้อมชื่อเว็บไซต์ \
             ฟังก์ชันที่มีเฉพาะใน executor ที่ script .lua แต่ละไฟล์เรียกใช้ โดยไม่เก็บเนื้อหา \
             และชื่อไฟล์ macro ของ AutoHotkey, AutoIt และอื่น ๆ",
            "รายการของ Explorer: โปรแกรมที่เปิดจากกล่อง Run (RunMRU ไม่อ่าน argument) โฟลเดอร์ที่พิมพ์ในแถบที่อยู่ \
             (TypedPaths) โปรแกรม script และไฟล์บีบอัดที่เปิดล่าสุด (RecentDocs เฉพาะชนิดไฟล์เหล่านั้น) \
             และโปรแกรมที่ใช้หน้าต่าง Open หรือ Save ล่าสุด",
            "Master File Table ของ NTFS บนไดรฟ์ Windows อ่านแบบ raw และอ่านอย่างเดียว: เก็บเฉพาะชื่อที่ตรงกับรายการเครื่องมือ Roblox \
             พร้อมโฟลเดอร์ เวลาของ NTFS และ record ยังใช้งานอยู่หรือถูกปล่อยจากการลบ ไม่อ่านเนื้อหาไฟล์",
            "โฟลเดอร์ที่ Explorer จำไว้ (ShellBags) และไฟล์ที่หน้าต่าง Open/Save จำไว้ (OpenSavePidlMRU) \
             เฉพาะ path ที่มีชื่อตรงกับรายการเครื่องมือ Roblox หรือมีคำว่า Roblox",
        ],
    }
}

/// The question `scan --full` asks before any collector runs (ADR 0052). Only `yes` starts a full scan.
pub fn full_question(lang: Lang) -> String {
    match lang {
        Lang::Pt => crate::pt::full_question(&full_reads(lang).join("\n  - ")),
        Lang::En => format!(
            "Full scan — this reads more than the standard scan:\n  - {}\nNothing is sent \
             anywhere.\nType yes for the full scan; anything else starts the \
             standard scan: ",
            full_reads(lang).join("\n  - ")
        ),
        Lang::Th => format!(
            "การสแกนแบบ Full — อ่านมากกว่าการสแกนแบบมาตรฐาน:\n  - {}\nไม่ส่งอะไรออกไปไหน\n\
             พิมพ์ yes เพื่อสแกนแบบ Full พิมพ์อย่างอื่นจะเป็นการสแกนแบบมาตรฐาน: ",
            full_reads(lang).join("\n  - ")
        ),
    }
}

/// Printed when the full-scan question was not answered `yes`.
pub fn full_declined(lang: Lang) -> &'static str {
    scan_text(lang, "full_declined")
}

/// Line shown before an elevated copy waits for Enter, so its window does not close on the report.
pub fn pause_at_exit(lang: Lang) -> &'static str {
    text(lang, "pause_at_exit")
}

/// Message printed once the elevated restart has been requested.
#[cfg(windows)]
pub fn elevate_started(lang: Lang) -> &'static str {
    text(lang, "elevate_started")
}

/// Message printed when the Windows consent prompt was dismissed.
#[cfg(windows)]
pub fn elevate_declined(lang: Lang) -> &'static str {
    text(lang, "elevate_declined")
}

/// Context added to the error when Windows refused to start the elevated program.
#[cfg(windows)]
pub fn elevate_failed(lang: Lang) -> &'static str {
    text(lang, "elevate_failed")
}

/// Message printed when `--elevate` is used on something other than Windows.
#[cfg(not(windows))]
pub fn elevate_not_windows(lang: Lang) -> &'static str {
    text(lang, "elevate_not_windows")
}

/// Renders a view as text.
pub fn render(view: &ReportView, bundle: &Bundle, lang: Lang) -> String {
    let mut out = String::new();
    let header = &view.header;
    let provenance = &header.provenance;

    let _ = writeln!(
        out,
        "B.O.P.E Scanner {} (based on aeterna-rongroi; modified version)",
        provenance.version
    );
    if provenance.official {
        let _ = writeln!(out, "{}", text(lang, "official"));
    } else {
        let _ = writeln!(out, "!! {UNOFFICIAL} — {}", text(lang, "unofficial"));
    }
    let elevated = match header.elevated {
        Some(true) => text(lang, "elevated_yes"),
        Some(false) => text(lang, "elevated_no"),
        None => text(lang, "elevated_unknown"),
    };
    let platform = match &header.os_build {
        Some(build) => format!("{} {build}", header.platform),
        None => header.platform.clone(),
    };
    let tier = match header.scan_tier {
        ScanTier::Standard => scan_text(lang, "tier_standard"),
        ScanTier::Full => scan_text(lang, "tier_full"),
    };
    let _ = writeln!(
        out,
        "{tier} · {platform} · {elevated} · rules: {} ({})",
        header.rules_bundle.rule_count,
        short(&header.rules_bundle.sha256),
    );
    if let Some(sha) = &provenance.exe_sha256 {
        let _ = writeln!(out, "exe sha256: {sha}");
    }
    let _ = writeln!(out, "{}", boot_time_line(&header.boot_time, lang));
    // Above the evidence, because it is a fact about the scan and not about the machine, and
    // because a reviewer who has made up their mind by the third row never reaches a footer
    // (ADR 0027).
    for (count, key) in [
        (view.scope.not_admin, "scope_not_admin"),
        (view.scope.not_attempted, "scope_not_attempted"),
        (view.scope.not_consented, "scope_not_consented"),
    ] {
        if count > 0 {
            let _ = writeln!(
                out,
                "{}",
                text(lang, key).replace("{n}", &count.to_string())
            );
        }
    }
    let _ = writeln!(
        out,
        "{}",
        text(lang, "listed")
            .replace("{found}", &view.listed.found.to_string())
            .replace("{not_found}", &view.listed.not_found.to_string())
            .replace("{unmeasured}", &view.listed.unmeasured.to_string())
    );
    out.push('\n');

    out.push_str(&assessment_section(view, bundle, lang));

    out.push_str(&evidence_section(view, bundle, lang));

    // Above the timeline, only when its conditions hold (ADR 0061 section 3).
    out.push_str(&crate::trace_ages::statement(&view.cross_source, lang));

    out.push_str(&timeline_section(&view.timeline, bundle, lang));

    // Beside the timeline: how far back each source reaches (ADR 0061).
    out.push_str(&crate::trace_ages::section(&view.trace_ages, bundle, lang));

    // Both sections come after the evidence and clearly apart from it, in this order.
    out.push_str(&own_traces_section(view, lang));
    out.push_str(&unmatched_section(view, lang));

    let code = if provenance.code_commit().is_some() {
        "code"
    } else {
        "code_unknown"
    };
    let _ = writeln!(
        out,
        "\n{}",
        text(lang, code).replace("{url}", &provenance.code_url())
    );
    let _ = writeln!(out, "{}", text(lang, "footer"));
    out
}

/// The B.O.P.E assessment above the evidence, when the view carries one (ADR 0100). It reads the
/// evidence and never replaces it; in every language the categories and the conclusion use the
/// Portuguese labels of `bope_core::export`, which are the product's own words.
fn assessment_section(view: &ReportView, bundle: &Bundle, lang: Lang) -> String {
    use bope_core::export::{category_label, conclusion_label, conclusion_note, state_label};
    let Some(assessment) = &view.assessment else {
        return String::new();
    };
    let mut out = String::new();
    let _ = writeln!(out, "== AVALIAÇÃO / ASSESSMENT ==");
    let _ = writeln!(
        out,
        "{}\n  {}",
        conclusion_label(assessment.conclusion),
        conclusion_note(assessment.conclusion)
    );
    for category in &assessment.categories {
        let _ = writeln!(
            out,
            "  [{:<14}] {}{}",
            state_label(category.state),
            category_label(&category.category),
            if category.partial { " (parcial)" } else { "" }
        );
    }
    for item in &assessment.supporting {
        let title = bundle
            .text(&item.rule_id, lang.code())
            .map_or_else(|| item.rule_id.clone(), |t| t.title);
        let _ = writeln!(
            out,
            "  -> {} {title} ({})",
            match item.level {
                bope_core::assessment::Level::Flag => "FLAG",
                bope_core::assessment::Level::Warn => "WARN",
                bope_core::assessment::Level::Info => "INFO",
            },
            item.source
        );
    }
    for caveat in &assessment.caveats {
        let _ = writeln!(out, "  * {}", bope_core::export::caveat_label(caveat));
    }
    out.push('\n');
    out
}

/// The one line of context that says when Windows last started counting (ADR 0039).
fn boot_time_line(boot_time: &BootTime, lang: Lang) -> String {
    match boot_time {
        BootTime::Measured {
            booted_at,
            seconds_since_boot,
        } => text(lang, "boot_time")
            .replace("{at}", booted_at)
            .replace("{since}", &elapsed(*seconds_since_boot, lang)),
        BootTime::Unmeasured { reason: why } => {
            text(lang, "boot_time_unmeasured").replace("{reason}", reason(lang, *why))
        }
    }
}

/// Whole seconds as days, hours and minutes; days only when there is at least one.
fn elapsed(seconds: u64, lang: Lang) -> String {
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    match (lang, days) {
        (Lang::Pt, _) => crate::pt::elapsed(days, hours, minutes),
        (Lang::En, 0) => format!("{hours}h {minutes}m"),
        (Lang::En, _) => format!("{days}d {hours}h {minutes}m"),
        (Lang::Th, 0) => format!("{hours} ชม. {minutes} นาที"),
        (Lang::Th, _) => format!("{days} วัน {hours} ชม. {minutes} นาที"),
    }
}

/// The evidence, one entry at a time, each with the rule's own text.
fn evidence_section(view: &ReportView, bundle: &Bundle, lang: Lang) -> String {
    let mut out = String::new();
    // A rule title states what the rule looks for, not what was seen; say so for every state.
    let check = match lang {
        Lang::Pt => "verificação",
        Lang::En => "check",
        Lang::Th => "ตรวจ",
    };
    for evidence in &view.evidence {
        let rule_text = bundle.text(&evidence.rule_id, lang.code());
        let title = rule_text
            .as_ref()
            .map_or_else(|| evidence.rule_id.clone(), |t| t.title.clone());
        let (label, detail) = match &evidence.state {
            EvidenceState::Found { observations } => {
                let fields = observations
                    .iter()
                    .flat_map(|o| o.fields.iter().map(|(k, v)| format!("{k}={}", plain(v))))
                    .collect::<Vec<_>>()
                    .join(", ");
                (text(lang, "found"), fields)
            }
            // The report keeps the English source text; the rule text carries the translation.
            EvidenceState::NotFound { retention } => (
                text(lang, "not_found"),
                rule_text
                    .as_ref()
                    .map_or_else(|| retention.clone(), |t| t.retention.clone()),
            ),
            EvidenceState::Unmeasured {
                reason: why,
                expected,
            } => {
                // A reason the rule itself named is a different statement from one it did not, and
                // a reader cannot tell them apart from the reason alone (ADR 0027).
                let label = if *expected {
                    text(lang, "unmeasured_expected")
                } else {
                    text(lang, "unmeasured_unexpected")
                };
                (label, reason(lang, *why).to_owned())
            }
        };
        let _ = writeln!(
            out,
            "[{label}] {check}: {title}  ({}, {})",
            evidence.strength.as_str(),
            evidence.collector
        );
        if !detail.is_empty() {
            let _ = writeln!(out, "    {detail}");
        }
        if let Some(band) = view.row_bands.get(&evidence.rule_id) {
            let _ = writeln!(out, "    {}", row_band_line(band, &evidence.state, lang));
        }
        // What the rule means and what it does not prove, beside every state; what legitimately
        // produces the same evidence, beside a match only. Both are mandatory in every rule and
        // neither reached a screen before (ADR 0027).
        if let Some(rule_text) = &rule_text {
            if !rule_text.description.is_empty() {
                let _ = writeln!(
                    out,
                    "    {}: {}",
                    text(lang, "description"),
                    rule_text.description
                );
            }
            if matches!(evidence.state, EvidenceState::Found { .. })
                && !rule_text.falsepositives.is_empty()
            {
                let _ = writeln!(out, "    {}:", text(lang, "falsepositives"));
                for cause in &rule_text.falsepositives {
                    let _ = writeln!(out, "      - {cause}");
                }
            }
        }
    }
    out
}

/// The span a row's count is for, in the words its state needs (ADR 0047, amendment of 2026-09-30).
fn row_band_line(band: &RowBand, state: &EvidenceState, lang: Lang) -> String {
    match band {
        RowBand::Span { from, to } => {
            let key = if matches!(state, EvidenceState::NotFound { .. }) {
                "row_band_not_found"
            } else {
                "row_band_found"
            };
            text(lang, key).replace("{from}", from).replace("{to}", to)
        }
        RowBand::NoSpan => text(lang, "row_band_none").to_owned(),
    }
}

/// The timeline: its note, the spans the sources could show, what could not be read, the times, and
/// the text of every timeline selector that put a time there (ADR 0051).
fn timeline_section(timeline: &Timeline, bundle: &Bundle, lang: Lang) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n{} — {}",
        text(lang, "timeline"),
        text(lang, "timeline_note")
    );
    if !timeline.bands.is_empty() {
        let _ = writeln!(out, "    {}", text(lang, "coverage_note"));
    }
    for band in &timeline.bands {
        let _ = writeln!(
            out,
            "    [{}{}] {}: {} .. {}",
            band.collector,
            where_(band.place.as_deref(), band.subject.as_deref()),
            text(lang, "coverage"),
            band.from,
            band.to
        );
    }
    for source in &timeline.unmeasured {
        let place = source
            .place
            .as_deref()
            .map(|place| format!(" {place}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "    [{}{place}] {}: {}",
            source.collector,
            text(lang, "not_measured"),
            reason(lang, source.reason)
        );
    }
    let title = |id: &str| {
        bundle
            .text(id, lang.code())
            .map_or_else(|| id.to_owned(), |text| text.title)
    };
    let mut selectors: Vec<&str> = Vec::new();
    for entry in &timeline.entries {
        let what = match (&entry.source, entry.field.as_str()) {
            (EntrySource::Anchor, "generated_at") => text(lang, "scan_time").to_owned(),
            (EntrySource::Anchor, _) => text(lang, "boot_anchor").to_owned(),
            (source, field) => {
                let from = match source {
                    EntrySource::Evidence { rule_id } => format!(" ({})", title(rule_id)),
                    EntrySource::Selector { selector_id } => {
                        if !selectors.contains(&selector_id.as_str()) {
                            selectors.push(selector_id);
                        }
                        format!(" ({})", title(selector_id))
                    }
                    EntrySource::Anchor | EntrySource::Observation => String::new(),
                };
                format!(
                    "[{}{}] {field}{from}",
                    entry.collector.as_deref().unwrap_or_default(),
                    where_(entry.place.as_deref(), entry.subject.as_deref()),
                )
            }
        };
        let _ = writeln!(out, "    {}  {what}", entry.at);
    }
    // Each selector's meaning and ordinary causes once, rather than beside each of its times.
    if !selectors.is_empty() {
        let _ = writeln!(out, "    {}:", text(lang, "selectors"));
    }
    for id in selectors {
        let Some(selector) = bundle.text(id, lang.code()) else {
            continue;
        };
        let _ = writeln!(out, "    - {}: {}", selector.title, selector.description);
        let _ = writeln!(out, "      {}:", text(lang, "selector_causes"));
        for cause in &selector.falsepositives {
            let _ = writeln!(out, "        - {cause}");
        }
    }
    out
}

/// ` place subject`, leaving out what is not there.
fn where_(place: Option<&str>, subject: Option<&str>) -> String {
    let mut out = String::new();
    for part in [place, subject].into_iter().flatten() {
        out.push(' ');
        out.push_str(part);
    }
    out
}

/// One observation as `field=value, field=value`, the way both trailing sections list it.
fn fields_of(observation: &Observation) -> String {
    observation
        .fields
        .iter()
        .map(|(k, v)| format!("{k}={}", plain(v)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What this program itself left in what the collectors saw. Shown in both modes (ADR 0010).
fn own_traces_section(view: &ReportView, lang: Lang) -> String {
    let mut out = String::new();
    if view.own_traces.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "\n{} — {}",
        text(lang, "own_traces"),
        text(lang, "own_traces_note")
    );
    for entry in &view.own_traces {
        let _ = writeln!(
            out,
            "    [{}] {}",
            entry.collector,
            fields_of(&entry.observation)
        );
    }
    out
}

/// What the collectors saw that no rule matched (ADR 0014).
fn unmatched_section(view: &ReportView, lang: Lang) -> String {
    let mut out = String::new();
    if view.unmatched.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "\n{} — {}",
        text(lang, "unmatched"),
        text(lang, "unmatched_note")
    );
    for group in &view.unmatched {
        for observation in &group.observations {
            let _ = writeln!(out, "    [{}] {}", group.collector, fields_of(observation));
        }
    }
    out
}

fn plain(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

#[cfg(test)]
mod tests {
    use bope_core::model::{
        Evidence, EvidenceState, Observation, OwnTraceEntry, REPORT_SCHEMA_VERSION, Report,
        ReportHeader, Strength, UnmatchedGroup,
    };
    use bope_core::provenance::Provenance;
    use bope_core::rules::Rule;
    use bope_core::view;

    use super::*;

    /// The rule these tests build a report around.
    ///
    /// Looked up by path, not taken as `rules()[0]`: the report below fabricates a
    /// `secure_boot=disabled` observation and asserts this rule's own Thai `retention`, so it is
    /// this rule the tests mean and not whichever one sorts first. Index 0 was that rule until
    /// `rules/evtx/` existed, which is the kind of coupling a new rule is not supposed to break.
    fn subject(bundle: &Bundle) -> &Rule {
        &bundle
            .rules()
            .iter()
            .find(|sourced| sourced.path == "posture/boot/secure-boot-disabled/rule.yaml")
            .expect("the secure-boot rule is in the embedded bundle")
            .rule
    }

    fn report(official: bool) -> (Report, Bundle) {
        let bundle = Bundle::embedded().unwrap();
        let rule = subject(&bundle);
        let header = ReportHeader {
            schema_version: REPORT_SCHEMA_VERSION,
            provenance: Provenance::from_parts(official.then_some("1"), "0.0.0-test", None, None),
            rules_bundle: bundle.info().clone(),
            platform: "windows".to_owned(),
            os_build: Some("26100".to_owned()),
            elevated: Some(false),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            boot_time: bope_core::model::BootTime::Measured {
                booted_at: "2025-12-28T21:56:56Z".to_owned(),
                seconds_since_boot: 266_584,
            },
            scan_tier: bope_core::model::ScanTier::Standard,
            anchors: Vec::new(),
        };
        let evidence = Evidence {
            rule_id: rule.id.clone(),
            collector: rule.collector.clone(),
            strength: Strength::Posture,
            state: EvidenceState::Found {
                observations: vec![Observation {
                    collector: "posture".to_owned(),
                    fields: [(
                        "secure_boot".to_owned(),
                        serde_json::Value::from("disabled"),
                    )]
                    .into(),
                }],
            },
        };
        (
            Report {
                header,
                evidence: vec![evidence],
                own_traces: Vec::new(),
                unmatched: Vec::new(),
                timeline_selections: Vec::new(),
                timestamp_fields: std::collections::BTreeMap::new(),
                discriminators: std::collections::BTreeMap::new(),
                coverage_fields: std::collections::BTreeMap::new(),
                unmeasured_sources: Vec::new(),
                age_fields: std::collections::BTreeMap::new(),
                timeline_selectors: std::collections::BTreeMap::new(),
            },
            bundle,
        )
    }

    /// ADR 0051: the timeline says what it does not show above its times, and names the scan's own.
    #[test]
    fn the_timeline_is_a_section_with_its_note_and_the_scan_time() {
        let (report, bundle) = report(true);
        for (lang, note) in [
            (Lang::En, "not an order of events"),
            (Lang::Th, "ไม่ใช่ลำดับของเหตุการณ์"),
        ] {
            let text = render(&view::for_report(&report), &bundle, lang);
            assert!(text.contains(note), "{text}");
            assert!(
                text.contains(&format!(
                    "    {}  {}",
                    report.header.generated_at,
                    text_timeline(lang, "scan_time")
                )),
                "{text}"
            );
        }
    }

    #[test]
    fn a_timeline_entry_names_its_place_subject_field_and_selector() {
        let (_, bundle) = report(true);
        let selector = bundle
            .rules()
            .iter()
            .find(|sourced| sourced.rule.is_timeline_selector())
            .expect("the bundle ships a timeline selector");
        let timeline = Timeline {
            entries: vec![bope_core::view::TimelineEntry {
                at: "2026-09-15T18:02:11Z".to_owned(),
                collector: Some("prefetch".to_owned()),
                field: "last_run".to_owned(),
                place: None,
                source: EntrySource::Selector {
                    selector_id: selector.rule.id.clone(),
                },
                subject: Some("FIVEM.EXE".to_owned()),
            }],
            bands: Vec::new(),
            unmeasured: vec![bope_core::model::UnmeasuredSource {
                collector: "usn".to_owned(),
                place: None,
                reason: UnmeasuredReason::NotAdmin,
            }],
        };
        let text = timeline_section(&timeline, &bundle, Lang::En);
        assert!(
            text.contains(&format!(
                "    2026-09-15T18:02:11Z  [prefetch FIVEM.EXE] last_run ({})",
                selector.rule.title
            )),
            "{text}"
        );
        assert!(
            text.contains(
                "[usn] not measured: Windows would not show this without administrator rights"
            ),
            "{text}"
        );
        assert!(
            text.contains("Ordinary things behind these times"),
            "{text}"
        );
        assert!(text.contains(&selector.rule.falsepositives[0]), "{text}");
    }

    #[test]
    fn unofficial_build_is_announced() {
        let (report, bundle) = report(false);
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(text.contains("UNOFFICIAL BUILD"), "{text}");
        let thai = render(&view::for_report(&report), &bundle, Lang::Th);
        assert!(thai.contains("UNOFFICIAL BUILD"), "{thai}");
    }

    /// One line above the evidence, in both languages, carrying the caveat that stops
    /// a start days ago being read as something the player did (ADR 0039).
    #[test]
    fn the_boot_time_is_one_line_of_context_above_the_evidence() {
        let (report, bundle) = report(false);
        {
            let text = render(&view::for_report(&report), &bundle, Lang::En);
            let (above, below) = text
                .split_once("[FOUND]")
                .expect("the evidence is rendered");
            let lines: Vec<&str> = above
                .lines()
                .filter(|line| line.starts_with("Windows start:"))
                .collect();
            assert_eq!(lines.len(), 1, "{text}");
            assert!(
                lines[0].contains("2025-12-28T21:56:56Z, 3d 2h 3m before this scan"),
                "{text}"
            );
            assert!(lines[0].contains("Fast Startup"), "{text}");
            // The line is not repeated. The timeline carries the same time as an anchor, in its own
            // words, among the other times (ADR 0051).
            assert!(!below.contains("Windows start:"), "{text}");
            assert!(
                below.contains("2025-12-28T21:56:56Z  Windows started"),
                "{text}"
            );

            let thai = render(&view::for_report(&report), &bundle, Lang::Th);
            assert!(
                thai.contains("Windows เริ่มทำงาน: 2025-12-28T21:56:56Z"),
                "{thai}"
            );
            assert!(thai.contains("3 วัน 2 ชม. 3 นาที"), "{thai}");
            assert!(thai.contains("Fast Startup"), "{thai}");
        }
    }

    /// No time is printed where none was measured, and the reason uses the words every other
    /// unmeasured result uses.
    #[test]
    fn an_unmeasured_boot_time_says_why_and_prints_no_time() {
        let (mut report, bundle) = report(false);
        report.header.boot_time = bope_core::model::BootTime::Unmeasured {
            reason: UnmeasuredReason::NotWindows,
        };
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(
            text.contains("Windows start: not measured — not running on Windows"),
            "{text}"
        );
        assert!(!text.contains("before this scan"), "{text}");
    }

    #[test]
    fn elapsed_time_leaves_out_days_when_there_are_none() {
        assert_eq!(elapsed(0, Lang::En), "0h 0m");
        assert_eq!(elapsed(59, Lang::En), "0h 0m");
        assert_eq!(elapsed(32_571, Lang::En), "9h 2m");
        assert_eq!(elapsed(86_400, Lang::En), "1d 0h 0m");
        assert_eq!(elapsed(32_571, Lang::Th), "9 ชม. 2 นาที");
    }

    #[test]
    fn official_build_has_no_banner() {
        let (report, bundle) = report(true);
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(!text.contains("UNOFFICIAL BUILD"), "{text}");
    }

    #[test]
    fn own_traces_are_rendered_in_their_own_section() {
        let (mut report, bundle) = report(false);
        report.own_traces = vec![OwnTraceEntry {
            collector: "process".to_owned(),
            observation: Observation {
                collector: "process".to_owned(),
                fields: [
                    (
                        "name".to_owned(),
                        serde_json::Value::from("aeterna-rongroi.exe"),
                    ),
                    (
                        "path".to_owned(),
                        serde_json::Value::from(r"C:\Users\a\aeterna-rongroi.exe"),
                    ),
                ]
                .into(),
            },
        }];
        let view = view::for_report(&report);
        let text = render(&view, &bundle, Lang::En);

        let (above, section) = text
            .split_once("own traces (excluded)")
            .expect("the own-traces section is announced");
        // Nothing about the tool's own process appears among the evidence above it.
        assert!(!above.contains("aeterna-rongroi.exe"), "{above}");
        assert!(section.contains("aeterna-rongroi.exe"), "{section}");
        assert!(
            section.contains(r"C:\Users\a\aeterna-rongroi.exe"),
            "{section}"
        );

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ร่องรอยของโปรแกรมนี้เอง"), "{thai}");
    }

    /// A plugin file the `fivem_dir` collector saw, written here as an unmatched observation. Rules read
    /// that collector since ADR 0036; what this test needs is an entry in the bucket, not a real match.
    fn plugin_file() -> Vec<UnmatchedGroup> {
        vec![UnmatchedGroup {
            collector: "fivem_dir".to_owned(),
            observations: vec![Observation {
                collector: "fivem_dir".to_owned(),
                fields: [(
                    "path".to_owned(),
                    serde_json::Value::from(
                        r"C:\Users\a\AppData\Local\FiveM\FiveM.app\plugins\overlay.dll",
                    ),
                )]
                .into(),
            }],
        }]
    }

    /// What the collectors saw that no rule matched is listed after the evidence and after the own
    /// traces, in a section of its own that says these are not findings (ADR 0014).
    #[test]
    fn unmatched_observations_are_rendered_in_their_own_section() {
        let (mut report, bundle) = report(false);
        report.unmatched = plugin_file();
        let view = view::for_report(&report);
        let text = render(&view, &bundle, Lang::En);

        let (above, section) = text
            .split_once("unmatched observations")
            .expect("the unmatched section is announced");
        // Nothing about the file appears among the evidence above it.
        assert!(!above.contains("overlay.dll"), "{above}");
        assert!(section.contains("overlay.dll"), "{section}");
        assert!(section.contains("fivem_dir"), "{section}");

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ไม่ตรง rule ใดเลย"), "{thai}");
    }

    #[test]
    fn no_unmatched_section_when_every_observation_matched_a_rule() {
        let (report, bundle) = report(false);
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(!text.contains("unmatched observations"), "{text}");
    }

    /// A match shown without what else produces it is a match shown as an accusation. Both halves
    /// are mandatory in every rule, both are translated, and neither reached a screen before
    /// (NIST SP 800-86 section 3.4, ADR 0027).
    #[test]
    fn a_found_entry_shows_its_description_and_its_false_positives() {
        let (report, bundle) = report(false);
        let rule = subject(&bundle);
        let view = view::for_report(&report);

        let english = render(&view, &bundle, Lang::En);
        assert!(english.contains("About this check"), "{english}");
        assert!(english.contains(&rule.description), "{english}");
        assert!(
            english.contains("Ordinary things that also produce this"),
            "{english}"
        );
        for cause in &rule.falsepositives {
            assert!(english.contains(cause), "{english}");
        }

        let thai = render(&view, &bundle, Lang::Th);
        let translated = bundle.text(&rule.id, "th").expect("the rule is translated");
        assert!(thai.contains("เกี่ยวกับการตรวจนี้"), "{thai}");
        assert!(thai.contains(&translated.description), "{thai}");
        for cause in &translated.falsepositives {
            assert!(thai.contains(cause), "{thai}");
        }
        // The English text is not shown alongside it.
        assert!(!thai.contains(&rule.description), "{thai}");
    }

    /// `description` says what the check is, which a reader needs whatever the answer was.
    /// `falsepositives` explains a match, and nothing matched here, so there is nothing to explain.
    #[test]
    fn a_not_found_entry_shows_the_description_and_not_the_false_positives() {
        let (mut report, bundle) = report(false);
        let rule = subject(&bundle).clone();
        report.evidence[0].state = EvidenceState::NotFound {
            retention: rule.retention.clone(),
        };
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(text.contains(&rule.description), "{text}");
        assert!(
            !text.contains("Ordinary things that also produce this"),
            "{text}"
        );
        for cause in &rule.falsepositives {
            assert!(!text.contains(cause), "{text}");
        }
    }

    /// A row whose count is for a span says the span beside it, in the words its state needs, in
    /// both languages; a source that held no record says there was no span (ADR 0047, amendment of
    /// 2026-09-30, decision 3).
    #[test]
    fn a_row_with_a_band_says_the_span_its_count_is_for() {
        let (mut report, bundle) = report(false);
        let rule = subject(&bundle).clone();
        let band = RowBand::Span {
            from: "2026-09-30T10:24:00Z".to_owned(),
            to: "2026-09-30T11:03:00Z".to_owned(),
        };
        let found = {
            let mut view = view::for_report(&report);
            view.row_bands.insert(rule.id.clone(), band.clone());
            render(&view, &bundle, Lang::En)
        };
        assert!(
            found.contains(
                "The source held only 2026-09-30T10:24:00Z to 2026-09-30T11:03:00Z when it was read"
            ),
            "{found}"
        );

        report.evidence[0].state = EvidenceState::NotFound {
            retention: rule.retention.clone(),
        };
        let mut view = view::for_report(&report);
        view.row_bands.insert(rule.id.clone(), band);
        let english = render(&view, &bundle, Lang::En);
        assert!(
            english
                .contains("Nothing within this span: 2026-09-30T10:24:00Z to 2026-09-30T11:03:00Z"),
            "{english}"
        );
        let thai = render(&view, &bundle, Lang::Th);
        assert!(
            thai.contains("ไม่มีอะไรในช่วงนี้: 2026-09-30T10:24:00Z"),
            "{thai}"
        );

        view.row_bands.insert(rule.id.clone(), RowBand::NoSpan);
        let none = render(&view, &bundle, Lang::En);
        assert!(none.contains("so there is no span"), "{none}");
        assert!(!none.contains("Nothing within this span"), "{none}");
    }

    /// Two rules that could not be measured for want of administrator rights are one fact about the
    /// scan. It is stated once, above the evidence, and it names the remedy (ADR 0012, ADR 0027).
    #[test]
    fn missing_administrator_rights_is_one_scope_statement_above_the_evidence() {
        let (mut report, bundle) = report(false);
        let first = report.evidence[0].clone();
        report.evidence = vec![first.clone(), first];
        for item in &mut report.evidence {
            item.state = EvidenceState::Unmeasured {
                reason: bope_core::model::UnmeasuredReason::NotAdmin,
                expected: false,
            };
        }
        let view = view::for_report(&report);

        let text = render(&view, &bundle, Lang::En);
        let (scope, below) = text
            .split_once("Scope: 2 check(s)")
            .expect("the scope statement is printed once, with the count");
        assert!(scope.contains("standard scan"), "{scope}");
        assert!(!below.contains("Scope: "), "{below}");
        assert!(below.contains("[NOT MEASURED (not expected)]"), "{below}");

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("ขอบเขตการตรวจ: มี 2 รายการ"), "{thai}");
    }

    /// A reason the rule named and a reason it did not are different statements, and the reason
    /// alone does not tell them apart (ADR 0027).
    #[test]
    fn an_expected_unmeasured_result_is_labelled_apart_from_an_unexpected_one() {
        let (mut report, bundle) = report(false);
        report.evidence[0].state = EvidenceState::Unmeasured {
            reason: bope_core::model::UnmeasuredReason::SourceAbsent,
            expected: true,
        };
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(text.contains("[NOT MEASURED (expected here)]"), "{text}");
        assert!(!text.contains("(not expected)"), "{text}");
    }

    /// Three counts above the evidence, in both languages, never summed (ADR 0045).
    #[test]
    fn listed_counts_are_one_line_above_the_evidence() {
        let (report, bundle) = report(true);
        for (lang, marker, line) in [
            (
                Lang::En,
                "[FOUND]",
                "Listed: 1 found · 0 not found · 0 not measured",
            ),
            (
                Lang::Th,
                "[เจอ]",
                "รายการที่แสดง: เจอ 1 · ไม่เจอ 0 · ยังไม่ได้วัด 0",
            ),
        ] {
            let text = render(&view::for_report(&report), &bundle, lang);
            let (above, _) = text.split_once(marker).expect("the evidence is rendered");
            assert_eq!(above.lines().filter(|l| *l == line).count(), 1, "{text}");
        }
    }

    #[test]
    fn the_code_link_is_the_commit_of_an_official_build() {
        let (mut report, bundle) = report(true);
        report.header.provenance.commit =
            Some("2c673c54aeb084cd3773057efbb9ed3b98fd2dbc".to_owned());
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        let (before_footer, _) = text.split_once("Evidence only.").expect("footer");
        assert!(
            before_footer.contains(
                "\nCode: https://github.com/aeterna/aeterna-rongroi/tree/2c673c54aeb084cd3773057efbb9ed3b98fd2dbc\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn an_unofficial_build_links_the_repository_and_says_its_code_is_not_known() {
        let (report, bundle) = report(false);
        let text = render(&view::for_report(&report), &bundle, Lang::En);
        assert!(
            text.contains(
                "Code: https://github.com/aeterna/aeterna-rongroi (the code this build was made from is not known)"
            ),
            "{text}"
        );
        assert!(!text.contains("/tree/"), "{text}");
        let thai = render(&view::for_report(&report), &bundle, Lang::Th);
        assert!(
            thai.contains(
                "โค้ด: https://github.com/aeterna/aeterna-rongroi (ไม่รู้ว่า build นี้สร้างจากโค้ดของ commit ไหน)"
            ),
            "{thai}"
        );
    }

    #[test]
    fn not_found_retention_is_shown_in_the_chosen_language() {
        let (mut report, bundle) = report(false);
        let english = subject(&bundle).retention.clone();
        report.evidence[0].state = EvidenceState::NotFound {
            retention: english.clone(),
        };
        let view = view::for_report(&report);

        let thai = render(&view, &bundle, Lang::Th);
        assert!(thai.contains("เป็นค่าที่ตั้งไว้ตอนนี้เท่านั้น"), "{thai}");
        assert!(!thai.contains(&english), "{thai}");

        let text = render(&view, &bundle, Lang::En);
        assert!(text.contains(&english), "{text}");
    }
}
