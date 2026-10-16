// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Times as the exported reports write them (B.O.P.E, ADR 0132): the same `DD/MM/AAAA HH:mm:ss`, the
//! same kinds of time and the same certainty as the desktop's `src/time.ts`, so a report and the
//! window that saved it say the same thing. A value is converted once, from the RFC 3339 text the
//! report holds; a value that is not one is written as received, marked.

use jiff::Timestamp;
use jiff::tz::TimeZone;

/// `DD/MM/AAAA HH:mm:ss` of `time` in `zone`.
pub fn wall_clock(time: Timestamp, zone: &TimeZone) -> String {
    time.to_zoned(zone.clone())
        .strftime("%d/%m/%Y %H:%M:%S")
        .to_string()
}

/// The offset of `zone` at `time`, as `UTC+07:00` or `UTC−03:00` (a real minus sign).
pub fn offset_of(time: Timestamp, zone: &TimeZone) -> String {
    let seconds = zone.to_offset(time).seconds();
    let sign = if seconds < 0 { '\u{2212}' } else { '+' };
    let abs = seconds.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

/// A zone by IANA name, `None` for an empty or unknown name.
pub fn zone_named(name: &str) -> Option<TimeZone> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    TimeZone::get(name).ok()
}

/// `text` written for a report: UTC always, and the zone's reading beside it when there is one.
/// `"16/10/2026 13:05:09 UTC · 16/10/2026 10:05:09 (UTC−03:00)"`.
pub fn shown(text: &str, zone: Option<&TimeZone>) -> String {
    let Ok(time) = text.trim().parse::<Timestamp>() else {
        return format!("{text} (formato não reconhecido)");
    };
    let utc = format!("{} UTC", wall_clock(time, &TimeZone::UTC));
    match zone {
        Some(zone) => format!(
            "{utc} · {} ({})",
            wall_clock(time, zone),
            offset_of(time, zone)
        ),
        None => utc,
    }
}

/// What a recorded time says happened, as `timeKind` in `src/time.ts` names it.
pub fn kind(collector: Option<&str>, field: &str) -> &'static str {
    let Some(collector) = collector else {
        return if field == "generated_at" {
            "scan"
        } else {
            "system_start"
        };
    };
    match (collector, field) {
        ("windows_service", "event_at") => return "service_event",
        ("windows_start", "started_at") => return "system_start",
        ("process", "started_at") => return "execution",
        _ => {}
    }
    match field {
        "event_at" | "time" => return "event",
        "first_install_at" | "first_install" => return "installed",
        "key_written" | "hive_written" => return "registered",
        "collected_at" => return "collected",
        "generated_at" => return "scan",
        "deleted_at" => return "deleted",
        "last_run" => return "execution",
        "first_seen" => return "first_seen",
        "last_seen" => return "last_seen",
        "last_arrival" | "last_arrival_at" => return "connected",
        "last_removal" | "last_removal_at" => return "removed",
        "si_changed" => return "changed",
        _ => {}
    }
    if ["oldest", "earliest", "log_first", "first_install"]
        .iter()
        .any(|p| field.starts_with(p))
    {
        return "range_start";
    }
    if ["newest", "latest", "log_last", "last_artifact_change"]
        .iter()
        .any(|p| field.starts_with(p))
    {
        return "range_end";
    }
    if field.ends_with("accessed") {
        return "accessed";
    }
    if field.ends_with("created") || field.ends_with("created_at") {
        return "created";
    }
    if ["modified", "modified_at", "written", "write"]
        .iter()
        .any(|s| field.ends_with(s))
    {
        return "modified";
    }
    "recorded"
}

/// The words a report uses for a kind.
pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "created" => "Criação",
        "modified" => "Modificação",
        "accessed" => "Acesso",
        "changed" => "Alteração de metadados",
        "execution" => "Execução",
        "first_seen" => "Primeiro registro",
        "last_seen" => "Último registro",
        "registered" => "Registro (gravação de chave)",
        "installed" => "Instalação",
        "deleted" => "Exclusão (Lixeira)",
        "event" => "Evento",
        "service_event" => "Evento de serviço",
        "system_start" => "Início do sistema",
        "connected" => "Conexão de dispositivo",
        "removed" => "Remoção de dispositivo",
        "collected" => "Coleta",
        "scan" => "Verificação",
        "range_start" => "Início do intervalo",
        "range_end" => "Fim do intervalo",
        _ => "Horário registrado",
    }
}

/// How certain a time of `collector`'s `field` is, as `timeCertainty` in `src/time.ts` says.
pub fn certainty(collector: Option<&str>, field: &str) -> &'static str {
    match kind(collector, field) {
        "scan" | "collected" | "system_start" | "event" | "service_event" | "deleted" => "exato",
        "execution" if collector == Some("process") => "exato",
        "created" | "modified" | "accessed" | "changed" => "incerto",
        _ => "aproximado",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_utc_and_the_zone_like_the_window() {
        let zone = zone_named("America/Sao_Paulo").unwrap();
        assert_eq!(
            shown("2026-10-16T13:05:09Z", Some(&zone)),
            "16/10/2026 13:05:09 UTC · 16/10/2026 10:05:09 (UTC\u{2212}03:00)"
        );
        assert_eq!(
            shown("2026-10-16T13:05:09Z", None),
            "16/10/2026 13:05:09 UTC"
        );
        let bangkok = zone_named("Asia/Bangkok").unwrap();
        assert_eq!(
            shown("2026-01-31T20:30:00Z", Some(&bangkok)),
            "31/01/2026 20:30:00 UTC · 01/02/2026 03:30:00 (UTC+07:00)"
        );
    }

    #[test]
    fn keeps_what_it_cannot_read() {
        assert_eq!(
            shown("16/10/2026", None),
            "16/10/2026 (formato não reconhecido)"
        );
        assert!(zone_named("Not/AZone").is_none());
        assert!(zone_named("").is_none());
    }

    #[test]
    fn kinds_match_the_window() {
        // The same cases as `time.test.ts`.
        assert_eq!(kind(Some("recycle_bin"), "deleted_at"), "deleted");
        assert_eq!(kind(Some("recycle_bin"), "content_modified"), "modified");
        assert_eq!(kind(Some("recycle_bin"), "folder_created"), "created");
        assert_eq!(
            kind(Some("recycle_bin"), "last_artifact_change"),
            "range_end"
        );
        assert_eq!(kind(Some("windows_service"), "event_at"), "service_event");
        assert_eq!(kind(Some("windows_service"), "collected_at"), "collected");
        assert_eq!(kind(Some("windows_start"), "started_at"), "system_start");
        assert_eq!(kind(Some("prefetch"), "last_run"), "execution");
        assert_eq!(kind(Some("shortcuts"), "target_accessed"), "accessed");
        assert_eq!(kind(Some("mft"), "si_changed"), "changed");
        assert_eq!(kind(Some("usb_device"), "last_arrival_at"), "connected");
        assert_eq!(kind(None, "generated_at"), "scan");
        assert_eq!(kind(Some("x"), "something_new"), "recorded");
        assert_eq!(certainty(Some("prefetch"), "last_run"), "aproximado");
        assert_eq!(certainty(Some("roblox_files"), "modified"), "incerto");
        assert_eq!(certainty(Some("recycle_bin"), "deleted_at"), "exato");
    }
}
