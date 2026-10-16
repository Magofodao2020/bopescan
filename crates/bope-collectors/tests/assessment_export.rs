// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! The assessment and the saved reports over whole scans of fixture hosts (B.O.P.E, ADR 0100,
//! ADR 0116): what an ordinary Roblox player's PC reads as, what a PC with executor traces reads as,
//! and that every export is the bytes its hash names.

// A test helper outside `#[test]` may unwrap: a broken fixture is a failed test.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use bope_collectors::scan::{self, ScanContext};
use bope_core::assessment::{Conclusion, ModuleState};
use bope_core::bundle::Bundle;
use bope_core::engine::SelfIdentity;
use bope_core::export::{self, Format};
use bope_core::model::{Report, ScanTier};
use bope_core::provenance::Provenance;
use bope_core::view;
use bope_host::FixtureHost;

fn scan_fixture(name: &str) -> (Report, Bundle) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/hosts")
        .join(name);
    let host = FixtureHost::load(&dir).unwrap();
    let bundle = Bundle::embedded().unwrap();
    let report = scan::run(
        &host,
        &bundle,
        ScanContext {
            provenance: Provenance::current(),
            generated_at: "2026-10-15T12:00:00Z".to_owned(),
            self_identity: SelfIdentity::default(),
            tier: ScanTier::Full,
        },
    );
    (report, bundle)
}

#[test]
fn an_ordinary_roblox_pc_has_no_supporting_evidence_and_is_never_called_clean() {
    let (report, bundle) = scan_fixture("baseline-roblox-win11");
    let view = view::for_report(&report).with_assessment(&report, &bundle);
    let assessment = view.assessment.as_ref().unwrap();
    assert!(
        assessment.supporting.is_empty(),
        "{:?}",
        assessment.supporting
    );
    assert_eq!(assessment.conclusion, Conclusion::NoSuspiciousEvidence);
    assert!(assessment.caveats.contains(&"software_only".to_owned()));
    let roblox = assessment
        .categories
        .iter()
        .find(|c| c.category == "roblox")
        .unwrap();
    // Bloxstrap is context, so the category is INFO, never WARN or FLAG.
    assert_eq!(roblox.state, ModuleState::Info);
    let text =
        String::from_utf8(export::export(&view, &bundle, "pt-BR", Format::Text).bytes).unwrap();
    assert!(
        text.contains("NÃO é uma declaração de que o PC está limpo"),
        "{text}"
    );
}

#[test]
fn executor_traces_from_independent_sources_are_high_confidence() {
    let (report, bundle) = scan_fixture("roblox-executor-traces");
    let view = view::for_report(&report).with_assessment(&report, &bundle);
    let assessment = view.assessment.as_ref().unwrap();
    assert_eq!(
        assessment.conclusion,
        Conclusion::HighConfidence,
        "{assessment:#?}"
    );
    assert!(assessment.independent_sources >= 2);
    // `executor_footprint` and `user_files` read the same folder listing: one source, not two.
    let file_listing = assessment
        .supporting
        .iter()
        .filter(|f| f.source == "file_listing")
        .count();
    assert!(file_listing >= 2);
    assert!(
        !assessment.proximity.is_empty(),
        "the USB board and the executor folder are close in time"
    );
}

/// The `roblox_trace` rows of a report, by scope: from its evidence and from what no rule matched.
fn trace_rows<'a>(report: &'a Report, scope: &str) -> Vec<&'a bope_core::model::Observation> {
    let found = report.evidence.iter().filter_map(|e| match &e.state {
        bope_core::model::EvidenceState::Found { observations }
            if e.collector == "roblox_trace" =>
        {
            Some(observations)
        }
        _ => None,
    });
    let unmatched = report
        .unmatched
        .iter()
        .filter(|g| g.collector == "roblox_trace")
        .map(|g| &g.observations);
    let mut rows: Vec<&bope_core::model::Observation> = found
        .chain(unmatched)
        .flatten()
        .filter(|o| o.fields["scope"] == scope)
        .collect();
    rows.dedup_by(|a, b| a == b);
    let mut unique = Vec::new();
    for row in rows {
        if !unique.contains(&row) {
            unique.push(row);
        }
    }
    unique
}

#[test]
fn a_removed_executor_is_corroborated_from_history_without_its_files() {
    // Fluxus is a distinctive executor name, so it needs no other Roblox context (ADR 0118).
    let (report, bundle) = scan_fixture("roblox-tool-history");
    let tools = trace_rows(&report, "tool");
    let fluxus = tools
        .iter()
        .find(|o| o.fields["tool_id"] == "fluxus")
        .unwrap_or_else(|| panic!("{tools:#?}"));
    assert_eq!(fluxus.fields["status"], "corroborated", "{fluxus:#?}");
    assert_eq!(fluxus.fields["execution"], true);
    assert_eq!(fluxus.fields["deleted"], true);
    assert_eq!(fluxus.fields["missing_now"], true);
    let families = fluxus.fields["families"].as_str().unwrap();
    for family in [
        "userassist",
        "amcache",
        "shortcuts",
        "usn",
        "file_listing",
        "srum",
        "mft",
        "shellbags",
    ] {
        assert!(
            families.contains(family),
            "{family} missing from {families}"
        );
    }
    // ChromeSetup in Amcache is a program in Downloads, not a Roblox tool: no row of its own.
    assert!(tools.iter().all(|o| o.fields["tool_id"] != "chromesetup"));
    // Every source the correlation could use says whether it was read.
    let sources = trace_rows(&report, "source");
    assert_eq!(sources.len(), 23, "{sources:#?}");
    for source in ["srum", "mft", "shellbags", "wmi_subscription"] {
        assert!(
            sources
                .iter()
                .any(|o| o.fields["source"] == source && o.fields["state"] == "measured"),
            "{source} was not read: {sources:#?}"
        );
    }
    // Windows' own WMI subscription is read and is never a hit.
    assert!(
        trace_rows(&report, "hit")
            .iter()
            .all(|o| o.fields["source"] != "wmi_subscription")
    );
    assert!(sources.iter().any(|o| o.fields["state"] != "measured"));
    assert!(
        sources
            .iter()
            .any(|o| o.fields["source"] == "amcache" && o.fields["state"] == "measured")
    );

    let view = view::for_report(&report).with_assessment(&report, &bundle);
    let assessment = view.assessment.as_ref().unwrap();
    assert_eq!(
        assessment.conclusion,
        Conclusion::HighConfidence,
        "{assessment:#?}"
    );
    let tools_category = assessment
        .categories
        .iter()
        .find(|c| c.category == "roblox_tools")
        .unwrap();
    assert_eq!(tools_category.state, ModuleState::Flag);
    let fastflags = assessment
        .categories
        .iter()
        .find(|c| c.category == "fastflags")
        .unwrap();
    assert_eq!(fastflags.state, ModuleState::Warn);
}

#[test]
fn every_export_is_the_bytes_its_hash_names_and_html_is_escaped() {
    let (report, bundle) = scan_fixture("roblox-executor-traces");
    let view = view::for_report(&report).with_assessment(&report, &bundle);
    for format in [Format::Json, Format::Html, Format::Text, Format::Pdf] {
        let exported = export::export(&view, &bundle, "pt-BR", format);
        assert_eq!(exported.sha256, export::sha256_hex(&exported.bytes));
        assert_eq!(exported.extension, format.extension());
    }
    let json: serde_json::Value =
        serde_json::from_slice(&export::export(&view, &bundle, "pt-BR", Format::Json).bytes)
            .unwrap();
    assert_eq!(json["format"], export::FORMAT_NAME);
    assert!(json["view"]["assessment"]["conclusion"].is_string());
    let html =
        String::from_utf8(export::export(&view, &bundle, "pt-BR", Format::Html).bytes).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(!html.contains("<script"), "an exported page runs nothing");
    // The PDF carries the version, the time in UTC, the tools section, the sources and the hash of
    // the JSON export of the same view (ADR 0129).
    let pdf = export::export(&view, &bundle, "pt-BR", Format::Pdf).bytes;
    let pdf_text = String::from_utf8_lossy(&pdf);
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf_text.contains(&report.header.provenance.version));
    assert!(pdf_text.contains("FERRAMENTAS ROBLOX"));
    let json_sha = export::export(&view, &bundle, "pt-BR", Format::Json).sha256;
    assert!(pdf_text.contains(&json_sha));
}

/// B.O.P.E, ADR 0132: the exported files write each time in UTC and in the zone the window showed,
/// in the window's `DD/MM/AAAA HH:mm:ss`, with the kind of time; JSON keeps the recorded value; the
/// services and Recycle Bin sections keep current state, history and artifact times apart.
#[test]
fn exports_write_times_like_the_window_and_keep_services_and_recycle_bin_apart() {
    let (report, bundle) = scan_fixture("roblox-tool-history");
    let mut view = view::for_report(&report).with_assessment(&report, &bundle);
    let observe = |fields: serde_json::Value| bope_core::model::Observation {
        collector: "windows_service".to_owned(),
        fields: serde_json::from_value(fields).unwrap(),
    };
    view.services = vec![
        observe(
            serde_json::json!({"scope": "current", "service": "SysMain", "query": "ok",
            "state": "stopped", "start_type": "disabled", "disabled": true,
            "collected_at": "2026-10-16T13:00:04Z"}),
        ),
        observe(
            serde_json::json!({"scope": "history", "service": "SysMain", "event": "state_change",
            "event_id": 7036, "record_id": 41, "event_at": "2026-10-15T22:10:05Z",
            "state_text": "stopped"}),
        ),
    ];
    let text = String::from_utf8(
        export::export_in_zone(
            &view,
            &bundle,
            "pt-BR",
            Format::Text,
            Some("America/Sao_Paulo"),
        )
        .bytes,
    )
    .unwrap();
    assert!(
        text.contains("16/10/2026 13:00:04 UTC · 16/10/2026 10:00:04 (UTC\u{2212}03:00)"),
        "{text}"
    );
    assert!(text.contains("no fuso America/Sao_Paulo"));
    assert!(text.contains("SERVIÇOS DO WINDOWS"));
    assert!(text.contains("não é, por si só, indício de trapaça"));
    assert!(text.contains("(evento 7036, registro 41)"));
    assert!(text.contains("Última modificação observada no artefato"));
    assert!(
        text.contains("Exclusão (Lixeira) · exato")
            || text.contains("[Exclusão (Lixeira) · exato]")
    );
    let utc_only =
        String::from_utf8(export::export(&view, &bundle, "pt-BR", Format::Text).bytes).unwrap();
    assert!(utc_only.contains("16/10/2026 13:00:04 UTC"));
    assert!(!utc_only.contains("UTC\u{2212}03:00"));
    let json: serde_json::Value = serde_json::from_slice(
        &export::export_in_zone(
            &view,
            &bundle,
            "pt-BR",
            Format::Json,
            Some("America/Sao_Paulo"),
        )
        .bytes,
    )
    .unwrap();
    assert_eq!(json["time_zone"], "America/Sao_Paulo");
    assert_eq!(
        json["view"]["services"][0]["fields"]["collected_at"],
        "2026-10-16T13:00:04Z"
    );
    let html = String::from_utf8(
        export::export_in_zone(&view, &bundle, "pt-BR", Format::Html, Some("Bad/Zone")).bytes,
    )
    .unwrap();
    assert!(html.contains("horários em UTC; o JSON guarda o valor original em UTC"));
}
