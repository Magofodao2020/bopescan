// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Runs the whole pipeline over a fixture host and prints what the desktop's IPC commands would answer,
//! as one JSON object (B.O.P.E, ADR 0132). Used to take screenshots of the interface with synthetic
//! data only; it never reads the machine it runs on.
//!
//! `cargo run -p bope-collectors --example view_json -- <fixture-host-dir> [lang] [generated_at]`

use std::collections::BTreeMap;
use std::path::PathBuf;

use bope_collectors::scan::{self, ScanContext};
use bope_core::bundle::Bundle;
use bope_core::engine::SelfIdentity;
use bope_core::model::ScanTier;
use bope_core::provenance::Provenance;
use bope_core::view;
use bope_host::FixtureHost;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .ok_or("usage: view_json <fixture-host-dir> [lang]")?,
    );
    let lang = args.next().unwrap_or_else(|| "pt-BR".to_owned());
    let generated_at = args
        .next()
        .unwrap_or_else(|| "2026-10-16T13:00:00Z".to_owned());
    let host = FixtureHost::load(&dir)?;
    let bundle = Bundle::embedded()?;
    let context = ScanContext {
        provenance: Provenance::from_parts(None, env!("CARGO_PKG_VERSION"), None, None),
        generated_at,
        self_identity: SelfIdentity::default(),
        tier: ScanTier::Full,
        flag_reference: None,
    };
    let report = scan::run(&host, &bundle, context);
    let views: BTreeMap<&str, view::ReportView> = BTreeMap::from([(
        "self",
        view::for_report(&report).with_assessment(&report, &bundle),
    )]);
    let texts: BTreeMap<String, _> = bundle
        .rules()
        .iter()
        .filter_map(|sourced| {
            let id = &sourced.rule.id;
            bundle.text(id, &lang).map(|text| (id.clone(), text))
        })
        .collect();
    let meta: BTreeMap<String, serde_json::Value> = bundle
        .rules()
        .iter()
        .map(|sourced| {
            let rule = &sourced.rule;
            (
                rule.id.clone(),
                serde_json::json!({
                    "level": rule.assessment_level(),
                    "category": rule.assessment_category(),
                    "collector": rule.collector,
                    "selector": rule.is_timeline_selector(),
                }),
            )
        })
        .collect();
    let ages: BTreeMap<String, _> = bundle
        .ages()
        .iter()
        .filter_map(|sourced| {
            let collector = &sourced.text.collector;
            bundle
                .age_text(collector, &lang)
                .map(|text| (collector.clone(), text))
        })
        .collect();
    let time_fields: BTreeMap<&str, Vec<&str>> = bope_collectors::all()
        .iter()
        .map(|collector| {
            (
                collector.id(),
                collector
                    .fields()
                    .iter()
                    .filter(|field| field.kind == bope_collectors::FieldKind::Timestamp)
                    .map(|field| field.name)
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, fields)| !fields.is_empty())
        .collect();
    let collectors: Vec<serde_json::Value> = bope_collectors::all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id(),
                "tier": c.tier(),
                "category": bope_core::assessment::default_category(c.id()),
            })
        })
        .collect();
    let out = serde_json::json!({
        "views": views,
        "texts": texts,
        "meta": meta,
        "ages": ages,
        "time_fields": time_fields,
        "collectors": collectors,
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
