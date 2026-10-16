// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! `bope-scanner-cli`: scan this PC and print evidence. Never prints a verdict.

mod output;
mod pt;
mod trace_ages;

use std::io::{BufRead, Write};
use std::process::ExitCode;

use anyhow::Context;
use bope_collectors::scan::{self, ScanContext};
use bope_core::bundle::Bundle;
use bope_core::engine::SelfIdentity;
use bope_core::model::ScanTier;
use bope_core::provenance::Provenance;
use bope_core::view;
use bope_host::Host;
use clap::{Args, Parser, Subcommand};

use crate::output::Lang;

#[derive(Parser)]
#[command(
    name = "bope-scanner-cli",
    version,
    about = "B.O.P.E Scanner — verificação offline de PC para Roblox (e FiveM). Mostra evidências; nunca diz que um PC está limpo."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan this PC and print the report.
    Scan(ScanArgs),
}

// Each of these is an independent command-line switch, which is what a bool is for; the lint's
// state-machine concern does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
struct ScanArgs {
    /// Print the report as JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Language of the text output.
    #[arg(long, value_enum, default_value_t = Lang::Pt)]
    lang: Lang,
    /// Save the report to this folder as JSON, HTML, text and PDF, each with a `.sha256` file beside it.
    #[arg(long, value_name = "FOLDER")]
    export_dir: Option<std::path::PathBuf>,
    /// Which formats `--export-dir` writes, comma-separated: json, html, txt, pdf.
    #[arg(long, value_delimiter = ',', default_value = "json,html,txt,pdf")]
    export_format: Vec<String>,
    /// Ask for a full scan, which reads more than the standard one (ADR 0052). The question is asked
    /// every time, before anything is read; only `yes` starts it, and no flag answers it.
    #[arg(long)]
    full: bool,
    /// Restart with administrator rights before scanning (Windows only). Windows asks you to confirm.
    #[arg(long)]
    elevate: bool,
    /// Wait for Enter before exiting. Added by `--elevate` to the copy it starts, whose console window
    /// Windows closes as soon as that copy exits (ADR 0012, amended); not meant to be typed.
    #[arg(long, hide = true)]
    pause_at_exit: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => {
            let outcome = scan(&args);
            // Printed here rather than by returning the error from `main`, because that would print
            // it after the pause below — into a window that has already closed.
            if let Err(error) = &outcome {
                eprintln!("Error: {error:?}");
            }
            if args.pause_at_exit {
                wait_for_enter(args.lang);
            }
            if outcome.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn scan(args: &ScanArgs) -> anyhow::Result<()> {
    let bundle = Bundle::embedded().context("the embedded rules bundle is invalid")?;
    let host = live_host();

    // Elevation is a property of a process token, so it takes a new process (ADR 0012). Asked before the
    // full-scan question, so nobody answers that question for a scan that will not happen here.
    if args.elevate && host.is_elevated() != Some(true) {
        return relaunch_elevated(args.lang);
    }

    // Asked by the process that reads, before any collector runs, every time: a flag in a shortcut
    // is not a player agreeing (ADR 0052).
    let tier = if args.full && ask_full(args.lang)? {
        ScanTier::Full
    } else {
        if args.full {
            eprintln!("{}", output::full_declined(args.lang));
        }
        ScanTier::Standard
    };

    let provenance = Provenance::current();
    // This program is in its own process list while it scans. The engine needs to know what "this
    // program" is to separate those traces from evidence about the PC (ADR 0010); the executable's
    // digest is the one the header already carries, so it is not read twice.
    let self_identity = SelfIdentity {
        exe_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        exe_sha256: provenance.exe_sha256.clone(),
    };
    let context = ScanContext {
        provenance,
        generated_at: jiff::Timestamp::now().to_string(),
        self_identity,
        tier,
    };
    let report = scan::run(host.as_ref(), &bundle, context);
    let view = view::for_report(&report).with_assessment(&report, &bundle);

    if let Some(dir) = &args.export_dir {
        export_reports(&view, &bundle, args, dir)?;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        print!("{}", output::render(&view, &bundle, args.lang));
    }
    Ok(())
}

/// Writes each chosen format into `dir`, with a `.sha256` file beside each, and prints where
/// (B.O.P.E, ADR 0116). The report goes only where the person pointed; nothing is sent anywhere.
fn export_reports(
    view: &view::ReportView,
    bundle: &Bundle,
    args: &ScanArgs,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    use bope_core::export::{self, Format};
    std::fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    let stem = export::file_stem(&view.header.generated_at);
    for name in &args.export_format {
        let format = Format::parse(name)
            .with_context(|| format!("unknown export format `{name}` (json, html, txt, pdf)"))?;
        // The zone this PC uses, as the desktop window shows it; UTC only when it has no name.
        let zone = jiff::tz::TimeZone::system().iana_name().map(str::to_owned);
        let exported =
            export::export_in_zone(view, bundle, args.lang.code(), format, zone.as_deref());
        let file_name = format!("{stem}.{}", exported.extension);
        let path = dir.join(&file_name);
        std::fs::write(&path, &exported.bytes)
            .with_context(|| format!("could not write {}", path.display()))?;
        let hash_path = dir.join(format!("{file_name}.sha256"));
        std::fs::write(
            &hash_path,
            export::sha256_line(&exported.sha256, &file_name),
        )
        .with_context(|| format!("could not write {}", hash_path.display()))?;
        eprintln!("{}  {}", exported.sha256, path.display());
    }
    Ok(())
}

/// The full-scan question. Only `yes` is yes: a stray `y` is not agreement to read more (ADR 0052).
fn ask_full(lang: Lang) -> anyhow::Result<bool> {
    Ok(is_full_answer(&read_answer(&output::full_question(lang))?))
}

fn is_full_answer(answer: &str) -> bool {
    answer == "yes" || answer == "sim"
}

/// Prints `question` on standard error and reads one line, trimmed and lower-cased.
///
/// Standard error, not standard output: standard output is the report, and with `--json` it is the
/// file someone redirected it into.
fn read_answer(question: &str) -> anyhow::Result<String> {
    eprint!("{question}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim().to_ascii_lowercase())
}

/// Waits for Enter, on a window that would otherwise close with the report still unread.
///
/// End of input counts as Enter, so a copy whose input is not a keyboard exits instead of hanging.
fn wait_for_enter(lang: Lang) {
    eprint!("\n{}", output::pause_at_exit(lang));
    // Neither failure matters: the program is exiting either way, and a failed read is no reason to
    // keep a window open that nobody can answer.
    std::io::stderr().flush().ok();
    std::io::stdin().lock().read_line(&mut String::new()).ok();
}

/// The arguments the elevated copy is started with, given this process's own.
///
/// `--elevate` is dropped, so the new process cannot ask to elevate again: a token that is elevated
/// but restricted reports `is_elevated() == false` and would otherwise relaunch in a loop.
/// `--pause-at-exit` is added, because the copy runs in a console window of its own that Windows
/// closes the moment the copy exits — measured on a real Windows 11 machine (ADR 0012, amended).
#[cfg_attr(not(windows), allow(dead_code))]
fn elevated_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut forwarded: Vec<String> = args
        .into_iter()
        .filter(|arg| arg != "--elevate" && arg != "--pause-at-exit")
        .collect();
    forwarded.push("--pause-at-exit".to_owned());
    forwarded
}

/// Starts an elevated copy and returns without scanning; the new process scans from the beginning.
#[cfg(windows)]
fn relaunch_elevated(lang: Lang) -> anyhow::Result<()> {
    use bope_host_windows::elevate::{self, ElevateError};

    let forwarded = elevated_args(std::env::args().skip(1));

    // Both lines go to standard error for the reason `read_answer` does: standard output is the
    // report, and this process produces none.
    match elevate::relaunch_elevated(&forwarded) {
        Ok(()) => {
            eprintln!("{}", output::elevate_started(lang));
            Ok(())
        }
        // Declining the prompt is a choice, not a failure (ADR 0012).
        Err(ElevateError::Declined) => {
            eprintln!("{}", output::elevate_declined(lang));
            Ok(())
        }
        Err(error) => Err(anyhow::Error::new(error).context(output::elevate_failed(lang))),
    }
}

// Same signature as the Windows arm, so the caller does not need to know which one it got. There is
// nothing here that can fail: saying so and exiting is the whole behaviour.
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn relaunch_elevated(lang: Lang) -> anyhow::Result<()> {
    eprintln!("{}", output::elevate_not_windows(lang));
    Ok(())
}

#[cfg(windows)]
fn live_host() -> Box<dyn Host> {
    Box::new(bope_host_windows::LiveHost)
}

#[cfg(not(windows))]
fn live_host() -> Box<dyn Host> {
    Box::new(bope_host::NonWindowsHost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// `--full` reaches the elevated copy, which asks again in its own window (ADR 0052).
    #[test]
    fn the_elevated_copy_keeps_the_full_flag() {
        assert_eq!(
            elevated_args(args(&["scan", "--full", "--elevate"])),
            args(&["scan", "--full", "--pause-at-exit"]),
        );
    }

    #[test]
    fn only_yes_starts_a_full_scan() {
        assert!(is_full_answer("yes"));
        for answer in ["y", "", "no", "ye", "yes please", "ใช่"] {
            assert!(!is_full_answer(answer), "{answer}");
        }
    }

    #[test]
    fn the_elevated_copy_does_not_elevate_again_and_waits_before_closing() {
        assert_eq!(
            elevated_args(args(&["scan", "--json", "--elevate", "--lang", "th"])),
            args(&["scan", "--json", "--lang", "th", "--pause-at-exit"]),
        );
    }

    /// A copy started from a copy still waits once, not twice.
    #[test]
    fn pause_at_exit_is_added_once() {
        assert_eq!(
            elevated_args(args(&["scan", "--pause-at-exit", "--elevate"])),
            args(&["scan", "--pause-at-exit"]),
        );
    }
}
