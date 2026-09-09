// SPDX-License-Identifier: GPL-3.0-or-later
//! `selucid` CLI: explain, suggest, watch, booleans.

use clap::{Parser, Subcommand, ValueEnum};
use selucid_core::{
    AvcEvent, extract_avc_events, group_by_serial,
    reader::{LogTailer, parse_lines},
};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "selucid", version, about = "SELinux AVC troubleshooter")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Explain AVC denials in plain language.
    Explain {
        /// Log file; defaults to stdin, then /var/log/audit/audit.log.
        input: Option<PathBuf>,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Cross-check each denial against the loaded policy via audit2why.
        /// Oracle booleans outrank the static hint map in the diagnosis.
        #[arg(long)]
        why: bool,
    },
    /// Print only the suggested remediation commands.
    Suggest {
        input: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Cross-check each denial against the loaded policy via audit2why.
        #[arg(long)]
        why: bool,
    },
    /// Follow the audit log and print new denials as they arrive.
    Watch {
        /// Poll interval in milliseconds (fallback when inotify is
        /// unavailable; otherwise notifications arrive instantly).
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        /// Cross-check each denial against the loaded policy via audit2why.
        #[arg(long)]
        why: bool,
    },
    /// Show the audit2why verdict for each denial (policy ground truth).
    Why {
        input: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Export events (and optionally diagnoses) to a file.
    Export {
        /// Log file to read; defaults to stdin, then /var/log/audit/audit.log.
        input: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Output file (`-` for stdout).
        #[arg(long, short, default_value = "-")]
        output: String,
        /// Include full diagnoses (explanation + fixes) in the export.
        #[arg(long)]
        with_diagnoses: bool,
        /// Cross-check each denial against the loaded policy via audit2why.
        #[arg(long)]
        why: bool,
    },
    /// Preview or apply a remediation fix for one denial.
    ///
    /// Without `--execute`, prints the exact privileged command for review.
    /// With `--execute`, re-runs it under `pkexec` after confirmation.
    Fix {
        /// Log file holding the denial; defaults to stdin, then the audit log.
        input: Option<PathBuf>,
        /// 1-based index of the denial in the input (as shown by `explain`).
        #[arg(long, default_value_t = 1)]
        index: usize,
        /// 1-based index of the fix within that denial's suggestion list.
        #[arg(long, default_value_t = 1)]
        fix: usize,
        /// Actually execute via pkexec (otherwise just preview). Prompts for
        /// confirmation unless `--yes` is also given.
        #[arg(long)]
        execute: bool,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// List SELinux booleans, optionally filtered by substring.
    Booleans {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

/// Serialization formats for `selucid export` (blueprint §4: config
/// management and export routines via serde/serde_json).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    /// Pretty-printed JSON array of events (or event+diagnosis objects).
    Json,
    /// JSON lines: one event per line, for log pipelines.
    Jsonl,
    /// CSV: one row per denial (summary, contexts, perms, path, fixes).
    Csv,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::Jsonl => write!(f, "jsonl"),
            ExportFormat::Csv => write!(f, "csv"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Explain { input, json, why } => {
            let events = load_events(input).await;
            let oracles = maybe_oracles(&events, why);
            if json {
                let out: Vec<_> = events
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        serde_json::json!({
                            "event": e,
                            "diagnosis": diagnose_event(e, oracles.get(i).and_then(|o| o.as_ref())),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if events.is_empty() {
                println!("No AVC denials found.");
            } else {
                for (i, event) in events.iter().enumerate() {
                    print_explanation(event, oracles.get(i).and_then(|o| o.as_ref()));
                }
            }
        }
        Commands::Suggest { input, json, why } => {
            let events = load_events(input).await;
            let oracles = maybe_oracles(&events, why);
            if json {
                let fixes: Vec<_> = events
                    .iter()
                    .enumerate()
                    .map(|(i, e)| diagnose_event(e, oracles.get(i).and_then(|o| o.as_ref())).fixes)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&fixes)?);
            } else if events.is_empty() {
                println!("No AVC denials found.");
            } else {
                for (i, event) in events.iter().enumerate() {
                    let d = diagnose_event(event, oracles.get(i).and_then(|o| o.as_ref()));
                    println!("# {}", event.summary());
                    for fix in &d.fixes {
                        println!("  {}", fix.command);
                    }
                    println!();
                }
            }
        }
        Commands::Watch { interval_ms, why } => {
            watch_log(interval_ms, why).await?;
        }
        Commands::Why { input, json } => {
            run_why(input, json).await?;
        }
        Commands::Export {
            input,
            format,
            output,
            with_diagnoses,
            why,
        } => {
            run_export(input, format, &output, with_diagnoses, why).await?;
        }
        Commands::Fix {
            input,
            index,
            fix,
            execute,
            yes,
        } => {
            let events = load_events(input).await;
            let Some(event) = events.get(index.saturating_sub(1)) else {
                eprintln!(
                    "No denial #{index} (input holds {} denial(s)).",
                    events.len()
                );
                std::process::exit(1);
            };
            let d = diagnose_event(event, None);
            let Some(suggestion) = d.fixes.get(fix.saturating_sub(1)) else {
                eprintln!(
                    "Denial #{index} has {} fix(es); no fix #{fix}.",
                    d.fixes.len()
                );
                std::process::exit(1);
            };
            let action = fix_to_action(&d.fixes[fix.saturating_sub(1)]);
            println!("Denial: {}", event.summary());
            println!("Fix:    {}", suggestion.title);
            println!("Command (via pkexec): {}", action.preview());
            if !execute {
                println!("Re-run with `--execute` to apply after review.");
                return Ok(());
            }
            if !yes {
                println!("Apply this fix? [y/N]");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim().to_lowercase() != "y" {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            match action.execute() {
                Ok(out) => {
                    if out.trim().is_empty() {
                        println!("Fix applied.");
                    } else {
                        println!("Fix applied:\n{out}");
                    }
                }
                Err(e) => {
                    eprintln!("Fix failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Booleans { search, json } => {
            let list = match search {
                Some(q) => selucid_core::booleans::search_booleans(&q),
                None => selucid_core::booleans::list_booleans(),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("No SELinux booleans found (is SELinux enabled?).");
            } else {
                for b in list {
                    println!("{:<45} {}", b.name, if b.active { "on" } else { "off" });
                }
            }
        }
    }
    Ok(())
}

fn expected_for(event: &AvcEvent) -> Option<String> {
    // Only absolute paths are meaningful to matchpathcon; relative names from
    // bare `name=` fields (e.g. smbd share names) would otherwise produce
    // confusing `<<none>>` output.
    let path = event.path.as_deref().filter(|p| p.starts_with('/'))?;
    selucid_core::privileged::expected_context(path)
}

/// Diagnose with an optional precomputed oracle result.
fn diagnose_event(
    event: &AvcEvent,
    oracle: Option<&selucid_core::WhyAnalysis>,
) -> selucid_core::Diagnosis {
    selucid_core::diagnose_with_oracle(event, expected_for(event).as_deref(), None, oracle)
}

/// Run `audit2why` over all events when `--why` is passed; otherwise Nones.
fn maybe_oracles(events: &[AvcEvent], enabled: bool) -> Vec<Option<selucid_core::WhyAnalysis>> {
    if !enabled {
        return events.iter().map(|_| None).collect();
    }
    let raws: Vec<&str> = events.iter().map(|e| e.raw.as_str()).collect();
    selucid_core::analyze_batch(&raws)
        .into_iter()
        .map(|a| if a.inconclusive { None } else { Some(a) })
        .collect()
}

fn analyses_json(
    events: &[AvcEvent],
    analyses: &[selucid_core::WhyAnalysis],
) -> Vec<serde_json::Value> {
    events
        .iter()
        .zip(analyses)
        .map(|(e, a)| {
            serde_json::json!({
                "summary": e.summary(),
                "audit_id": e.audit_id,
                "booleans": a.booleans,
                "needs_type_enforcement": a.needs_type_enforcement,
                "inconclusive": a.inconclusive,
            })
        })
        .collect()
}

/// Map a suggested fix back onto an executable privileged action.
///
/// `Restorecon` and `SetBoolean` have exact argv builders. Compound or
/// generated commands (semanage pipelines, audit2allow module builds) are
/// intentionally *not* executable here: they embed shell pipelines and
/// deserve eyes-on review, so `fix --execute` refuses them with guidance.
fn fix_to_action(fix: &selucid_core::SuggestedFix) -> selucid_core::privileged::PrivilegedAction {
    use selucid_core::{FixKind, privileged as privrun};
    match &fix.kind {
        FixKind::Restorecon => {
            let path = fix
                .command
                .strip_prefix("restorecon -v ")
                .unwrap_or("")
                .trim();
            privrun::restorecon_action(path)
        }
        FixKind::SetBoolean => {
            // Command shape: `setsebool -P <name> 1`.
            let mut parts = fix.command.split_whitespace();
            let name = parts.nth(2).unwrap_or("");
            let on = parts.next().unwrap_or("1") == "1";
            privrun::setsebool_action(name, on)
        }
        FixKind::SemanageFcontext | FixKind::PolicyModule | FixKind::ContainerVolume => {
            eprintln!(
                "This fix is a compound/generated command and cannot run unattended:\n  {}\n\
                 Review it, then apply it manually (for Podman `-v` flags: edit the \
                 container's run command and restart it).",
                fix.command
            );
            std::process::exit(2);
        }
    }
}

/// Live log view: inotify-driven when available, polling fallback otherwise.
async fn watch_log(interval_ms: u64, why: bool) -> Result<(), Box<dyn std::error::Error>> {
    use selucid_core::{LogWatcher, WatchEvent};
    use std::sync::mpsc::channel;

    let path = LogTailer::audit_log();
    println!("Watching {} … (Ctrl-C to stop)", path.path().display());

    // Bridge notify's sync callback into the async loop via an mpsc channel.
    let (tx, rx) = channel::<WatchEvent>();
    let _watch = match LogWatcher::watch(path.path(), move |ev| {
        let _ = tx.send(ev);
    }) {
        Ok(w) => {
            println!("(live: inotify notifications)");
            Some(w)
        }
        Err(e) => {
            eprintln!("(inotify unavailable: {e}; falling back to polling)");
            None
        }
    };

    if _watch.is_some() {
        loop {
            // Poll the channel without blocking the runtime: notify pushes,
            // we drain with a short timeout, then yield to tokio.
            let mut pending = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                pending.push(ev);
            }
            for ev in pending {
                match ev {
                    WatchEvent::Denials(events) => {
                        let oracles = maybe_oracles(&events, why);
                        for (i, event) in events.iter().enumerate() {
                            print_explanation(event, oracles.get(i).and_then(|o| o.as_ref()));
                        }
                    }
                    WatchEvent::Rotated => println!("(log rotated — continuing)"),
                    WatchEvent::WatchError(e) => eprintln!("watch error: {e}"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    // Polling fallback: the original tailer loop.
    let mut tailer = LogTailer::audit_log();
    loop {
        let events = events_from_lines(&tailer.poll_new_lines().await?);
        let oracles = maybe_oracles(&events, why);
        for (i, event) in events.iter().enumerate() {
            print_explanation(event, oracles.get(i).and_then(|o| o.as_ref()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }
}

fn print_explanation(event: &AvcEvent, oracle: Option<&selucid_core::WhyAnalysis>) {
    let expected = expected_for(event);
    let d = selucid_core::diagnose_with_oracle(event, expected.as_deref(), None, oracle);
    println!("=== {} ===", event.summary());
    println!("audit id:  {}  raw: {}", event.audit_id, event.raw);
    println!("scontext:  {}", event.scontext);
    println!("tcontext:  {}", event.tcontext);
    if let Some(path) = &event.path {
        println!("path:      {path}");
        if !path.starts_with('/') {
            println!("expected:  (relative name — no matchpathcon lookup)");
        } else {
            match expected {
                Some(e) => println!("expected:  {e}  (via matchpathcon)"),
                None => println!("expected:  (matchpathcon unavailable)"),
            }
        }
    }
    println!("\n{}", d.explanation);
    println!("\nSuggested fixes (confidence: {:?}):", d.confidence);
    for (i, fix) in d.fixes.iter().enumerate() {
        let root = if fix.needs_root { " [needs root]" } else { "" };
        println!("  {}. {}{}\n     $ {}", i + 1, fix.title, root, fix.command);
        println!("     {}", fix.description);
    }
    println!();
}

/// Read log lines from: explicit path → piped stdin → live audit log.
async fn load_events(input: Option<PathBuf>) -> Vec<AvcEvent> {
    if let Some(path) = input {
        return events_from_file(&path).await;
    }
    if !std::io::stdin().is_terminal() {
        let mut text = String::new();
        if std::io::stdin().read_to_string(&mut text).is_ok() && !text.trim().is_empty() {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            return events_from_lines(&lines);
        }
    }
    match LogTailer::audit_log().read_all().await {
        Ok(lines) => events_from_lines(&lines),
        Err(e) => {
            eprintln!(
                "Cannot read {}: {e}. Try: ausearch -m avc -ts recent | selucid explain",
                LogTailer::audit_log().path().display()
            );
            Vec::new()
        }
    }
}

async fn events_from_file(path: &PathBuf) -> Vec<AvcEvent> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => {
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            events_from_lines(&lines)
        }
        Err(e) => {
            eprintln!("Cannot read {}: {e}", path.display());
            Vec::new()
        }
    }
}

fn events_from_lines(lines: &[String]) -> Vec<AvcEvent> {
    extract_avc_events(&group_by_serial(parse_lines(lines)))
}
/// Show the audit2why verdict for each denial (policy ground truth).
async fn run_why(input: Option<PathBuf>, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let events = load_events(input).await;
    let raws: Vec<&str> = events.iter().map(|e| e.raw.as_str()).collect();
    let analyses = selucid_core::analyze_batch(&raws);
    if json {
        write_output(
            "-",
            &serde_json::to_string_pretty(&analyses_json(&events, &analyses))?,
        )?;
    } else if events.is_empty() {
        println!("No AVC denials found.");
    } else {
        for (event, analysis) in events.iter().zip(&analyses) {
            println!("=== {} ===", event.summary());
            if analysis.inconclusive {
                println!("(audit2why gave no verdict — is it installed?)");
            } else {
                if !analysis.booleans.is_empty() {
                    println!("booleans: {}", analysis.booleans.join(", "));
                }
                if analysis.needs_type_enforcement {
                    println!("verdict:  missing TE allow rule (audit2allow needed)");
                }
                let body = analysis.raw.trim();
                if !body.is_empty() {
                    println!("--- audit2why ---");
                    println!("{body}");
                }
            }
            println!();
        }
    }
    Ok(())
}

/// Serialize events (plus optional diagnoses) as JSON / JSONL / CSV.
async fn run_export(
    input: Option<PathBuf>,
    format: ExportFormat,
    output: &str,
    with_diagnoses: bool,
    why: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let events = load_events(input).await;
    let oracles = maybe_oracles(&events, why);
    let text = match format {
        ExportFormat::Json => {
            if with_diagnoses {
                let out: Vec<_> = events
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        serde_json::json!({
                            "event": e,
                            "diagnosis": diagnose_event(
                                e,
                                oracles.get(i).and_then(|o| o.as_ref())
                            ),
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&out)?
            } else {
                serde_json::to_string_pretty(&events)?
            }
        }
        ExportFormat::Jsonl => {
            let mut buf = String::new();
            for (i, e) in events.iter().enumerate() {
                if with_diagnoses {
                    buf.push_str(&serde_json::to_string(&serde_json::json!({
                        "event": e,
                        "diagnosis": diagnose_event(
                            e,
                            oracles.get(i).and_then(|o| o.as_ref())
                        ),
                    }))?);
                } else {
                    buf.push_str(&serde_json::to_string(e)?);
                }
                buf.push('\n');
            }
            buf
        }
        ExportFormat::Csv => export_csv(&events, &oracles, with_diagnoses),
    };
    write_output(output, &text)
}

fn export_csv(
    events: &[AvcEvent],
    oracles: &[Option<selucid_core::WhyAnalysis>],
    with_diagnoses: bool,
) -> String {
    fn esc(s: &str) -> String {
        if s.contains([',', '"', '\n']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::from(
        "serial,timestamp,comm,pid,scontext,tcontext,tclass,perms,path,confidence,fixes\n",
    );
    for (i, e) in events.iter().enumerate() {
        let fixes = if with_diagnoses {
            diagnose_event(e, oracles.get(i).and_then(|o| o.as_ref()))
                .fixes
                .iter()
                .map(|f| f.command.clone())
                .collect::<Vec<_>>()
                .join(" | ")
        } else {
            String::new()
        };
        let confidence = if with_diagnoses {
            format!(
                "{:?}",
                diagnose_event(e, oracles.get(i).and_then(|o| o.as_ref())).confidence
            )
        } else {
            String::new()
        };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            e.serial,
            e.timestamp,
            esc(e.comm.as_deref().unwrap_or("")),
            e.pid.map(|p| p.to_string()).unwrap_or_default(),
            esc(&e.scontext),
            esc(&e.tcontext),
            esc(&e.tclass),
            esc(&e.perms.join(" ")),
            esc(e.path.as_deref().unwrap_or("")),
            confidence,
            esc(&fixes),
        ));
    }
    out
}

/// Write text to stdout (`-`) or a file.
fn write_output(dest: &str, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if dest == "-" {
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    } else {
        std::fs::write(dest, text)?;
        eprintln!("Wrote {} ({} bytes)", dest, text.len());
    }
    Ok(())
}
