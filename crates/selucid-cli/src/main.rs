// SPDX-License-Identifier: GPL-3.0-or-later
//! `selucid` CLI: explain, suggest, watch, booleans.

use clap::{Parser, Subcommand};
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
    },
    /// Print only the suggested remediation commands.
    Suggest {
        input: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Follow the audit log and print new denials as they arrive.
    Watch {
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// List SELinux booleans, optionally filtered by substring.
    Booleans {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Explain { input, json } => {
            let events = load_events(input).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else if events.is_empty() {
                println!("No AVC denials found.");
            } else {
                for event in &events {
                    print_explanation(event);
                }
            }
        }
        Commands::Suggest { input, json } => {
            let events = load_events(input).await;
            if json {
                let fixes: Vec<_> = events
                    .iter()
                    .map(|e| selucid_core::diagnose(e, expected_for(e).as_deref(), None).fixes)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&fixes)?);
            } else if events.is_empty() {
                println!("No AVC denials found.");
            } else {
                for event in &events {
                    let d = selucid_core::diagnose(event, expected_for(event).as_deref(), None);
                    println!("# {}", event.summary());
                    for fix in &d.fixes {
                        println!("  {}", fix.command);
                    }
                    println!();
                }
            }
        }
        Commands::Watch { interval_ms } => {
            let mut tailer = LogTailer::audit_log();
            println!("Watching {} …", tailer.path().display());
            loop {
                for event in events_from_lines(&tailer.poll_new_lines().await?) {
                    print_explanation(&event);
                }
                tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
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
fn print_explanation(event: &AvcEvent) {
    let expected = expected_for(event);
    let d = selucid_core::diagnose(event, expected.as_deref(), None);
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
