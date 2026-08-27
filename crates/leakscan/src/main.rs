use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use leakscan::scan_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(name = "leakscan")]
struct Args {
    #[arg(long)]
    canaries: PathBuf,
    #[arg(long, required = true)]
    json: bool,
    #[arg(required = true)]
    targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CanaryFile {
    canaries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    hits: Vec<ReportHit>,
}

#[derive(Debug, Serialize)]
struct ReportHit {
    path: String,
    canary_index: usize,
    encoding: String,
    byte_offset: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(has_hits) => {
            if has_hits {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let args = Args::parse();
    let _json = args.json;
    let canaries = read_canaries(&args.canaries)?;
    let mut hits = Vec::new();

    for target in &args.targets {
        scan_target(target, &canaries, &mut hits)?;
    }

    let report = Report { hits };
    println!(
        "{}",
        serde_json::to_string(&report).expect("serializing the report cannot fail")
    );
    Ok(!report.hits.is_empty())
}

fn read_canaries(path: &Path) -> Result<Vec<String>, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read canaries file {}: {error}", path.display()))?;
    let canary_file: CanaryFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse canaries file {}: {error}", path.display()))?;
    Ok(canary_file.canaries)
}

fn scan_target(target: &str, canaries: &[String], hits: &mut Vec<ReportHit>) -> Result<(), String> {
    if target == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        append_hits("-", &bytes, canaries, hits);
        return Ok(());
    }

    let path = Path::new(target);
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect target {}: {error}", path.display()))?;

    if metadata.is_dir() {
        scan_directory(path, canaries, hits, true)
    } else if metadata.is_file() {
        scan_file(path, canaries, hits, true)
    } else {
        Ok(())
    }
}

fn scan_directory(
    directory: &Path,
    canaries: &[String],
    hits: &mut Vec<ReportHit>,
    is_target: bool,
) -> Result<(), String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if is_target => {
            return Err(format!(
                "failed to read directory {}: {error}",
                directory.display()
            ));
        }
        Err(error) => {
            eprintln!(
                "warning: failed to read directory {}: {error}",
                directory.display()
            );
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("warning: failed to read directory entry: {error}");
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                eprintln!("warning: failed to inspect {}: {error}", path.display());
                continue;
            }
        };

        if file_type.is_dir() {
            scan_directory(&path, canaries, hits, false)?;
        } else if file_type.is_file() {
            scan_file(&path, canaries, hits, false)?;
        }
    }

    Ok(())
}

fn scan_file(
    path: &Path,
    canaries: &[String],
    hits: &mut Vec<ReportHit>,
    is_target: bool,
) -> Result<(), String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if is_target => {
            return Err(format!("failed to read target {}: {error}", path.display()));
        }
        Err(error) => {
            eprintln!("warning: failed to read {}: {error}", path.display());
            return Ok(());
        }
    };

    append_hits(&path.to_string_lossy(), &bytes, canaries, hits);
    Ok(())
}

fn append_hits(path: &str, bytes: &[u8], canaries: &[String], hits: &mut Vec<ReportHit>) {
    for hit in scan_bytes(bytes, canaries) {
        hits.push(ReportHit {
            path: path.to_owned(),
            canary_index: hit.canary_index,
            encoding: hit.encoding,
            byte_offset: hit.byte_offset,
        });
    }
}
