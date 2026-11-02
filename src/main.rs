use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use significant::{Added, FileKey, Trust, keys};

#[derive(Parser)]
#[command(version, about = "Sign and verify media files with no sidecar files")]
struct Cli {
    /// Key directory. Defaults to $SIGNIFICANT_HOME or ~/.config/significant.
    #[arg(long, global = true)]
    key_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a development device key
    Keygen {
        /// Replace an existing key
        #[arg(long)]
        force: bool,
    },
    /// Embed a signature in a file
    Sign { file: PathBuf },
    /// Check a file's embedded signature
    Verify {
        file: PathBuf,
        /// Print the full report as JSON
        #[arg(long)]
        json: bool,
        /// Fail unless the signer is trusted
        #[arg(long)]
        require_trust: bool,
    },
    /// Trust a device fingerprint, or the authorities in a PEM file
    Trust { signer: String },
    /// Print the byte ranges the manifest occupies, as "start length"
    Ranges { file: PathBuf },
    /// Remove an embedded signature, saving its manifest next to the file
    Unsign {
        file: PathBuf,
        /// Delete the manifest instead of saving it
        #[arg(long, conflicts_with = "force")]
        discard: bool,
        /// Replace an existing saved manifest
        #[arg(long)]
        force: bool,
    },
    /// Put a saved manifest back
    Restore {
        file: PathBuf,
        /// Manifest file. Defaults to FILE.c2pa.
        manifest: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let key_dir = || cli.key_dir.clone().map_or_else(keys::default_key_dir, Ok);
    match &cli.command {
        Command::Keygen { force } => {
            let dir = key_dir()?;
            let id = keys::generate(&dir, *force)?;
            println!("fingerprint sha256:{id}");
            println!("keys in {}", dir.display());
        }
        Command::Sign { file } => {
            let key = FileKey::load(&key_dir()?)?;
            significant::sign(file, Arc::new(key))?;
            println!("signed {}", file.display());
        }
        Command::Verify {
            file,
            json,
            require_trust,
        } => {
            let trust = match key_dir() {
                Ok(dir) => Trust::load(&dir)?,
                Err(_) => Trust::default(),
            };
            let Some(result) = significant::verify_with(file, &trust)? else {
                println!("unsigned");
                return Ok(ExitCode::from(1));
            };
            if *json {
                println!("{}", result.report);
            } else {
                print_verification(&result);
            }
            if !result.intact || (*require_trust && !result.trusted) {
                return Ok(ExitCode::from(1));
            }
        }
        Command::Trust { signer } => match Trust::add(&key_dir()?, signer)? {
            Added::Device => println!("trusted device {signer}"),
            Added::Authorities(count) => println!("trusted {count} authority certificate(s)"),
        },
        Command::Ranges { file } => {
            let Some(ranges) = significant::manifest_ranges(file)? else {
                println!("unsigned");
                return Ok(ExitCode::from(1));
            };
            for range in ranges {
                println!("{} {}", range.start, range.end - range.start);
            }
        }
        Command::Unsign {
            file,
            discard,
            force,
        } => {
            let sidecar = (!discard).then(|| significant::sidecar_path(file));
            if significant::unsign(file, sidecar.as_deref(), *force)? {
                println!("unsigned {}", file.display());
                if let Some(sidecar) = sidecar {
                    println!("manifest saved to {}", sidecar.display());
                }
            } else {
                println!("{} has no signature", file.display());
            }
        }
        Command::Restore { file, manifest } => {
            let manifest = manifest
                .clone()
                .unwrap_or_else(|| significant::sidecar_path(file));
            significant::restore(file, &manifest)?;
            println!("restored {}", file.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_verification(result: &significant::Verification) {
    let content = if result.intact { "intact" } else { "FAILED" };
    println!("content: {content}");
    match &result.fingerprint {
        Some(id) => println!("signer: sha256:{id}"),
        None => println!("signer: unknown"),
    }
    if result.trusted {
        if let Some(name) = &result.claimed_name {
            println!("name: {name}");
        }
    }
    let identity = match (result.intact, result.trusted) {
        (false, _) => "not checked, content failed",
        (true, true) => "trusted",
        (true, false) => "unknown",
    };
    println!("identity: {identity}");
    for problem in &result.problems {
        println!("problem: {problem}");
    }
}
