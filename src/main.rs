use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use significant::{FileKey, keys};

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
        /// Print the full C2PA report as JSON
        #[arg(long)]
        json: bool,
    },
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
            println!("device {id}");
            println!("keys in {}", dir.display());
        }
        Command::Sign { file } => {
            let key = FileKey::load(&key_dir()?)?;
            significant::sign(file, Arc::new(key))?;
            println!("signed {}", file.display());
        }
        Command::Verify { file, json } => {
            let Some(result) = significant::verify(file)? else {
                println!("unsigned");
                return Ok(ExitCode::from(1));
            };
            if *json {
                println!("{}", result.report);
            } else {
                println!(
                    "content: {}",
                    if result.intact { "intact" } else { "FAILED" }
                );
                println!("signer: {}", result.signer.as_deref().unwrap_or("unknown"));
                println!(
                    "identity: {}",
                    if result.trusted {
                        "trusted"
                    } else {
                        "not checked"
                    }
                );
                for problem in &result.problems {
                    println!("problem: {problem}");
                }
            }
            if !result.intact {
                return Ok(ExitCode::from(1));
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
