//! `xcrypt` — the command-line front end.
//!
//! This crate owns argument parsing, prompting, progress, and output formatting.
//! Every cryptographic and filesystem decision lives in `xcrypt-core`.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | success |
//! | 1    | the operation failed (authentication, I/O, refused overwrite) |
//! | 2    | the command line was invalid |
//!
//! # Output discipline
//!
//! Results go to stdout, progress and diagnostics to stderr. With `--json`,
//! stdout carries exactly one JSON object — including on failure — so a caller
//! can parse the outcome without scraping text.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod args;
mod ui;

use std::path::Path;

use clap::Parser;
use serde_json::json;

use xcrypt_core::{
    decrypt_archive, encrypt_paths, list_archive, rewrap_archive, verify_archive, ArchiveSummary,
    DecryptOptions, EncryptOptions, EntryKind, Error, KdfPolicy, Manifest, PackSummary, Result,
};

use args::{Cli, Command};
use ui::{Reporter, NEW_PASSPHRASE_ENV, PASSPHRASE_ENV};

fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    match run(cli) {
        Ok(()) => {}
        Err(error) => {
            report_error(&error, json);
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Encrypt {
            paths,
            output,
            chunk_size,
            argon2_mem,
            argon2_time,
            argon2_lanes,
            pad_names,
            force,
        } => {
            let options = EncryptOptions {
                chunk_size,
                m_cost_kib: argon2_mem,
                t_cost: argon2_time,
                p_cost: argon2_lanes,
                pad_sizes: pad_names,
                force,
                policy: KdfPolicy::default(),
            };
            // Fail on a bad cost before asking for a passphrase: nobody enjoys
            // typing one twice only to be told `--argon2-mem` was too small.
            options.policy.check(&xcrypt_core::KdfParams {
                algorithm: xcrypt_core::KdfAlgorithm::Argon2id,
                m_cost_kib: options.m_cost_kib,
                t_cost: options.t_cost,
                p_cost: options.p_cost,
                salt: [0u8; 32],
            })?;

            let passphrase = ui::read_passphrase("New passphrase", true, PASSPHRASE_ENV)?;
            let reporter = Reporter::new("encrypting", cli.quiet, cli.json);
            let summary = encrypt_paths(
                &paths,
                &output,
                &passphrase,
                &options,
                reporter.as_progress(),
            );
            reporter.finish();
            let summary = summary?;

            emit_summary("encrypt", &output, &summary, &reporter.notes(), cli.json);
            Ok(())
        }

        Command::Decrypt {
            archive,
            output,
            force,
            no_restore_modes,
        } => {
            let options = DecryptOptions {
                force,
                restore_modes: !no_restore_modes,
                policy: KdfPolicy::default(),
            };
            let passphrase = ui::read_passphrase("Passphrase", false, PASSPHRASE_ENV)?;
            let reporter = Reporter::new("decrypting", cli.quiet, cli.json);
            let summary = decrypt_archive(
                &archive,
                &output,
                &passphrase,
                &options,
                reporter.as_progress(),
            );
            reporter.finish();
            let summary = summary?;

            emit_summary("decrypt", &output, &summary, &reporter.notes(), cli.json);
            Ok(())
        }

        Command::List { archive } => {
            let passphrase = ui::read_passphrase("Passphrase", false, PASSPHRASE_ENV)?;
            let manifest = list_archive(&archive, &passphrase, &KdfPolicy::default())?;
            emit_listing(&archive, &manifest, cli.json);
            Ok(())
        }

        Command::Verify { archive } => {
            let passphrase = ui::read_passphrase("Passphrase", false, PASSPHRASE_ENV)?;
            let reporter = Reporter::new("verifying", cli.quiet, cli.json);
            let summary = verify_archive(
                &archive,
                &passphrase,
                &KdfPolicy::default(),
                reporter.as_progress(),
            );
            reporter.finish();
            let summary = summary?;

            emit_summary("verify", &archive, &summary, &reporter.notes(), cli.json);
            Ok(())
        }

        Command::Pack {
            archive,
            output,
            chunk_size,
            force,
        } => {
            let options = EncryptOptions {
                chunk_size,
                force,
                ..Default::default()
            };
            let passphrase = ui::read_passphrase("Passphrase", false, PASSPHRASE_ENV)?;
            let reporter = Reporter::new("packing", cli.quiet, cli.json);
            let summary = xcrypt_core::pack_archive(
                &archive,
                &output,
                &passphrase,
                &options,
                reporter.as_progress(),
            );
            reporter.finish();
            let summary = summary?;

            emit_pack("pack", &output, &summary, cli.json);
            Ok(())
        }

        Command::Unpack {
            packed,
            output,
            force,
        } => {
            let passphrase = ui::read_passphrase("Passphrase", false, PASSPHRASE_ENV)?;
            let reporter = Reporter::new("unpacking", cli.quiet, cli.json);
            let summary = xcrypt_core::unpack_archive(
                &packed,
                &output,
                &passphrase,
                &KdfPolicy::default(),
                force,
                reporter.as_progress(),
            );
            reporter.finish();
            let summary = summary?;

            emit_pack("unpack", &output, &summary, cli.json);
            Ok(())
        }

        Command::Rewrap {
            archive,
            argon2_mem,
            argon2_time,
            argon2_lanes,
        } => {
            let options = EncryptOptions {
                m_cost_kib: argon2_mem,
                t_cost: argon2_time,
                p_cost: argon2_lanes,
                ..Default::default()
            };
            let old = ui::read_passphrase("Current passphrase", false, PASSPHRASE_ENV)?;
            let new = ui::read_passphrase("New passphrase", true, NEW_PASSPHRASE_ENV)?;

            rewrap_archive(&archive, &old, &new, &options)?;

            if cli.json {
                println!(
                    "{}",
                    json!({
                        "command": "rewrap",
                        "archive": archive.to_string_lossy(),
                        "ok": true,
                    })
                );
            } else {
                println!("Passphrase changed for {}", archive.display());
                println!("File containers were not rewritten; only the master key was rewrapped.");
            }
            Ok(())
        }
    }
}

/// Print a summary for `encrypt`, `decrypt`, or `verify`.
fn emit_summary(
    command: &str,
    path: &Path,
    summary: &ArchiveSummary,
    notes: &[String],
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            json!({
                "command": command,
                "path": path.to_string_lossy(),
                "files": summary.files,
                "directories": summary.directories,
                "symlinks": summary.symlinks,
                "bytes": summary.bytes,
                "skipped": summary
                    .skipped
                    .iter()
                    .map(|(path, reason)| json!({
                        "path": path.to_string_lossy(),
                        "reason": reason,
                    }))
                    .collect::<Vec<_>>(),
                "notes": notes,
            })
        );
        return;
    }

    let verb = match command {
        "encrypt" => "Encrypted",
        "decrypt" => "Decrypted",
        _ => "Verified",
    };
    println!(
        "{verb} {} files, {} directories, {} symlinks ({}) — {}",
        summary.files,
        summary.directories,
        summary.symlinks,
        human_bytes(summary.bytes),
        path.display()
    );
    for (path, reason) in &summary.skipped {
        println!("  skipped {}: {reason}", path.display());
    }
}

/// Print a summary for `pack` or `unpack`.
fn emit_pack(command: &str, path: &Path, summary: &PackSummary, json_output: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "command": command,
                "path": path.to_string_lossy(),
                "objects": summary.objects,
                "files": summary.files,
                "bundle_bytes": summary.bundle_len,
                "packed_bytes": summary.packed_len,
            })
        );
        return;
    }

    if command == "pack" {
        println!(
            "Packed {} files ({} objects) into {} — {}",
            summary.files,
            summary.objects,
            human_bytes(summary.packed_len),
            path.display()
        );
        println!("The packed file hides the object count and individual object sizes.");
    } else {
        println!(
            "Unpacked {} objects ({} files) into {}",
            summary.objects,
            summary.files,
            path.display()
        );
    }
}

/// Print a manifest listing.
fn emit_listing(archive: &Path, manifest: &Manifest, json_output: bool) {
    if json_output {
        let entries: Vec<serde_json::Value> = manifest
            .entries
            .iter()
            .map(|entry| {
                let (kind, size, target) = match &entry.kind {
                    EntryKind::File { size, .. } => ("file", Some(*size), None),
                    EntryKind::Directory => ("directory", None, None),
                    EntryKind::Symlink { target } => (
                        "symlink",
                        None,
                        Some(String::from_utf8_lossy(target).into_owned()),
                    ),
                };
                json!({
                    "path": entry.display_path().to_string_lossy(),
                    "kind": kind,
                    "size": size,
                    "mode": entry.mode.map(|m| format!("{:04o}", m & 0o7777)),
                    "mtime_secs": entry.mtime_secs,
                    "target": target,
                })
            })
            .collect();

        println!(
            "{}",
            json!({
                "command": "list",
                "archive": archive.to_string_lossy(),
                "files": manifest.file_count(),
                "bytes": manifest.total_size(),
                "entries": entries,
            })
        );
        return;
    }

    for entry in &manifest.entries {
        let mode = entry
            .mode
            .map(|m| format!("{:04o}", m & 0o7777))
            .unwrap_or_else(|| "----".to_owned());
        match &entry.kind {
            EntryKind::File { size, .. } => println!(
                "{mode}  {:>10}  {}",
                human_bytes(*size),
                entry.display_path().display()
            ),
            EntryKind::Directory => {
                println!("{mode}  {:>10}  {}/", "-", entry.display_path().display())
            }
            EntryKind::Symlink { target } => println!(
                "{mode}  {:>10}  {} -> {}",
                "link",
                entry.display_path().display(),
                String::from_utf8_lossy(target)
            ),
        }
    }
    println!(
        "\n{} files, {} total",
        manifest.file_count(),
        human_bytes(manifest.total_size())
    );
}

/// Report a failure. With `--json`, the machine-readable form goes to stdout so a
/// caller parsing stdout sees the error rather than an empty stream.
fn report_error(error: &Error, json_output: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "ok": false,
                "error": {
                    "kind": error.kind(),
                    "message": error.to_string(),
                },
            })
        );
    } else {
        eprintln!("xcrypt: error: {error}");
        if let Error::NoMatchingRecipient = error {
            eprintln!("        (the passphrase is wrong, or the archive's keyring was altered)");
        }
    }
}

/// Human-readable byte count. Binary units, because that is what the format uses.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_render_readably() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(10 * 1024 * 1024), "10.0 MiB");
    }
}
