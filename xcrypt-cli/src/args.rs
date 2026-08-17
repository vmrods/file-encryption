//! Command-line surface.
//!
//! One deliberate omission: there is no `--passphrase` flag, and there never
//! will be. Command lines are visible in `ps`, land in shell history, and end up
//! in CI logs. Passphrases come from a TTY prompt or from `XCRYPT_PASSPHRASE`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use xcrypt_core::header::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};

/// Authenticated encryption for files and directory trees.
#[derive(Debug, Parser)]
#[command(
    name = "xcrypt",
    version,
    about = "Authenticated file and folder encryption",
    long_about = "Encrypts files and directory trees with XChaCha20-Poly1305 in the \
                  STREAM construction, under an Argon2id-derived key.\n\n\
                  Passphrases are read from a terminal prompt, or from the \
                  XCRYPT_PASSPHRASE environment variable. There is no passphrase flag."
)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout instead of human-readable text.
    ///
    /// Progress bars are suppressed; errors are reported as JSON too.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress progress output on stderr.
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The five verbs.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt files and directories into a new archive.
    Encrypt {
        /// Files and directories to archive.
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<PathBuf>,

        /// Archive directory to create.
        #[arg(short = 'o', long = "output", value_name = "ARCHIVE_DIR")]
        output: PathBuf,

        /// Plaintext bytes per chunk. Accepts suffixes: 64KiB, 1MiB.
        #[arg(long, value_name = "SIZE", default_value = "64KiB", value_parser = parse_chunk_size)]
        chunk_size: u32,

        /// Argon2id memory cost. Accepts suffixes: 256MiB, 1GiB.
        #[arg(long, value_name = "SIZE", default_value = "256MiB", value_parser = parse_memory_kib)]
        argon2_mem: u32,

        /// Argon2id iteration count.
        #[arg(long, value_name = "N", default_value_t = 3)]
        argon2_time: u32,

        /// Argon2id parallelism (lanes).
        #[arg(long, value_name = "N", default_value_t = 4)]
        argon2_lanes: u32,

        /// Pad stored files to power-of-two lengths, hiding exact file sizes.
        ///
        /// Costs up to 2x storage. Does not hide the archive's total size or its
        /// file count.
        #[arg(long)]
        pad_names: bool,

        /// Replace an existing archive at the output path.
        #[arg(long)]
        force: bool,
    },

    /// Decrypt an archive into a destination directory.
    Decrypt {
        /// Archive directory to read.
        #[arg(value_name = "ARCHIVE_DIR")]
        archive: PathBuf,

        /// Destination directory.
        #[arg(short = 'o', long = "output", value_name = "DEST")]
        output: PathBuf,

        /// Overwrite files that already exist at the destination.
        #[arg(long)]
        force: bool,

        /// Do not restore Unix mode bits from the manifest.
        #[arg(long)]
        no_restore_modes: bool,
    },

    /// List an archive's contents. Decrypts the manifest only.
    List {
        /// Archive directory to read.
        #[arg(value_name = "ARCHIVE_DIR")]
        archive: PathBuf,
    },

    /// Authenticate every byte of an archive. Writes nothing.
    Verify {
        /// Archive directory to read.
        #[arg(value_name = "ARCHIVE_DIR")]
        archive: PathBuf,
    },

    /// Change an archive's passphrase.
    ///
    /// Rewraps the 32-byte master key and rewrites only the manifest, so this is
    /// fast regardless of archive size. The new passphrase may be supplied via
    /// XCRYPT_NEW_PASSPHRASE.
    Rewrap {
        /// Archive directory to re-key.
        #[arg(value_name = "ARCHIVE_DIR")]
        archive: PathBuf,

        /// Argon2id memory cost for the new wrap. Accepts suffixes.
        #[arg(long, value_name = "SIZE", default_value = "256MiB", value_parser = parse_memory_kib)]
        argon2_mem: u32,

        /// Argon2id iteration count for the new wrap.
        #[arg(long, value_name = "N", default_value_t = 3)]
        argon2_time: u32,

        /// Argon2id parallelism for the new wrap.
        #[arg(long, value_name = "N", default_value_t = 4)]
        argon2_lanes: u32,
    },
}

/// Parse a byte size with an optional binary suffix.
fn parse_bytes(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    let (digits, multiplier) = match trimmed {
        s if s.ends_with("GiB") || s.ends_with("G") => (strip_suffix(s), 1024 * 1024 * 1024),
        s if s.ends_with("MiB") || s.ends_with("M") => (strip_suffix(s), 1024 * 1024),
        s if s.ends_with("KiB") || s.ends_with("K") => (strip_suffix(s), 1024),
        s if s.ends_with("B") => (strip_suffix(s), 1),
        s => (s, 1),
    };

    digits
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{input:?} is not a byte size (try 64KiB, 256MiB, 1GiB)"))?
        .checked_mul(multiplier)
        .ok_or_else(|| format!("{input:?} overflows"))
}

fn strip_suffix(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_ascii_alphabetic())
}

/// Chunk size, validated against the format's own limits so a bad value fails at
/// the command line rather than halfway through a large archive.
fn parse_chunk_size(input: &str) -> Result<u32, String> {
    let bytes = parse_bytes(input)?;
    let size = u32::try_from(bytes).map_err(|_| format!("{input:?} is too large"))?;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) {
        return Err(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        ));
    }
    Ok(size)
}

/// Argon2 memory cost, expressed in KiB as the algorithm wants it.
fn parse_memory_kib(input: &str) -> Result<u32, String> {
    let bytes = parse_bytes(input)?;
    let kib = bytes / 1024;
    u32::try_from(kib).map_err(|_| format!("{input:?} is too much memory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes_parse() {
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_bytes("64KiB").unwrap(), 65536);
        assert_eq!(parse_bytes("64K").unwrap(), 65536);
        assert_eq!(parse_bytes("256MiB").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes(" 8 MiB ").unwrap(), 8 * 1024 * 1024);
        assert!(parse_bytes("banana").is_err());
        assert!(parse_bytes("-1").is_err());
    }

    #[test]
    fn chunk_sizes_are_range_checked_at_the_command_line() {
        assert_eq!(parse_chunk_size("64KiB").unwrap(), 65536);
        assert!(parse_chunk_size("64").is_err(), "below the minimum");
        assert!(parse_chunk_size("64MiB").is_err(), "above the maximum");
    }

    #[test]
    fn memory_costs_convert_to_kib() {
        assert_eq!(parse_memory_kib("256MiB").unwrap(), 256 * 1024);
        assert_eq!(parse_memory_kib("19MiB").unwrap(), 19 * 1024);
    }

    /// clap's own consistency checks: duplicate flags, bad defaults, and so on.
    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
