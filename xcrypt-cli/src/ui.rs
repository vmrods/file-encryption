//! Passphrase prompting and progress reporting.
//!
//! Everything here writes to **stderr**. Stdout carries results only, so
//! `xcrypt list --json | jq` works while a progress bar is still on screen.

use std::path::Path;
use std::sync::Mutex;

use indicatif::{ProgressBar, ProgressStyle};
use xcrypt_core::{Error, Passphrase, Progress, Result};

/// Environment variable holding the passphrase, for non-interactive use.
pub const PASSPHRASE_ENV: &str = "XCRYPT_PASSPHRASE";

/// Environment variable holding the *new* passphrase during `rewrap`.
pub const NEW_PASSPHRASE_ENV: &str = "XCRYPT_NEW_PASSPHRASE";

/// Read a passphrase from the environment or prompt for it.
///
/// `confirm` re-prompts and compares in constant time. The environment path never
/// confirms: a script that sets the variable has already committed to its value.
pub fn read_passphrase(prompt: &str, confirm: bool, env_var: &str) -> Result<Passphrase> {
    if let Some(value) = std::env::var_os(env_var) {
        let text = value.into_string().map_err(|_| {
            Error::io(
                env_var,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "passphrase environment variable is not valid UTF-8",
                ),
            )
        })?;
        return Ok(Passphrase::new(text));
    }

    let first = Passphrase::new(
        rpassword::prompt_password(format!("{prompt}: ")).map_err(|e| Error::io("terminal", e))?,
    );

    if confirm {
        let second = Passphrase::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .map_err(|e| Error::io("terminal", e))?,
        );
        if !first.ct_eq(&second) {
            return Err(Error::io(
                "terminal",
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "passphrases do not match"),
            ));
        }
    }

    Ok(first)
}

/// A progress bar on stderr, plus a place for notes that must not be swallowed
/// by the bar's redraw.
pub struct BarProgress {
    bar: ProgressBar,
    notes: Mutex<Vec<String>>,
}

impl BarProgress {
    /// Create a byte-counting spinner. The total is unknown until the walk
    /// finishes, so this reports throughput rather than a percentage.
    pub fn new(verb: &str) -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner} {msg:<40!} {bytes:>10} at {bytes_per_sec:>11} [{elapsed_precise}]",
            )
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        bar.set_message(verb.to_owned());
        bar.enable_steady_tick(std::time::Duration::from_millis(120));
        Self {
            bar,
            notes: Mutex::new(Vec::new()),
        }
    }

    /// Clear the bar and print any notes that accumulated during the run.
    pub fn finish(&self) {
        self.bar.finish_and_clear();
        if let Ok(notes) = self.notes.lock() {
            for note in notes.iter() {
                eprintln!("xcrypt: {note}");
            }
        }
    }

    /// The notes gathered so far, for inclusion in a summary.
    pub fn notes(&self) -> Vec<String> {
        self.notes.lock().map(|n| n.clone()).unwrap_or_default()
    }
}

impl Progress for BarProgress {
    fn file_started(&self, path: &Path, _size: u64) {
        // Truncation is the template's job; keep the tail, which is the useful end.
        let shown = path.to_string_lossy();
        self.bar.set_message(shown.into_owned());
    }

    fn bytes_advanced(&self, delta: u64) {
        self.bar.inc(delta);
    }

    fn note(&self, message: &str) {
        if let Ok(mut notes) = self.notes.lock() {
            notes.push(message.to_owned());
        }
    }
}

/// A [`Progress`] that only collects notes: used with `--quiet` and `--json`.
#[derive(Default)]
pub struct SilentProgress {
    notes: Mutex<Vec<String>>,
}

impl SilentProgress {
    /// The notes gathered so far.
    pub fn notes(&self) -> Vec<String> {
        self.notes.lock().map(|n| n.clone()).unwrap_or_default()
    }
}

impl Progress for SilentProgress {
    fn note(&self, message: &str) {
        if let Ok(mut notes) = self.notes.lock() {
            notes.push(message.to_owned());
        }
    }
}

/// Either kind of progress sink, chosen at startup.
pub enum Reporter {
    /// Interactive: a live bar on stderr.
    Bar(BarProgress),
    /// Non-interactive: notes only.
    Silent(SilentProgress),
}

impl Reporter {
    /// Pick a reporter based on the flags and whether stderr is a terminal.
    pub fn new(verb: &str, quiet: bool, json: bool) -> Self {
        if quiet || json || !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            Reporter::Silent(SilentProgress::default())
        } else {
            Reporter::Bar(BarProgress::new(verb))
        }
    }

    /// The underlying [`Progress`] to hand to `xcrypt-core`.
    pub fn as_progress(&self) -> &dyn Progress {
        match self {
            Reporter::Bar(bar) => bar,
            Reporter::Silent(silent) => silent,
        }
    }

    /// Tear down any live display.
    pub fn finish(&self) {
        match self {
            Reporter::Bar(bar) => bar.finish(),
            Reporter::Silent(silent) => {
                for note in silent.notes() {
                    eprintln!("xcrypt: {note}");
                }
            }
        }
    }

    /// Notes gathered during the run.
    pub fn notes(&self) -> Vec<String> {
        match self {
            Reporter::Bar(bar) => bar.notes(),
            Reporter::Silent(silent) => silent.notes(),
        }
    }
}
