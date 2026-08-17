//! End-to-end tests that drive the real binary as a subprocess.
//!
//! These assert the contract a user or a script sees: exit codes, what lands on
//! stdout versus stderr, the JSON shape, and the absence of a `--passphrase`
//! flag.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Cheap KDF cost, still above the 19 MiB policy floor so the default policy
/// accepts it. Anything smaller would be refused, which is the point of the floor.
const CHEAP_MEM: &str = "19MiB";

fn xcrypt(args: &[&str], passphrase: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xcrypt"));
    command.args(args);
    match passphrase {
        Some(value) => command.env("XCRYPT_PASSPHRASE", value),
        None => command.env_remove("XCRYPT_PASSPHRASE"),
    };
    command.output().expect("failed to run the xcrypt binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn write(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    vault: PathBuf,
    dest: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("src");
    write(&source.join("notes.txt"), b"plain notes");
    write(&source.join("nested/data.bin"), &vec![42u8; 100_000]);
    write(&source.join("empty.txt"), b"");
    Fixture {
        source,
        vault: dir.path().join("vault"),
        dest: dir.path().join("out"),
        _dir: dir,
    }
}

fn encrypt(fx: &Fixture, passphrase: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "encrypt",
        fx.source.to_str().unwrap(),
        "-o",
        fx.vault.to_str().unwrap(),
        "--argon2-mem",
        CHEAP_MEM,
    ];
    args.extend_from_slice(extra);
    xcrypt(&args, Some(passphrase))
}

#[test]
fn full_roundtrip_through_the_binary() {
    let fx = fixture();

    let out = encrypt(&fx, "cli passphrase", &[]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("Encrypted 3 files"));

    let out = xcrypt(
        &[
            "decrypt",
            fx.vault.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
        ],
        Some("cli passphrase"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    assert_eq!(
        std::fs::read(fx.dest.join("src/notes.txt")).unwrap(),
        b"plain notes"
    );
    assert_eq!(
        std::fs::read(fx.dest.join("src/nested/data.bin")).unwrap(),
        vec![42u8; 100_000]
    );
    assert!(std::fs::read(fx.dest.join("src/empty.txt"))
        .unwrap()
        .is_empty());
}

#[test]
fn a_wrong_passphrase_exits_one_and_says_why() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "right", &[])), 0);

    let out = xcrypt(
        &[
            "decrypt",
            fx.vault.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
        ],
        Some("wrong"),
    );
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("passphrase"), "{}", stderr(&out));
    assert!(
        !fx.dest.join("src/notes.txt").exists(),
        "wrote plaintext anyway"
    );
}

#[test]
fn json_mode_emits_one_object_on_stdout() {
    let fx = fixture();
    let out = encrypt(&fx, "pw", &["--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let value: serde_json::Value =
        serde_json::from_str(stdout(&out).trim()).expect("stdout must be exactly one JSON object");
    assert_eq!(value["command"], "encrypt");
    assert_eq!(value["files"], 3);
    assert!(value["bytes"].as_u64().unwrap() > 100_000);

    let out = xcrypt(&["list", fx.vault.to_str().unwrap(), "--json"], Some("pw"));
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    let entries = value["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["path"] == "src/notes.txt"));
    assert!(entries
        .iter()
        .any(|e| e["kind"] == "directory" && e["path"] == "src/nested"));
}

#[test]
fn json_mode_reports_errors_as_json_on_stdout() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "right", &[])), 0);

    let out = xcrypt(
        &[
            "decrypt",
            fx.vault.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
            "--json",
        ],
        Some("wrong"),
    );
    assert_eq!(code(&out), 1);

    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim())
        .expect("a failure must still produce parseable JSON on stdout");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["kind"], "no_matching_recipient");
}

#[test]
fn verify_detects_tampering_and_exits_one() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "pw", &[])), 0);

    let out = xcrypt(&["verify", fx.vault.to_str().unwrap()], Some("pw"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // Flip a bit in the largest object.
    let objects = fx.vault.join("objects");
    let biggest = std::fs::read_dir(&objects)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max_by_key(|p| std::fs::metadata(p).unwrap().len())
        .unwrap();
    let mut bytes = std::fs::read(&biggest).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&biggest, &bytes).unwrap();

    let out = xcrypt(
        &["verify", fx.vault.to_str().unwrap(), "--json"],
        Some("pw"),
    );
    assert_eq!(code(&out), 1);
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["error"]["kind"], "chunk_auth_failed");
}

#[test]
fn existing_outputs_are_not_clobbered_without_force() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "pw", &[])), 0);

    let out = encrypt(&fx, "pw", &["--json"]);
    assert_eq!(code(&out), 1);
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["error"]["kind"], "would_overwrite");

    assert_eq!(code(&encrypt(&fx, "pw", &["--force"])), 0);
}

#[test]
fn rewrap_changes_the_passphrase() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "old pw", &[])), 0);

    let out = Command::new(env!("CARGO_BIN_EXE_xcrypt"))
        .args([
            "rewrap",
            fx.vault.to_str().unwrap(),
            "--argon2-mem",
            CHEAP_MEM,
        ])
        .env("XCRYPT_PASSPHRASE", "old pw")
        .env("XCRYPT_NEW_PASSPHRASE", "new pw")
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    assert_eq!(
        code(&xcrypt(
            &["list", fx.vault.to_str().unwrap()],
            Some("old pw")
        )),
        1,
        "the old passphrase still works"
    );
    assert_eq!(
        code(&xcrypt(
            &["list", fx.vault.to_str().unwrap()],
            Some("new pw")
        )),
        0
    );
}

/// The passphrase must never be accepted as an argument: `ps` and shell history
/// would capture it.
#[test]
fn there_is_no_passphrase_flag() {
    let out = xcrypt(&["encrypt", "--help"], None);
    let help = stdout(&out);
    assert!(!help.contains("--passphrase"), "{help}");
    assert!(!help.contains("--password"), "{help}");

    let fx = fixture();
    let out = xcrypt(
        &[
            "encrypt",
            fx.source.to_str().unwrap(),
            "-o",
            fx.vault.to_str().unwrap(),
            "--passphrase",
            "hunter2",
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 2, "an unknown flag must be a usage error");
}

#[test]
fn bad_arguments_are_usage_errors() {
    // Missing required output.
    assert_eq!(code(&xcrypt(&["encrypt", "somewhere"], Some("pw"))), 2);
    // Chunk size below the format minimum, caught before any prompt.
    let fx = fixture();
    let out = encrypt(&fx, "pw", &["--chunk-size", "64"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("chunk size"), "{}", stderr(&out));
}

/// An Argon2 cost below the policy floor is refused *before* the passphrase
/// prompt, so a user is never asked to type one twice for nothing.
#[test]
fn a_weak_argon2_cost_is_refused_up_front() {
    let fx = fixture();
    // Built without the helper: it supplies its own --argon2-mem, and clap
    // rejects the flag twice.
    let out = xcrypt(
        &[
            "encrypt",
            fx.source.to_str().unwrap(),
            "-o",
            fx.vault.to_str().unwrap(),
            "--argon2-mem",
            "1MiB",
            "--json",
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["error"]["kind"], "kdf_params_rejected");
}

#[test]
fn padding_mode_roundtrips_through_the_binary() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "pw", &["--pad-names"])), 0);

    let out = xcrypt(
        &[
            "decrypt",
            fx.vault.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        std::fs::read(fx.dest.join("src/notes.txt")).unwrap(),
        b"plain notes"
    );
    assert!(std::fs::read(fx.dest.join("src/empty.txt"))
        .unwrap()
        .is_empty());
}

#[test]
fn pack_and_unpack_round_trip_through_the_binary() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "pw", &[])), 0);

    let packed = fx.vault.parent().unwrap().join("bundle.xcra");
    let out = xcrypt(
        &[
            "pack",
            fx.vault.to_str().unwrap(),
            "-o",
            packed.to_str().unwrap(),
            "--json",
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["command"], "pack");
    assert_eq!(value["objects"], 3);
    assert!(packed.is_file(), "pack produced a single file");

    // A packed archive is one file, not a directory.
    assert!(!packed.is_dir());

    let restored_vault = fx.vault.parent().unwrap().join("restored-vault");
    let out = xcrypt(
        &[
            "unpack",
            packed.to_str().unwrap(),
            "-o",
            restored_vault.to_str().unwrap(),
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("Unpacked 3 objects"));

    // And the unpacked archive behaves exactly like the original.
    assert_eq!(
        code(&xcrypt(
            &["verify", restored_vault.to_str().unwrap()],
            Some("pw")
        )),
        0
    );

    let out = xcrypt(
        &[
            "decrypt",
            restored_vault.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        std::fs::read(fx.dest.join("src/notes.txt")).unwrap(),
        b"plain notes"
    );
    assert_eq!(
        std::fs::read(fx.dest.join("src/nested/data.bin")).unwrap(),
        vec![42u8; 100_000]
    );
}

#[test]
fn unpacking_a_corrupt_bundle_exits_one_and_leaves_nothing() {
    let fx = fixture();
    assert_eq!(code(&encrypt(&fx, "pw", &[])), 0);

    let packed = fx.vault.parent().unwrap().join("bundle.xcra");
    assert_eq!(
        code(&xcrypt(
            &[
                "pack",
                fx.vault.to_str().unwrap(),
                "-o",
                packed.to_str().unwrap()
            ],
            Some("pw")
        )),
        0
    );

    let mut bytes = std::fs::read(&packed).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    std::fs::write(&packed, &bytes).unwrap();

    let restored = fx.vault.parent().unwrap().join("restored-vault");
    let out = xcrypt(
        &[
            "unpack",
            packed.to_str().unwrap(),
            "-o",
            restored.to_str().unwrap(),
            "--json",
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 1);
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["error"]["kind"], "chunk_auth_failed");
    assert!(!restored.exists());
}

#[test]
fn quiet_mode_keeps_stdout_clean_of_progress() {
    let fx = fixture();
    let out = encrypt(&fx, "pw", &["--quiet"]);
    assert_eq!(code(&out), 0);
    // The summary is on stdout; nothing resembling a progress bar is.
    assert!(!stdout(&out).contains('\r'));
}

#[test]
fn encrypt_with_pack_writes_one_file_and_no_directory() {
    let fx = fixture();
    let packed = fx.vault.parent().unwrap().join("vault.xcra");

    let out = xcrypt(
        &[
            "encrypt",
            fx.source.to_str().unwrap(),
            "-o",
            packed.to_str().unwrap(),
            "--pack",
            "--argon2-mem",
            CHEAP_MEM,
            "--json",
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["packed"], true);
    assert_eq!(value["files"], 3);
    assert_eq!(value["objects"], 3);

    assert!(packed.is_file(), "--pack must produce a single file");
    assert!(!fx.vault.exists(), "no archive directory should remain");

    // And it restores.
    let restored = fx.vault.parent().unwrap().join("restored-vault");
    assert_eq!(
        code(&xcrypt(
            &[
                "unpack",
                packed.to_str().unwrap(),
                "-o",
                restored.to_str().unwrap()
            ],
            Some("pw")
        )),
        0
    );
    let out = xcrypt(
        &[
            "decrypt",
            restored.to_str().unwrap(),
            "-o",
            fx.dest.to_str().unwrap(),
        ],
        Some("pw"),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        std::fs::read(fx.dest.join("src/notes.txt")).unwrap(),
        b"plain notes"
    );
}
