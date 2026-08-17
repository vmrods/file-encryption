//! The key hierarchy: passphrase → KEK → master key → per-container key.
//!
//! ```text
//! passphrase ──Argon2id(salt, m, t, p)──▶ KEK
//!                                          │ unwraps (XChaCha20-Poly1305, AAD = KDF params)
//!                                          ▼
//!                                     master key (32 random bytes)
//!                                          │ HKDF-SHA256(info = file_id ‖ label)
//!                                          ▼
//!                                 per-container content key
//! ```
//!
//! Consequences worth stating plainly:
//!
//! * Changing a passphrase rewraps 32 bytes. No file content is re-encrypted.
//! * Every container has a unique content key, because `file_id` is 16 fresh
//!   random bytes. Nonce reuse across containers is therefore not merely
//!   unlikely, it is structurally impossible even before the random STREAM nonce
//!   prefix is considered.
//! * The wrap is bound to its KDF parameters as AAD, so swapping in cheaper
//!   parameters cannot produce a key that unwraps.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::header::{
    ContainerKind, FileId, KdfAlgorithm, KdfParams, KdfPolicy, Keyring, Recipient, RecipientKind,
    FILE_ID_LEN, SALT_LEN, WRAPPED_KEY_LEN, WRAP_NONCE_LEN,
};

/// Length of every symmetric key in this crate.
pub const KEY_LEN: usize = 32;

/// A 32-byte symmetric key that is zeroized on drop and never printed.
///
/// Used for the KEK, the master key, and per-container content keys alike; the
/// type does not distinguish them, the call sites do.
pub struct Key(Secret<[u8; KEY_LEN]>);

impl Key {
    /// Wrap existing key bytes. The caller's copy should be zeroized; passing by
    /// value here means this type owns the only copy.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Key(Secret::new(bytes))
    }

    /// Generate a fresh key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let key = Key::new(bytes);
        bytes.zeroize();
        key
    }

    /// Borrow the raw bytes. Every call site should be short-lived and must not
    /// copy them into anything that is not itself zeroizing.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Key::new(*self.expose())
    }
}

/// Redacted: key bytes must never reach a log line or a panic message.
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([redacted])")
    }
}

/// A user passphrase, held only as long as needed to derive a KEK.
pub struct Passphrase(Secret<String>);

impl Passphrase {
    /// Take ownership of a passphrase string.
    pub fn new(passphrase: String) -> Self {
        Passphrase(Secret::new(passphrase))
    }

    /// The passphrase bytes, as fed to Argon2id (UTF-8, no normalization —
    /// see `SPEC.md` on why normalization is deliberately not applied).
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }

    /// Constant-time comparison, for confirming a passphrase at the prompt.
    ///
    /// A byte-wise `==` would leak the length of the common prefix through
    /// timing. It barely matters when both values came from the same terminal,
    /// but the habit is cheap and the exception is not worth arguing about.
    pub fn ct_eq(&self, other: &Passphrase) -> bool {
        self.expose_bytes().ct_eq(other.expose_bytes()).into()
    }
}

/// Redacted.
impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase([redacted])")
    }
}

/// Fill a buffer from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// A fresh random container identifier.
pub fn random_file_id() -> FileId {
    random_bytes::<FILE_ID_LEN>()
}

/// Derive the key-encryption key from a passphrase and the header's parameters.
///
/// `policy` is checked first: parameters read from a container are attacker
/// controlled, and a cost downgrade must be refused rather than honored.
pub fn derive_kek(passphrase: &Passphrase, params: &KdfParams, policy: &KdfPolicy) -> Result<Key> {
    policy.check(params)?;
    let KdfAlgorithm::Argon2id = params.algorithm;

    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::KdfParamsRejected {
        detail: format!("argon2 rejected the parameters: {e}"),
    })?;

    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.expose_bytes(), &params.salt, &mut out)
        .map_err(|e| Error::KdfParamsRejected {
            detail: format!("argon2 failed: {e}"),
        })?;

    let key = Key::new(out);
    out.zeroize();
    Ok(key)
}

/// AAD for the master-key wrap: the canonical encoding of the KDF parameters.
///
/// This is what makes a parameter downgrade fail closed even for values that sit
/// inside [`KdfPolicy`]: the wrap simply will not authenticate.
fn wrap_aad(params: &KdfParams) -> Result<Vec<u8>> {
    postcard::to_allocvec(params).map_err(|_| Error::MalformedHeader)
}

/// Wrap `master_key` under `kek`, producing one passphrase recipient.
pub fn wrap_master_key(
    kek: &Key,
    master_key: &Key,
    params: &KdfParams,
    label: Option<String>,
) -> Result<Recipient> {
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let nonce = random_bytes::<WRAP_NONCE_LEN>();
    let aad = wrap_aad(params)?;

    let wrapped = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: master_key.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;
    debug_assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);

    Ok(Recipient {
        kind: RecipientKind::Passphrase,
        label,
        nonce,
        wrapped_master_key: wrapped,
    })
}

/// Build a brand-new keyring around a fresh master key.
///
/// Returns the keyring to embed in the root container's header, and the master
/// key itself for immediate use.
pub fn new_keyring(
    passphrase: &Passphrase,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    policy: &KdfPolicy,
) -> Result<(Keyring, Key)> {
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib,
        t_cost,
        p_cost,
        salt: random_bytes::<SALT_LEN>(),
    };
    policy.check(&params)?;

    let kek = derive_kek(passphrase, &params, policy)?;
    let master_key = Key::random();
    let recipient = wrap_master_key(&kek, &master_key, &params, None)?;

    Ok((
        Keyring {
            kdf: params,
            recipients: vec![recipient],
        },
        master_key,
    ))
}

/// Recover the master key from a keyring using a passphrase.
///
/// Every passphrase recipient is tried in order. The KEK is derived once — the
/// KDF parameters are per-keyring, not per-recipient — so extra recipients cost
/// one AEAD open each, not one Argon2 pass each.
pub fn unwrap_master_key(
    keyring: &Keyring,
    passphrase: &Passphrase,
    policy: &KdfPolicy,
) -> Result<Key> {
    let kek = derive_kek(passphrase, &keyring.kdf, policy)?;
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let aad = wrap_aad(&keyring.kdf)?;

    for recipient in &keyring.recipients {
        let RecipientKind::Passphrase = recipient.kind;
        if recipient.wrapped_master_key.len() != WRAPPED_KEY_LEN {
            continue;
        }
        let opened = cipher.decrypt(
            (&recipient.nonce).into(),
            Payload {
                msg: &recipient.wrapped_master_key,
                aad: &aad,
            },
        );
        if let Ok(mut bytes) = opened {
            let array: [u8; KEY_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::NoMatchingRecipient)?;
            let key = Key::new(array);
            bytes.zeroize();
            return Ok(key);
        }
    }

    Err(Error::NoMatchingRecipient)
}

/// Re-wrap an existing master key under a new passphrase, replacing the keyring.
///
/// The master key is unchanged, so no ciphertext is rewritten — the point of
/// having a master key at all.
pub fn rewrap_keyring(
    master_key: &Key,
    new_passphrase: &Passphrase,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    policy: &KdfPolicy,
) -> Result<Keyring> {
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib,
        t_cost,
        p_cost,
        salt: random_bytes::<SALT_LEN>(),
    };
    policy.check(&params)?;
    let kek = derive_kek(new_passphrase, &params, policy)?;
    let recipient = wrap_master_key(&kek, master_key, &params, None)?;
    Ok(Keyring {
        kdf: params,
        recipients: vec![recipient],
    })
}

/// Derive a container's content key: `HKDF-SHA256(ikm = master, info = file_id ‖ label)`.
///
/// No salt: the master key is already uniformly random, which is exactly the
/// case where HKDF's extract step is unnecessary. Domain separation comes from
/// `info`, whose label differs between file and manifest containers, so a
/// manifest can never be substituted for a file.
pub fn derive_content_key(master_key: &Key, file_id: &FileId, kind: ContainerKind) -> Result<Key> {
    let mut info = Vec::with_capacity(FILE_ID_LEN + 32);
    info.extend_from_slice(file_id);
    info.extend_from_slice(kind.hkdf_label());

    let hkdf = Hkdf::<Sha256>::new(None, master_key.expose());
    let mut out = [0u8; KEY_LEN];
    hkdf.expand(&info, &mut out).map_err(|_| Error::Aead)?;

    let key = Key::new(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> Passphrase {
        Passphrase::new(s.to_owned())
    }

    // Cheap costs: these tests exercise plumbing, not KDF strength.
    const M: u32 = 8;
    const T: u32 = 1;
    const P: u32 = 1;

    fn policy() -> KdfPolicy {
        KdfPolicy::permissive()
    }

    #[test]
    fn keyring_roundtrip() {
        let (keyring, master) = new_keyring(&pass("correct horse"), M, T, P, &policy()).unwrap();
        let recovered = unwrap_master_key(&keyring, &pass("correct horse"), &policy()).unwrap();
        assert_eq!(recovered.expose(), master.expose());
    }

    #[test]
    fn wrong_passphrase_is_distinguishable() {
        let (keyring, _) = new_keyring(&pass("right"), M, T, P, &policy()).unwrap();
        assert!(matches!(
            unwrap_master_key(&keyring, &pass("wrong"), &policy()),
            Err(Error::NoMatchingRecipient)
        ));
    }

    #[test]
    fn empty_and_exotic_passphrases_work() {
        for p in ["", "🔐 ünïcödé ✓", &"x".repeat(4096)] {
            let (keyring, master) = new_keyring(&pass(p), M, T, P, &policy()).unwrap();
            let recovered = unwrap_master_key(&keyring, &pass(p), &policy()).unwrap();
            assert_eq!(recovered.expose(), master.expose());
        }
    }

    #[test]
    fn tampering_with_kdf_params_breaks_the_wrap() {
        let (mut keyring, _) = new_keyring(&pass("pw"), 16, 2, 1, &policy()).unwrap();
        // Stay inside the permissive policy so the failure comes from the AAD
        // binding rather than from the policy check.
        keyring.kdf.t_cost = 1;
        assert!(matches!(
            unwrap_master_key(&keyring, &pass("pw"), &policy()),
            Err(Error::NoMatchingRecipient)
        ));
    }

    #[test]
    fn kdf_downgrade_below_policy_is_rejected_loudly() {
        let (mut keyring, _) = new_keyring(&pass("pw"), 32 * 1024, 3, 1, &policy()).unwrap();
        keyring.kdf.m_cost_kib = 8;
        assert!(matches!(
            unwrap_master_key(&keyring, &pass("pw"), &KdfPolicy::default()),
            Err(Error::KdfParamsRejected { .. })
        ));
    }

    #[test]
    fn multiple_recipients_all_open() {
        let (mut keyring, master) = new_keyring(&pass("first"), M, T, P, &policy()).unwrap();
        // A second recipient under the same KDF parameters, as a hardware token
        // or recovery key would be once those exist.
        let kek2 = derive_kek(&pass("first"), &keyring.kdf, &policy()).unwrap();
        let extra =
            wrap_master_key(&kek2, &master, &keyring.kdf, Some("recovery".to_owned())).unwrap();
        keyring.recipients.push(extra);

        let recovered = unwrap_master_key(&keyring, &pass("first"), &policy()).unwrap();
        assert_eq!(recovered.expose(), master.expose());
    }

    #[test]
    fn rewrap_preserves_master_key() {
        let (keyring, master) = new_keyring(&pass("old"), M, T, P, &policy()).unwrap();
        let rewrapped = rewrap_keyring(&master, &pass("new"), M, T, P, &policy()).unwrap();

        assert!(unwrap_master_key(&rewrapped, &pass("old"), &policy()).is_err());
        let recovered = unwrap_master_key(&rewrapped, &pass("new"), &policy()).unwrap();
        assert_eq!(recovered.expose(), master.expose());
        // The salt must be fresh, or two archives share a KEK derivation.
        assert_ne!(keyring.kdf.salt, rewrapped.kdf.salt);
    }

    #[test]
    fn content_keys_are_domain_separated() {
        let master = Key::random();
        let id = random_file_id();
        let file = derive_content_key(&master, &id, ContainerKind::File).unwrap();
        let manifest = derive_content_key(&master, &id, ContainerKind::Manifest).unwrap();
        assert_ne!(file.expose(), manifest.expose());

        let other = derive_content_key(&master, &random_file_id(), ContainerKind::File).unwrap();
        assert_ne!(file.expose(), other.expose());
    }

    #[test]
    fn content_key_derivation_is_deterministic() {
        let master = Key::random();
        let id = random_file_id();
        let a = derive_content_key(&master, &id, ContainerKind::File).unwrap();
        let b = derive_content_key(&master, &id, ContainerKind::File).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let key = Key::random();
        let hex: String = key.expose().iter().map(|b| format!("{b:02x}")).collect();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "Key([redacted])");
        assert!(!rendered.contains(&hex));

        let p = pass("hunter2");
        assert_eq!(format!("{p:?}"), "Passphrase([redacted])");
    }

    #[test]
    fn passphrase_comparison() {
        assert!(pass("abc").ct_eq(&pass("abc")));
        assert!(!pass("abc").ct_eq(&pass("abd")));
        assert!(!pass("abc").ct_eq(&pass("abcd")));
    }
}
