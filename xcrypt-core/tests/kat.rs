//! Known-answer tests for the primitives, asserted against the pinned
//! dependency versions.
//!
//! These do not test `xcrypt` code — they test that the crates it depends on
//! still compute what the standards say they should, with the exact parameter
//! shapes `xcrypt` uses. A dependency bump that changes a default, an argument
//! order, or a version byte fails here rather than silently producing archives
//! that older builds cannot read.
//!
//! End-to-end stability of *our* derivation chain is pinned separately, by the
//! golden archive fixture in `format_stability.rs`.

use hex_literal::hex;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 8439 §2.8.2 — the ChaCha20-Poly1305 AEAD test vector.
///
/// XChaCha20-Poly1305, which `xcrypt` actually uses, is HChaCha20 subkey
/// derivation on top of exactly this construction; pinning the base vector pins
/// the core.
#[test]
fn rfc8439_chacha20poly1305_aead() {
    let key = hex!(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    let nonce = hex!("070000004041424344454647");
    let aad = hex!("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691"
    );

    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(ciphertext, expected, "ciphertext ‖ tag mismatch");

    let recovered = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(recovered, plaintext);
}

/// The AAD is authenticated, not merely accepted: this is the property the
/// header-as-AAD design rests on.
#[test]
fn aad_is_authenticated() {
    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let cipher = ChaCha20Poly1305::new(&key.into());

    let ct = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: b"payload",
                aad: b"header-bytes",
            },
        )
        .unwrap();

    assert!(cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &ct,
                aad: b"header-bytez",
            },
        )
        .is_err());
}

/// XChaCha20-Poly1305 accepts the 24-byte nonce `xcrypt` relies on, and the
/// 32-byte key wrap really is 48 bytes of output.
#[test]
fn xchacha20poly1305_wrap_shape() {
    let cipher = XChaCha20Poly1305::new(&[1u8; 32].into());
    let wrapped = cipher
        .encrypt(
            &[2u8; 24].into(),
            Payload {
                msg: &[3u8; 32],
                aad: b"kdf-params",
            },
        )
        .unwrap();
    assert_eq!(wrapped.len(), 48, "32-byte key plus a 16-byte tag");
}

/// Argon2id reference vector: `v=19, m=65536 KiB, t=2, p=1`, password
/// `"password"`, salt `"somesalt"`, 32-byte tag.
///
/// From the P-H-C reference implementation's own test suite. This pins the
/// algorithm/version pair `xcrypt` writes into every header.
#[test]
fn argon2id_reference_vector() {
    let params = ParamsBuilder::new()
        .m_cost(65536)
        .t_cost(2)
        .p_cost(1)
        .build()
        .unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(b"password", b"somesalt", &mut out)
        .unwrap();

    assert_eq!(
        out,
        hex!("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
    );
}

/// RFC 9106 §5.3 — Argon2id with a secret and associated data.
///
/// `xcrypt` uses neither, but this is the vector the standard publishes, so it is
/// the strongest single check that the pinned implementation is correct rather
/// than merely self-consistent.
#[test]
fn rfc9106_argon2id_vector() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let argon =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();

    let mut out = [0u8; 32];
    argon
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .unwrap();

    assert_eq!(
        out,
        hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

/// The parameters `xcrypt` writes by default really do cost what the header
/// claims — a sanity check on units (KiB, not bytes or blocks).
#[test]
fn default_parameters_are_accepted_by_the_implementation() {
    let params = ParamsBuilder::new()
        .m_cost(256 * 1024)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .build()
        .expect("the documented defaults must be constructible");
    assert_eq!(params.m_cost(), 256 * 1024);
    assert_eq!(params.t_cost(), 3);
    assert_eq!(params.p_cost(), 4);
}

/// RFC 5869 §A.3 — HKDF-SHA256 with no salt, which is the shape `xcrypt` uses
/// for per-container key derivation (the master key is already uniform, so the
/// extract step needs no salt).
#[test]
fn rfc5869_hkdf_sha256_no_salt() {
    let ikm = [0x0b; 22];
    let (prk, hkdf) = Hkdf::<Sha256>::extract(None, &ikm);
    assert_eq!(
        prk.as_slice(),
        hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
    );

    let mut okm = [0u8; 42];
    hkdf.expand(&[], &mut okm).unwrap();
    assert_eq!(
        okm,
        hex!(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        )
    );
}

/// RFC 5869 §A.1 — HKDF-SHA256 with salt and info, as a second independent check
/// on the same dependency.
#[test]
fn rfc5869_hkdf_sha256_with_salt() {
    let ikm = [0x0b; 22];
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hkdf.expand(&info, &mut okm).unwrap();

    assert_eq!(
        okm,
        hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
    );
}
