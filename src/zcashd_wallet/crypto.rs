//! Decryption of `zcashd`-encrypted wallet key material.
//!
//! When a `zcashd` wallet is encrypted with a passphrase, its spending keys and
//! seeds are stored as AES-256-CBC ciphertexts under a random 32-byte *master
//! key*. The master key is itself encrypted (in the `mkey` record) under a key
//! derived from the passphrase by an iterated SHA-512 KDF. This module
//! reproduces `zcashd`'s `CCrypter` (see `src/wallet/crypter.cpp`):
//!
//! - [`decrypt_master_key`] runs the passphrase KDF and decrypts an `mkey`
//!   record to recover the master key.
//! - [`decrypt_secret`] decrypts an individual key/seed ciphertext under the
//!   master key, using a record-specific initialization vector.
//!
//! All recovered secret material is returned in [`Zeroizing`] containers so it
//! is wiped from memory when dropped.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use secrecy::{ExposeSecret, SecretVec};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// AES-256 key length (`WALLET_CRYPTO_KEY_SIZE`).
const KEY_SIZE: usize = 32;
/// AES-CBC initialization-vector length (`WALLET_CRYPTO_IV_SIZE`).
const IV_SIZE: usize = 16;
/// Passphrase-KDF salt length (`WALLET_CRYPTO_SALT_SIZE`).
const SALT_SIZE: usize = 8;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Failure to decrypt `zcashd`-encrypted key material.
#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    /// The `mkey` record uses a key-derivation method this crate does not
    /// implement. Only method `0` (iterated SHA-512) is supported; method `1`
    /// (scrypt) was never used by released `zcashd` versions.
    #[error(
        "unsupported wallet key-derivation method {0} (only SHA-512, method 0, is supported)"
    )]
    UnsupportedDerivationMethod(u32),

    /// The `mkey` derivation parameters are malformed (zero iterations or a
    /// salt that is not {expected} bytes).
    #[error("invalid master-key derivation parameters: {0}")]
    InvalidMasterKeyParams(&'static str),

    /// An initialization-vector source was shorter than 16 bytes.
    #[error("initialization vector source is too short ({0} bytes, need at least 16)")]
    ShortInitializationVector(usize),

    /// AES-CBC decryption or PKCS#7 unpadding failed. For the `mkey` record
    /// this almost always means the supplied passphrase was wrong; for an
    /// individual secret it means the ciphertext is corrupt.
    #[error("decryption failed (wrong passphrase or corrupt ciphertext)")]
    Decrypt,

    /// A decrypted master key was not exactly 32 bytes, indicating a wrong
    /// passphrase whose bad plaintext happened to carry valid padding.
    #[error("decrypted master key has wrong length ({0} bytes, expected 32)")]
    MasterKeyLength(usize),
}

/// The master-key derivation parameters and ciphertext from a `zcashd` `mkey`
/// record (`CMasterKey`).
#[derive(Clone, Debug)]
pub struct MasterKeyParams {
    /// The AES-256-CBC ciphertext of the 32-byte master key (`vchCryptedKey`).
    pub encrypted_key: Vec<u8>,
    /// The passphrase-KDF salt (`vchSalt`, 8 bytes).
    pub salt: Vec<u8>,
    /// The key-derivation method (`nDerivationMethod`); 0 == iterated SHA-512.
    pub derivation_method: u32,
    /// The number of SHA-512 iterations (`nDeriveIterations`).
    pub derive_iterations: u32,
}

/// Derive the wallet master key from a passphrase and an `mkey` record.
///
/// Reproduces `CCrypter::SetKeyFromPassphrase` followed by decryption of
/// `CMasterKey::vchCryptedKey`: the passphrase and salt are hashed
/// `derive_iterations` times with SHA-512 to produce an AES key and IV, which
/// decrypt the master-key ciphertext.
///
/// Returns [`DecryptionError::Decrypt`] when the passphrase is wrong (the usual
/// case: the derived key produces invalid PKCS#7 padding).
pub fn decrypt_master_key(
    params: &MasterKeyParams,
    passphrase: &SecretVec<u8>,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, DecryptionError> {
    if params.derivation_method != 0 {
        return Err(DecryptionError::UnsupportedDerivationMethod(
            params.derivation_method,
        ));
    }
    if params.derive_iterations < 1 {
        return Err(DecryptionError::InvalidMasterKeyParams(
            "iteration count must be at least 1",
        ));
    }
    if params.salt.len() != SALT_SIZE {
        return Err(DecryptionError::InvalidMasterKeyParams(
            "salt must be 8 bytes",
        ));
    }

    let (key, iv) = bytes_to_key_sha512(&params.salt, passphrase.expose_secret(), params.derive_iterations);
    let plaintext = aes256_cbc_decrypt(&key, &iv, &params.encrypted_key)?;

    if plaintext.len() != KEY_SIZE {
        return Err(DecryptionError::MasterKeyLength(plaintext.len()));
    }
    let mut master_key = Zeroizing::new([0u8; KEY_SIZE]);
    master_key.copy_from_slice(&plaintext);
    Ok(master_key)
}

/// Decrypt a single encrypted secret under the wallet master key.
///
/// Reproduces `zcashd`'s `DecryptSecret`: the AES-256-CBC IV is the first 16
/// bytes of `iv_source`, a record-specific 32-byte value (a public-key hash,
/// address hash, viewing-key fingerprint, or seed fingerprint depending on the
/// record type).
pub fn decrypt_secret(
    master_key: &[u8; KEY_SIZE],
    ciphertext: &[u8],
    iv_source: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
    if iv_source.len() < IV_SIZE {
        return Err(DecryptionError::ShortInitializationVector(iv_source.len()));
    }
    aes256_cbc_decrypt(master_key, &iv_source[..IV_SIZE], ciphertext)
}

/// Derive an AES-256 key and IV from a passphrase and salt via `count`
/// iterations of SHA-512 (`CCrypter::BytesToKeySHA512AES`).
///
/// This mirrors OpenSSL's `EVP_BytesToKey` with an AES-256-CBC cipher and a
/// SHA-512 digest: because SHA-512's 64-byte output already covers the 32-byte
/// key plus the 16-byte IV, only a single hash chain (`D_0`) is needed.
fn bytes_to_key_sha512(
    salt: &[u8],
    passphrase: &[u8],
    count: u32,
) -> (Zeroizing<[u8; KEY_SIZE]>, [u8; IV_SIZE]) {
    let mut buf = Zeroizing::new([0u8; 64]);
    let mut hasher = Sha512::new();
    hasher.update(passphrase);
    hasher.update(salt);
    buf.copy_from_slice(hasher.finalize().as_slice());

    for _ in 0..count.saturating_sub(1) {
        let mut hasher = Sha512::new();
        hasher.update(&buf[..]);
        buf.copy_from_slice(hasher.finalize().as_slice());
    }

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&buf[..KEY_SIZE]);
    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&buf[KEY_SIZE..KEY_SIZE + IV_SIZE]);
    (key, iv)
}

/// AES-256-CBC decryption with PKCS#7 padding.
fn aes256_cbc_decrypt(
    key: &[u8; KEY_SIZE],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
    // CBC requires a non-empty, block-aligned ciphertext.
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(IV_SIZE) {
        return Err(DecryptionError::Decrypt);
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::Decrypt)?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| DecryptionError::Decrypt)?
        .len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors generated independently of this crate, using Python's
    // hashlib (SHA-512) and the `cryptography` package (OpenSSL AES-256-CBC),
    // reimplementing the algorithm defined in zcashd's crypter.cpp. See
    // `scratchpad/gen_vectors.py`.
    const PASSPHRASE: &[u8] = b"test pass phrase 123";
    const SALT: [u8; 8] = hex_lit("0102030405060708");
    const ITERATIONS: u32 = 1000;
    const KDF_KEY: [u8; 32] =
        hex_lit("84476d12831a7a2229490bca12be636b8cfc61e688a8ada6c31e98177cdf3645");
    const KDF_IV: [u8; 16] = hex_lit("0d0edb4c40db02c71134701ce2c7f170");
    const MASTER_KEY: [u8; 32] =
        hex_lit("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // AES-256-CBC(kdf_key, kdf_iv) of MASTER_KEY.
    const CRYPTED_MASTER: [u8; 48] = hex_lit(
        "f9d8003af2b0944d8a54dd6cf93b41b673eb7cd71aca5633c33bd3ab8e88b7b6\
         aba8cdb7e8a116489f9c0eb7316d3f92",
    );
    const SECRET_PLAINTEXT: [u8; 32] =
        hex_lit("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const IV_SOURCE32: [u8; 32] =
        hex_lit("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    // AES-256-CBC(master_key, iv_source32[..16]) of SECRET_PLAINTEXT.
    const CRYPTED_SECRET: [u8; 48] = hex_lit(
        "86830e87591a75e9145ec6a106a30b2f0bce04647200ad5a2441c6c3287baabe\
         e292c7aa4990cbad84a96d55b7a6aebc",
    );

    /// Compile-time hex decoder for fixed-size test vectors.
    const fn hex_lit<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        let mut out = [0u8; N];
        let mut i = 0; // index into `bytes`
        let mut o = 0; // index into `out`
        while o < N {
            // Skip any non-hex byte (whitespace, backslash line continuations).
            while !is_hex(bytes[i]) {
                i += 1;
            }
            let hi = hex_val(bytes[i]);
            let lo = hex_val(bytes[i + 1]);
            out[o] = (hi << 4) | lo;
            i += 2;
            o += 1;
        }
        out
    }

    const fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    const fn hex_val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        }
    }

    fn passphrase() -> SecretVec<u8> {
        SecretVec::new(PASSPHRASE.to_vec())
    }

    #[test]
    fn kdf_matches_independent_vector() {
        let (key, iv) = bytes_to_key_sha512(&SALT, PASSPHRASE, ITERATIONS);
        assert_eq!(&key[..], &KDF_KEY[..]);
        assert_eq!(iv, KDF_IV);
    }

    #[test]
    fn decrypts_master_key_with_correct_passphrase() {
        let params = MasterKeyParams {
            encrypted_key: CRYPTED_MASTER.to_vec(),
            salt: SALT.to_vec(),
            derivation_method: 0,
            derive_iterations: ITERATIONS,
        };
        let master = decrypt_master_key(&params, &passphrase()).expect("decrypts");
        assert_eq!(&master[..], &MASTER_KEY[..]);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let params = MasterKeyParams {
            encrypted_key: CRYPTED_MASTER.to_vec(),
            salt: SALT.to_vec(),
            derivation_method: 0,
            derive_iterations: ITERATIONS,
        };
        let wrong = SecretVec::new(b"not the passphrase".to_vec());
        assert!(matches!(
            decrypt_master_key(&params, &wrong),
            Err(DecryptionError::Decrypt | DecryptionError::MasterKeyLength(_))
        ));
    }

    #[test]
    fn scrypt_derivation_method_is_unsupported() {
        let params = MasterKeyParams {
            encrypted_key: CRYPTED_MASTER.to_vec(),
            salt: SALT.to_vec(),
            derivation_method: 1,
            derive_iterations: ITERATIONS,
        };
        assert!(matches!(
            decrypt_master_key(&params, &passphrase()),
            Err(DecryptionError::UnsupportedDerivationMethod(1))
        ));
    }

    #[test]
    fn decrypts_secret_with_master_key() {
        let plaintext = decrypt_secret(&MASTER_KEY, &CRYPTED_SECRET, &IV_SOURCE32).expect("decrypts");
        assert_eq!(plaintext.as_slice(), &SECRET_PLAINTEXT);
    }

    #[test]
    fn secret_decryption_only_uses_first_16_iv_bytes() {
        // Corrupting the IV source beyond byte 16 must not change the result,
        // since zcashd uses only the first 16 bytes as the AES IV.
        let mut iv_source = IV_SOURCE32;
        iv_source[16..].fill(0xff);
        let plaintext = decrypt_secret(&MASTER_KEY, &CRYPTED_SECRET, &iv_source).expect("decrypts");
        assert_eq!(plaintext.as_slice(), &SECRET_PLAINTEXT);
    }

    #[test]
    fn short_iv_source_is_rejected() {
        assert!(matches!(
            decrypt_secret(&MASTER_KEY, &CRYPTED_SECRET, &[0u8; 15]),
            Err(DecryptionError::ShortInitializationVector(15))
        ));
    }
}
