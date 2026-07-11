//! End-to-end decryption tests against a matched pair of real `zcashd` regtest
//! wallets.
//!
//! Both fixtures were produced from the *same* throwaway regtest wallet:
//! `plaintext-regtest-wallet.dat` is a copy taken just before running
//! `encryptwallet "test-passphrase-42"`, and `encrypted-regtest-wallet.dat` is
//! the result. `zcashd`'s `EncryptWallet` encrypts the existing keys in place
//! without regenerating them, so the two files hold identical key material —
//! which lets us assert that decrypting the encrypted wallet reproduces the
//! plaintext wallet's export exactly (`encrypted_export_matches_plaintext_export`).
//!
//! The ground-truth keys were also exported from the wallet (via `dumpprivkey`
//! / `z_exportkey`) before encryption, giving an independent (zcashd-side)
//! oracle for the two spending keys checked below.

use std::path::PathBuf;

use zewif::BlockHeight;
use zewif_zcashd::{
    BDBDump, Error, SecretVec, ZcashdDump, ZcashdParser, ZcashdWallet, migrate_to_zewif,
};

const PASSPHRASE: &str = "test-passphrase-42";

// Ground truth captured from zcashd before encryption:
const T_PUBKEY_HEX: &str = "03fbcb678f47782926e8a23e01e7aacd52ae10666c97d5df317274aeb4ae5373db";
// The secp256k1 scalar of WIF cPpVqgGvUHHGCPX8pDGoBTAtnrcU9QahtUitVmyphP2u1eDc3bjn.
const T_SCALAR_HEX: &str = "42c5ae019ceae4e57ae3013d1c72855af3ef950179178715537f0c37dc2b3c6f";
// The 169-byte serialization of the Sapling extended spending key for
// zregtestsapling1l5gx43wk23sg0da5u0xrzacaz0l67ppvhgt26sccnjtfvzev4dj0nyk8qspmrq0lpzn7y82t6ch.
const Z_EXTSK_HEX: &str = "0494d0622e0000008095ce657732206728f9e413c1c87770dd83f187043c418d4c9ccbb5be14bf65b986ee8f9ab4eb591c88e8e148eaad09aaabeccc4a8a2a89d231cb00fb7d80710bcb61db3e4c7e6f4938fd2c191394942ac183aff21d08e81bceba874c2ba2450b0035322cbe40c65341cca4e7149913895d73ddb7fa8b72a13dee1722cd27e0918621346cd256cebbd5ac01431ab45591da04bddbc9276cb867a9e9a96a83ecbc";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn dump(name: &str) -> ZcashdDump {
    let bdb = BDBDump::from_file(&fixture(name)).expect("db_dump the fixture");
    ZcashdDump::from_bdb_dump(&bdb, false).expect("collect records")
}

/// Parse the encrypted fixture, optionally with a passphrase.
fn parse_encrypted(passphrase: Option<&str>) -> Result<ZcashdWallet, Error> {
    let key = passphrase.map(|p| SecretVec::new(p.as_bytes().to_vec()));
    ZcashdParser::parse_dump_with_key(&dump("encrypted-regtest-wallet.dat"), false, key)
        .map(|(wallet, _)| wallet)
}

fn parse_plaintext() -> ZcashdWallet {
    ZcashdParser::parse_dump(&dump("plaintext-regtest-wallet.dat"), false)
        .expect("plaintext wallet parses")
        .0
}

#[test]
fn decrypts_transparent_key_to_ground_truth() {
    let wallet = parse_encrypted(Some(PASSPHRASE)).expect("decrypts with correct passphrase");

    let target = hex::decode(T_PUBKEY_HEX).unwrap();
    let keypair = wallet
        .keys()
        .keypairs()
        .find(|kp| kp.pubkey().as_slice() == target.as_slice())
        .expect("the known public key is present");

    let scalar = keypair.privkey().secp256k1_scalar().expect("scalar");
    assert_eq!(
        hex::encode(scalar),
        T_SCALAR_HEX,
        "decrypted transparent scalar must match the pre-encryption WIF"
    );
}

#[test]
fn decrypts_sapling_key_to_ground_truth() {
    let wallet = parse_encrypted(Some(PASSPHRASE)).expect("decrypts with correct passphrase");

    let sapling_keys: Vec<_> = wallet.sapling_keys().keypairs().collect();
    assert_eq!(sapling_keys.len(), 1, "one legacy Sapling key");

    let extsk_bytes = sapling_keys[0].extsk().to_bytes();
    assert_eq!(
        hex::encode(extsk_bytes),
        Z_EXTSK_HEX,
        "decrypted Sapling extended spending key must match the exported key"
    );
}

/// The strongest check: decrypting the encrypted wallet and migrating it must
/// produce a byte-for-byte identical ZeWIF document to migrating the plaintext
/// wallet it was encrypted from. This exercises every recovered key, seed,
/// address, and transaction at once, not just the two spot-checked above.
#[test]
fn encrypted_export_matches_plaintext_export() {
    let height = BlockHeight::from_u32(2_000_000);

    let plaintext = migrate_to_zewif(&parse_plaintext(), height, None)
        .expect("migrate plaintext")
        .to_bytes()
        .expect("serialize plaintext export");
    let decrypted = migrate_to_zewif(
        &parse_encrypted(Some(PASSPHRASE)).expect("decrypts"),
        height,
        None,
    )
    .expect("migrate decrypted")
    .to_bytes()
    .expect("serialize decrypted export");

    assert_eq!(
        decrypted, plaintext,
        "the decrypted wallet's export must be identical to the plaintext wallet's export"
    );
}

#[test]
fn recovers_all_transparent_keys() {
    let wallet = parse_encrypted(Some(PASSPHRASE)).expect("decrypts");
    // The plaintext and encrypted wallets carry the same key set.
    assert_eq!(
        wallet.keys().keypairs().count(),
        parse_plaintext().keys().keypairs().count()
    );
}

#[test]
fn wrong_passphrase_is_rejected() {
    match parse_encrypted(Some("the wrong passphrase")) {
        Err(Error::WrongWalletPassphrase) => {}
        other => panic!("expected WrongWalletPassphrase, got {other:?}"),
    }
}

#[test]
fn missing_passphrase_is_reported() {
    match parse_encrypted(None) {
        Err(Error::EncryptedWalletRequiresPassphrase) => {}
        other => panic!("expected EncryptedWalletRequiresPassphrase, got {other:?}"),
    }
}

#[test]
fn migrates_with_a_populated_secret_store() {
    let wallet = parse_encrypted(Some(PASSPHRASE)).expect("decrypts");
    let zewif = migrate_to_zewif(&wallet, BlockHeight::from_u32(1), None).expect("migrates");

    let secrets = zewif
        .secrets()
        .expect("an encrypted wallet exports its secrets");
    let zewif::Secrets::Plain(store) = secrets else {
        panic!("expected a plaintext secret store, got {secrets:?}");
    };
    assert!(
        !store.transparent_keys().is_empty(),
        "transparent spending keys are exported"
    );
    assert!(
        !store.sapling_keys().is_empty(),
        "the Sapling spending key is exported"
    );
}
