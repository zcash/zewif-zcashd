//! Legacy Sapling account synthesis, against the plaintext regtest fixture.
//!
//! The fixture wallet holds one legacy Sapling spending key (see
//! `encrypted_wallet.rs` for its provenance and ground-truth export). The
//! migration must represent it as its own `SaplingExtFvk` account — mirroring
//! zcashd's treatment of each `z_getnewaddress` key as a separate pool of
//! funds — with the key's z-address attached to that account rather than to
//! the synthesized legacy account.

mod common;

use common::require_fixture_dump;
use zewif::{AccountPurpose, AccountViewingKey, BlockHeight, ProtocolAddress};
use zewif_zcashd::{ZcashdParser, migrate_to_zewif};

const PLAINTEXT_FIXTURE: &str = "plaintext-regtest-wallet.dat";

/// The z-address of the fixture's Sapling spending key.
const Z_ADDR: &str =
    "zregtestsapling1l5gx43wk23sg0da5u0xrzacaz0l67ppvhgt26sccnjtfvzev4dj0nyk8qspmrq0lpzn7y82t6ch";

#[test]
fn legacy_sapling_key_becomes_its_own_account() {
    let dump = require_fixture_dump!(PLAINTEXT_FIXTURE);
    let wallet = ZcashdParser::parse_dump(dump, false)
        .expect("plaintext wallet parses")
        .0;
    let zewif = migrate_to_zewif(&wallet, BlockHeight::from_u32(1), None).expect("migrates");

    let accounts = zewif.wallets()[0].accounts();
    let sapling_accounts: Vec<_> = accounts
        .iter()
        .filter(|a| matches!(a.viewing_key(), AccountViewingKey::SaplingExtFvk(_)))
        .collect();
    assert_eq!(sapling_accounts.len(), 1, "one legacy Sapling account");

    let account = sapling_accounts[0];
    assert_eq!(account.name(), "zcashd legacy sapling 0");
    assert_eq!(account.provenance(), Some("zcashd_legacy"));
    assert_eq!(account.purpose(), Some(AccountPurpose::Spending));

    // The fixture's key was derived by post-v4.7.0 zcashd under the legacy
    // path `m/32'/1'/0x7FFFFFFF'/0'` from the mnemonic seed, and the key
    // source records that derivation against the exported seed.
    let Some(zewif::KeySource::Derived(derived)) = account.key_source() else {
        panic!(
            "the fixture's key is seed-derived: {:?}",
            account.key_source()
        );
    };
    assert_eq!(derived.account_index(), 0x7FFF_FFFF);
    assert_eq!(derived.legacy_address_index(), Some(0));

    // The key's z-address is attached to its account, with no Sapling
    // addresses left on the synthesized legacy account.
    let sapling_addrs = |account: &zewif::Account| -> Vec<String> {
        account
            .addresses()
            .iter()
            .filter_map(|a| match a.address() {
                ProtocolAddress::Sapling(s) => Some(s.address().to_string()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(sapling_addrs(account), vec![Z_ADDR.to_string()]);

    let legacy = accounts
        .iter()
        .find(|a| a.name() == "Legacy")
        .expect("the synthesized legacy account is present");
    assert_eq!(
        sapling_addrs(legacy),
        Vec::<String>::new(),
        "the legacy account no longer holds the key's z-address"
    );

    // The account's viewing key is the same extended FVK under which the
    // secret store records the spending key.
    let Some(zewif::Secrets::Plain(store)) = zewif.secrets() else {
        panic!("the fixture wallet exports a plaintext secret store");
    };
    let AccountViewingKey::SaplingExtFvk(efvk) = account.viewing_key() else {
        unreachable!("filtered above");
    };
    assert_eq!(store.sapling_keys().len(), 1);
    assert_eq!(store.sapling_keys()[0].fvk().encoding(), efvk.encoding());

    // The recorded derivation points at the exported mnemonic seed.
    let mnemonic_entry = store
        .seeds()
        .iter()
        .find(|entry| matches!(entry.material(), zewif::SeedMaterial::Bip39Mnemonic(_)))
        .expect("the mnemonic seed is exported");
    assert_eq!(derived.seed_fingerprint(), mnemonic_entry.fingerprint());

    // The legacy account is exported under ZIP 32 account 0x7FFFFFFF of the
    // mnemonic seed, carrying the full viewing key derived from it: the same
    // UFVK an importer holding the seed would re-derive.
    let AccountViewingKey::Ufvk(legacy_ufvk) = legacy.viewing_key() else {
        panic!(
            "a mnemonic-bearing wallet's legacy account carries a UFVK: {:?}",
            legacy.viewing_key()
        );
    };
    let Some(zewif::KeySource::Derived(legacy_derived)) = legacy.key_source() else {
        panic!(
            "the legacy account is seed-derived: {:?}",
            legacy.key_source()
        );
    };
    assert_eq!(legacy_derived.account_index(), 0x7FFF_FFFF);
    assert_eq!(legacy_derived.legacy_address_index(), None);
    assert_eq!(
        legacy_derived.seed_fingerprint(),
        mnemonic_entry.fingerprint()
    );

    let zewif::SeedMaterial::Bip39Mnemonic(phrase) = mnemonic_entry.material() else {
        unreachable!("filtered above");
    };
    let mnemonic =
        <bip0039::Mnemonic<bip0039::English>>::from_phrase(phrase.mnemonic()).expect("parses");
    // A regtest document exported without an activation schedule encodes
    // unified material as for the test network (same coin type).
    let params = zcash_protocol::consensus::TEST_NETWORK;
    let expected = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &params,
        &mnemonic.to_seed(""),
        zip32::AccountId::try_from(0x7FFF_FFFF).expect("valid account id"),
    )
    .expect("derives")
    .to_unified_full_viewing_key()
    .encode(&params);
    assert_eq!(legacy_ufvk.encoding(), &expected);
}

/// Every transparent address whose key the wallet holds carries its public
/// key — the key's viewing half — so a viewing-only import (which strips the
/// secret store) can register the address for watching.
#[test]
fn transparent_addresses_carry_pubkeys() {
    let dump = require_fixture_dump!(PLAINTEXT_FIXTURE);
    let wallet = ZcashdParser::parse_dump(dump, false)
        .expect("plaintext wallet parses")
        .0;
    let zewif = migrate_to_zewif(&wallet, BlockHeight::from_u32(1), None).expect("migrates");

    // The ground-truth spendable key from `encrypted_wallet.rs`.
    const T_PUBKEY_HEX: &str = "03fbcb678f47782926e8a23e01e7aacd52ae10666c97d5df317274aeb4ae5373db";

    let mut spendable_with_pubkey = 0;
    let mut ground_truth_seen = false;
    for wallet in zewif.wallets() {
        for account in wallet.accounts() {
            for address in account.addresses() {
                if let ProtocolAddress::Transparent(t) = address.address()
                    && t.spend_authority().is_some()
                {
                    let pubkey = t
                        .pubkey()
                        .expect("spendable transparent addresses carry their pubkeys");
                    spendable_with_pubkey += 1;
                    if hex::encode(pubkey.as_slice()) == T_PUBKEY_HEX {
                        ground_truth_seen = true;
                    }
                }
            }
        }
    }
    assert!(spendable_with_pubkey > 0, "spendable addresses are present");
    assert!(
        ground_truth_seen,
        "the known key's pubkey rides on its address"
    );
}
