//! End-to-end tests against a real pre-Sapling `zcashd` regtest wallet.
//!
//! The fixture was produced by zcashd v1.1.1 on a regtest chain (Sprout from
//! genesis, Overwinter activating at height 200). A wallet of that era has no
//! HD seed of any kind — every key is drawn from a pre-generated keypool — and
//! none of the records later zcashd versions require: no `networkinfo`, no
//! `orchard_note_commitment_tree`, and no mnemonic records. It holds 114
//! transparent keys, 2 watch-only scripts, 6 Sprout spending keys (plus 2
//! Sprout viewing-only `vkey` records, which are not migrated), mined
//! coinbase, and Sprout-era transactions.

mod common;

use std::collections::HashSet;

use common::require_fixture_dump;
use zewif::{BlockHeight, KeySource, Network, RegtestParams};
use zewif_zcashd::{
    DBKey, Error, ParseOptions, RegtestActivations, ZcashdDump, ZcashdParser, ZcashdWallet,
    migrate_to_zewif,
};

const FIXTURE: &str = "pre-sapling-regtest-wallet.dat";

/// The chain tip height at the time the fixture wallet was captured.
const EXPORT_HEIGHT: u32 = 349;

/// The wallet's own transparent addresses, as reported by zcashd.
const T_ADDRS: [&str; 4] = [
    "tmFb3XP5HGx5jM7QdWw7v528Hj3iZtJc27L",
    "tmHhos3RyvZgjkeXo5NM3mNumXtxWwUqvNJ",
    "tmKtLidoPHuNMtviNGwB2oo4WAptwNimaFM",
    "tmSmfYTiuqGwe5aN4rgjjPojh6UiGmgoQ1A",
];

fn parse_wallet(dump: &ZcashdDump) -> (ZcashdWallet, HashSet<DBKey>) {
    ZcashdParser::parse_dump_with_options(
        dump,
        ParseOptions::new().fallback_network(Network::Regtest(RegtestParams::default())),
    )
    .expect("pre-Sapling wallet parses")
}

/// A wallet without a `networkinfo` record cannot identify its chain; the
/// caller must supply one, and parsing without it fails explicitly.
#[test]
fn parsing_without_a_fallback_network_is_rejected() {
    let dump = require_fixture_dump!(FIXTURE);

    match ZcashdParser::parse_dump(dump, false) {
        Err(Error::MissingNetworkInfo) => {}
        Ok(_) => panic!("expected MissingNetworkInfo, got a parsed wallet"),
        Err(other) => panic!("expected MissingNetworkInfo, got {other:?}"),
    }
}

#[test]
fn parses_the_seedless_wallet() {
    let dump = require_fixture_dump!(FIXTURE);

    let (wallet, unparsed) = parse_wallet(dump);

    // The parser recognizes every record kind in the fixture except the
    // Sprout viewing-only `vkey` records, which are not migrated.
    assert_eq!(unparsed.len(), 2, "unparsed records");
    assert!(unparsed.iter().all(|key| key.keyname == "vkey"));

    // No HD material of any kind.
    assert!(wallet.legacy_hd_seed().is_none(), "no legacy HD seed");
    assert!(wallet.bip39_mnemonic().is_none(), "no mnemonic");
    assert!(wallet.mnemonic_hd_chain().is_none(), "no mnemonic HD chain");

    // The caller-supplied network stands in for the missing record.
    assert!(matches!(wallet.network(), Network::Regtest(_)));

    // Key material parsed from the pre-v5 record set.
    assert_eq!(wallet.keys().keypairs().count(), 114, "transparent keys");
    assert_eq!(wallet.watch_scripts().len(), 2, "watch-only scripts");
    assert_eq!(
        wallet.sprout_keys().map(|k| k.keypairs().count()),
        Some(6),
        "Sprout spending keys"
    );
    assert!(!wallet.key_pool().is_empty(), "keypool entries");
    assert!(!wallet.transactions().is_empty(), "transactions");
}

/// Migrating the seedless wallet yields exactly one account: the synthesized
/// legacy account, imported (no derivation root), holding the wallet's
/// transparent and watch-only addresses.
#[test]
fn migrates_to_a_single_imported_legacy_account() {
    let dump = require_fixture_dump!(FIXTURE);

    let (wallet, _) = parse_wallet(dump);

    // The fixture chain activated Overwinter at height 200 and nothing later;
    // regtest activation schedules live in node configuration, not the
    // wallet, so the export supplies them.
    let activations = RegtestActivations::Local(zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(zcash_protocol::consensus::BlockHeight::from_u32(200)),
        sapling: None,
        blossom: None,
        heartwood: None,
        canopy: None,
        nu5: None,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        #[cfg(zcash_unstable = "nu7")]
        nu7: None,
    });

    let zewif = migrate_to_zewif(
        &wallet,
        BlockHeight::from_u32(EXPORT_HEIGHT),
        Some(activations),
    )
    .expect("migrates");

    assert_eq!(zewif.wallets().len(), 1);
    let exported = &zewif.wallets()[0];
    assert_eq!(exported.accounts().len(), 1, "only the legacy account");

    let legacy = &exported.accounts()[0];
    assert_eq!(
        legacy.key_source(),
        Some(&KeySource::Imported),
        "a seedless wallet's legacy account has no derivation root"
    );

    let addresses: HashSet<String> = legacy.addresses().iter().map(|a| a.as_string()).collect();
    for addr in T_ADDRS {
        assert!(addresses.contains(addr), "missing address {addr}");
    }

    // The spending keys travel in the secret store.
    let secrets = zewif.secrets().expect("spending wallet exports secrets");
    let zewif::Secrets::Plain(store) = secrets else {
        panic!("expected a plaintext secret store, got {secrets:?}");
    };
    assert_eq!(store.transparent_keys().len(), 114);
    assert_eq!(store.sprout_keys().len(), 6);
    assert!(store.seeds().is_empty(), "no seed to export");
}
