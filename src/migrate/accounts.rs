use std::collections::HashMap;

use zcash_keys::keys::{UnifiedFullViewingKey, zcashd::ZcashdHdDerivation};
use zcash_protocol::consensus::{self, NetworkConstants};

use zewif::{
    Account, AccountPurpose, AccountViewingKey, DerivationInfo, DerivedKeySource, KeyScope,
    KeySource, NonHardenedChildIndex, sapling::SaplingIncomingViewingKey,
};

use crate::migrate::MigrateError;
use crate::{
    ZcashdWallet,
    migrate::secrets::{legacy_account_seed, sapling_hrps},
    zcashd_wallet::{UfvkFingerprint, encode_seed_fingerprint},
};

/// The ZIP-32 account index zcashd reserves for its legacy pool of
/// pre-mnemonic / imported keys (`m/32'/coin'/0x7FFFFFFF'`).
pub(crate) const ZCASHD_LEGACY_ACCOUNT: u32 = 0x7FFF_FFFF;

/// The accounts synthesized from a zcashd wallet, together with the routing
/// metadata needed to attach addresses and received outputs to them.
pub(crate) struct WalletAccounts {
    /// The accounts, in stable order: one per unified account (ascending
    /// ZIP-32 account index), then one per legacy Sapling spending key
    /// (ascending by viewing-key encoding), followed by the synthesized
    /// legacy account.
    pub accounts: Vec<Account>,
    /// Maps each unified account's zcashd UFVK fingerprint to its index in
    /// [`Self::accounts`], used to route unified addresses.
    pub ufvk_index: HashMap<UfvkFingerprint, usize>,
    /// For each unified account, its index in [`Self::accounts`] paired with
    /// the parsed UFVK, used to route Orchard received outputs by matching
    /// incoming viewing keys.
    pub unified: Vec<(usize, UnifiedFullViewingKey)>,
    /// For each legacy Sapling account, its index in [`Self::accounts`]
    /// paired with the key's incoming viewing key, used to route legacy
    /// Sapling addresses and received notes.
    pub sapling: Vec<(usize, SaplingIncomingViewingKey)>,
    /// Index of the synthesized legacy account (transparent and Sprout
    /// material, and any Sapling material not attributable to a spending
    /// key).
    pub legacy_index: usize,
}

/// Build the accounts for a zcashd wallet.
///
/// Each zcashd unified account becomes a [`AccountViewingKey::Ufvk`] account,
/// and each legacy Sapling spending key becomes a
/// [`AccountViewingKey::SaplingExtFvk`] account, mirroring zcashd's treatment
/// of each `z_getnewaddress` key as its own pool of funds. Everything else —
/// legacy transparent keys (derived, imported, watch-only) and Sprout keys —
/// is collected into a single synthesized legacy account keyed by
/// [`AccountViewingKey::TransparentAddressSet`], mirroring zcashd's own
/// account-0x7FFFFFFF legacy pool. Sprout addresses within it carry their own
/// protocol addresses; all spending keys live in the secret store.
pub(crate) fn build_accounts(
    wallet: &ZcashdWallet,
    params: &impl consensus::Parameters,
) -> Result<WalletAccounts, MigrateError> {
    let mut accounts = Vec::new();
    let mut ufvk_index = HashMap::new();
    let mut unified = Vec::new();
    let mut sapling = Vec::new();

    let unified_accounts = wallet.unified_accounts();

    // Deterministic order: ascending ZIP-32 account index.
    let mut metas: Vec<(&UfvkFingerprint, _)> = unified_accounts.account_metadata.iter().collect();
    metas.sort_by_key(|(_, m)| m.zip32_account_id());

    for (ufvk_fp, meta) in metas {
        let ufvk = unified_accounts
            .full_viewing_keys
            .get(ufvk_fp)
            .ok_or_else(|| MigrateError::MissingAccountUfvk {
                fingerprint: ufvk_fp.to_hex(),
            })?;

        let encoding = ufvk.encode(params);
        let mut account =
            Account::new(AccountViewingKey::Ufvk(zewif::UnifiedFullViewingKey::new(
                encoding,
            )));
        account.set_name(format!("Account #{}", meta.zip32_account_id()));
        account.set_key_source(KeySource::Derived(DerivedKeySource::new(
            meta.seed_fingerprint().clone(),
            meta.zip32_account_id(),
            None,
        )));
        account.set_provenance("zcashd_mnemonic");
        // zcashd holds spend authority for its mnemonic-derived accounts.
        account.set_purpose(AccountPurpose::Spending);

        let idx = accounts.len();
        ufvk_index.insert(*ufvk_fp, idx);
        unified.push((idx, ufvk.clone()));
        accounts.push(account);
    }

    // Legacy Sapling spending keys: one account per key, mirroring zcashd's
    // treatment of each `z_getnewaddress` key as a separate pool of funds.
    // Each account carries the key's extended full viewing key, so a
    // viewing-only import can represent it; the spending half lives in the
    // secret store.
    //
    // The legacy account's viewing key. zcashd reserves ZIP 32 account
    // 0x7FFFFFFF, derived from the post-v4.7.0 mnemonic seed, as the pool for
    // its legacy material: pre-v4.7.0 transparent addresses derived from
    // system randomness, and post-v4.7.0 `getnewaddress` /` z_getnewaddress`
    // keys derived under that account. Where the mnemonic (or, for a
    // pre-mnemonic wallet, the mnemonic zcashd's upgrade would derive from
    // its legacy HD seed) is recoverable, the account's full viewing key is
    // derived from it here, so that the account imports from that location
    // like any other seed-derived account — including into viewing-only
    // wallets. A wallet with no seed material at all falls back to a bare
    // transparent address set.
    let legacy_account_key = match legacy_account_seed(wallet)? {
        Some((seed, fp)) => {
            use secrecy::ExposeSecret;
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                params,
                seed.expose_secret(),
                zip32::AccountId::try_from(ZCASHD_LEGACY_ACCOUNT)
                    .expect("0x7FFFFFFF is a valid ZIP 32 account identifier"),
            )
            .map_err(MigrateError::LegacyAccountDerivation)?;
            Some((usk.to_unified_full_viewing_key(), fp))
        }
        None => None,
    };

    // Keys that duplicate viewing capability a unified account (or the
    // legacy account) already carries are skipped: zcashd stores a unified
    // account's Sapling receiver key in the Sapling keystore alongside
    // standalone keys, and its metadata does not reliably record the
    // derivation, so such keys are identified by their material — the
    // diversifiable full viewing key — rather than by metadata. Importing one
    // as its own account would collide with the covering account's Sapling
    // component.
    let unified_sapling_dfvks: std::collections::HashSet<[u8; 128]> = unified
        .iter()
        .map(|(_, ufvk)| ufvk)
        .chain(legacy_account_key.iter().map(|(ufvk, _)| ufvk))
        .filter_map(|ufvk| ufvk.sapling().map(|dfvk| dfvk.to_bytes()))
        .collect();
    let (_, extfvk_hrp) = sapling_hrps(wallet.network());
    let network_type = params.network_type();
    let mut legacy_sapling: Vec<(String, KeySource, SaplingIncomingViewingKey)> = wallet
        .sapling_keys()
        .keypairs()
        .filter_map(|key| {
            #[allow(deprecated)]
            let efvk = key.extsk().to_extended_full_viewing_key();
            if unified_sapling_dfvks
                .contains(&efvk.to_diversifiable_full_viewing_key().to_bytes())
            {
                return None;
            }
            let source = sapling_key_source(
                key.metadata().seed_fp(),
                key.metadata().hd_keypath().map(|s| s.as_str()),
                &network_type,
            );
            let encoding = zcash_keys::encoding::encode_extended_full_viewing_key(extfvk_hrp, &efvk);
            Some((encoding, source, *key.ivk()))
        })
        .collect();
    // Deterministic order (the source key map has no stable iteration order),
    // matching the secret store's viewing-key-sorted Sapling entries.
    legacy_sapling.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
    for (i, (encoding, source, ivk)) in legacy_sapling.into_iter().enumerate() {
        let mut account = Account::new(AccountViewingKey::SaplingExtFvk(
            zewif::sapling::SaplingExtendedFullViewingKey::new(encoding),
        ));
        account.set_name(format!("zcashd legacy sapling {i}"));
        account.set_key_source(source);
        account.set_provenance("zcashd_legacy");
        // zcashd holds the extended spending key for every `sapzkey` record.
        account.set_purpose(AccountPurpose::Spending);

        let idx = accounts.len();
        sapling.push((idx, ivk));
        accounts.push(account);
    }

    // The synthesized legacy account: a hybrid pool holding transparent,
    // legacy Sapling, and Sprout addresses (zcashd account 0x7FFFFFFF; see
    // `legacy_account_key` above for its derivation).
    let mut legacy = match &legacy_account_key {
        Some((ufvk, _)) => Account::new(AccountViewingKey::Ufvk(
            zewif::UnifiedFullViewingKey::new(ufvk.encode(params)),
        )),
        None => Account::new(AccountViewingKey::TransparentAddressSet),
    };
    legacy.set_name("Legacy");
    match &legacy_account_key {
        Some((_, seed_fp)) => {
            legacy.set_key_source(KeySource::Derived(DerivedKeySource::new(
                seed_fp.clone(),
                ZCASHD_LEGACY_ACCOUNT,
                None,
            )));
        }
        None => legacy.set_key_source(KeySource::Imported),
    }
    legacy.set_provenance("zcashd_legacy");
    legacy.set_purpose(AccountPurpose::Spending);

    let legacy_index = accounts.len();
    accounts.push(legacy);

    Ok(WalletAccounts {
        accounts,
        ufvk_index,
        unified,
        sapling,
        legacy_index,
    })
}

/// The key source of a legacy Sapling spending key, from its zcashd key
/// metadata.
///
/// A key whose metadata records both a seed fingerprint and a parseable HD
/// keypath is seed-derived: a standard ZIP-32 path (`m/32'/coin'/account'`)
/// yields that account index, and zcashd's post-v4.7.0 legacy path
/// (`m/32'/coin'/0x7FFFFFFF'/i'`) yields the legacy account index with the
/// path's address index. Anything else (an imported key, or metadata this
/// crate cannot interpret) is `Imported`; the spending key itself travels in
/// the secret store either way.
fn sapling_key_source<C: NetworkConstants>(
    seed_fp: Option<&[u8; 32]>,
    hd_keypath: Option<&str>,
    network: &C,
) -> KeySource {
    let derived = seed_fp.zip(hd_keypath).and_then(|(fp, path)| {
        match ZcashdHdDerivation::parse_hd_path(network, path) {
            Ok(ZcashdHdDerivation::Zip32 { account_id }) => Some(DerivedKeySource::new(
                encode_seed_fingerprint(fp),
                u32::from(account_id),
                None,
            )),
            Ok(ZcashdHdDerivation::Post470LegacySapling { address_index }) => {
                Some(DerivedKeySource::new(
                    encode_seed_fingerprint(fp),
                    ZCASHD_LEGACY_ACCOUNT,
                    Some(u32::from(address_index)),
                ))
            }
            Err(_) => None,
        }
    });
    match derived {
        Some(source) => KeySource::Derived(source),
        None => KeySource::Imported,
    }
}

/// The key scope implied by a BIP-44/ZIP-32 change component
/// (0 = external receiving, 1 = internal change, 2 = ephemeral).
pub(crate) fn scope_for_change(change: u32) -> KeyScope {
    match change {
        0 => KeyScope::External,
        1 => KeyScope::Internal,
        2 => KeyScope::Ephemeral,
        _ => KeyScope::External,
    }
}

/// Parse the trailing non-hardened `<change>/<address_index>` components of an
/// HD keypath into [`DerivationInfo`], returning `None` for any path whose
/// last two segments are not both non-hardened integers.
pub(crate) fn derivation_info_from_keypath(keypath: &str) -> Option<DerivationInfo> {
    let mut parts = keypath.rsplit('/');
    let address_index = parts.next()?.parse::<u32>().ok()?;
    let change = parts.next()?.parse::<u32>().ok()?;
    Some(DerivationInfo::new(
        NonHardenedChildIndex::from(change),
        NonHardenedChildIndex::from(address_index),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypath_parses_canonical_bip44_path() {
        let info = derivation_info_from_keypath("m/44'/133'/0'/0/5").unwrap();
        assert_eq!(u32::from(info.change()), 0);
        assert_eq!(u32::from(info.address_index()), 5);
    }

    #[test]
    fn keypath_parses_change_chain() {
        let info = derivation_info_from_keypath("m/44'/133'/0'/1/12").unwrap();
        assert_eq!(u32::from(info.change()), 1);
        assert_eq!(u32::from(info.address_index()), 12);
    }

    #[test]
    fn keypath_rejects_hardened_tail() {
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0'/5'").is_none());
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0/5'").is_none());
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0'/5").is_none());
    }

    #[test]
    fn keypath_rejects_too_few_components() {
        assert!(derivation_info_from_keypath("").is_none());
        assert!(derivation_info_from_keypath("5").is_none());
    }

    #[test]
    fn scope_maps_change_component() {
        assert_eq!(scope_for_change(0), KeyScope::External);
        assert_eq!(scope_for_change(1), KeyScope::Internal);
        assert_eq!(scope_for_change(2), KeyScope::Ephemeral);
    }

    /// Testnet/regtest coin type is 1.
    const TEST_NET: consensus::NetworkType = consensus::NetworkType::Test;
    const FP: [u8; 32] = [0xAB; 32];

    /// The dedup of unified-account Sapling receiver keys compares the
    /// receiver key's diversifiable FVK against the UFVK's Sapling component;
    /// this pins the identity that comparison relies on: a unified spending
    /// key's Sapling component and the UFVK derived from that spending key
    /// expose byte-identical diversifiable FVKs.
    #[test]
    fn ua_sapling_receiver_dfvk_matches_ufvk_component() {
        let seed = [0xCD; 32];
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &seed,
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let component = usk
            .to_unified_full_viewing_key()
            .sapling()
            .expect("UA carries a Sapling component")
            .to_bytes();
        #[allow(deprecated)]
        let from_extsk = usk
            .sapling()
            .to_extended_full_viewing_key()
            .to_diversifiable_full_viewing_key()
            .to_bytes();
        assert_eq!(component, from_extsk);
    }

    #[test]
    fn sapling_key_source_maps_zip32_path() {
        let source = sapling_key_source(Some(&FP), Some("m/32'/1'/3'"), &TEST_NET);
        let KeySource::Derived(derived) = source else {
            panic!("expected a derived key source, got {source:?}");
        };
        assert_eq!(derived.seed_fingerprint(), &encode_seed_fingerprint(&FP));
        assert_eq!(derived.account_index(), 3);
        assert_eq!(derived.legacy_address_index(), None);
    }

    #[test]
    fn sapling_key_source_maps_post470_legacy_path() {
        let source = sapling_key_source(Some(&FP), Some("m/32'/1'/2147483647'/5'"), &TEST_NET);
        let KeySource::Derived(derived) = source else {
            panic!("expected a derived key source, got {source:?}");
        };
        assert_eq!(derived.account_index(), ZCASHD_LEGACY_ACCOUNT);
        assert_eq!(derived.legacy_address_index(), Some(5));
    }

    #[test]
    fn sapling_key_source_without_metadata_is_imported() {
        assert!(matches!(
            sapling_key_source(None, Some("m/32'/1'/3'"), &TEST_NET),
            KeySource::Imported
        ));
        assert!(matches!(
            sapling_key_source(Some(&FP), None, &TEST_NET),
            KeySource::Imported
        ));
    }

    #[test]
    fn sapling_key_source_with_unparseable_path_is_imported() {
        // A BIP-44 transparent path is not a Sapling ZIP-32 path.
        assert!(matches!(
            sapling_key_source(Some(&FP), Some("m/44'/1'/0'/0/5"), &TEST_NET),
            KeySource::Imported
        ));
        // A coin type for the wrong network is rejected by the parser.
        assert!(matches!(
            sapling_key_source(Some(&FP), Some("m/32'/133'/3'"), &TEST_NET),
            KeySource::Imported
        ));
    }
}
