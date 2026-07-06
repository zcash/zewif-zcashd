use std::collections::HashMap;

use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus;

use zewif::{
    Account, AccountPurpose, AccountViewingKey, DerivationInfo, DerivedKeySource, KeyScope,
    KeySource, NonHardenedChildIndex,
};

use crate::migrate::MigrateError;
use crate::{
    ZcashdWallet,
    migrate::secrets::mnemonic_seed_fingerprint,
    zcashd_wallet::UfvkFingerprint,
};

/// The ZIP-32 account index zcashd reserves for its legacy pool of
/// pre-mnemonic / imported keys (`m/32'/coin'/0x7FFFFFFF'`).
pub(crate) const ZCASHD_LEGACY_ACCOUNT: u32 = 0x7FFF_FFFF;

/// The accounts synthesized from a zcashd wallet, together with the routing
/// metadata needed to attach addresses and received outputs to them.
pub(crate) struct WalletAccounts {
    /// The accounts, in stable order: one per unified account (ascending
    /// ZIP-32 account index), followed by the synthesized legacy account.
    pub accounts: Vec<Account>,
    /// Maps each unified account's zcashd UFVK fingerprint to its index in
    /// [`Self::accounts`], used to route unified addresses.
    pub ufvk_index: HashMap<UfvkFingerprint, usize>,
    /// For each unified account, its index in [`Self::accounts`] paired with
    /// the parsed UFVK, used to route Orchard received outputs by matching
    /// incoming viewing keys.
    pub unified: Vec<(usize, UnifiedFullViewingKey)>,
    /// Index of the synthesized legacy account (transparent, legacy Sapling,
    /// and Sprout material).
    pub legacy_index: usize,
}

/// Build the accounts for a zcashd wallet.
///
/// Each zcashd unified account becomes a [`AccountViewingKey::Ufvk`] account.
/// Everything else — legacy transparent keys (derived, imported, watch-only),
/// legacy Sapling addresses allocated via `z_getnewaddress`, and Sprout keys —
/// is collected into a single synthesized legacy account keyed by
/// [`AccountViewingKey::TransparentAddressSet`], mirroring zcashd's own
/// account-0x7FFFFFFF legacy pool. Sapling and Sprout addresses within it
/// carry their own protocol addresses; their spending keys live in the secret
/// store.
pub(crate) fn build_accounts(
    wallet: &ZcashdWallet,
    params: &impl consensus::Parameters,
) -> Result<WalletAccounts, MigrateError> {
    let mut accounts = Vec::new();
    let mut ufvk_index = HashMap::new();
    let mut unified = Vec::new();

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

    // The synthesized legacy account: a hybrid pool holding transparent,
    // legacy Sapling, and Sprout addresses (zcashd account 0x7FFFFFFF).
    let mut legacy = Account::new(AccountViewingKey::TransparentAddressSet);
    legacy.set_name("Legacy");
    // The mnemonic seed is the only seed from which zcashd ever derives keys
    // at account index 0x7FFFFFFF: post-v4.7.0 `getnewaddress` transparent
    // keys (m/44'/coin'/0x7FFFFFFF'/change/index) and post-v4.7.0
    // `z_getnewaddress` Sapling keys (m/32'/coin'/0x7FFFFFFF'/idx'). The
    // pre-mnemonic legacy seed only ever derived Sapling keys, at
    // m/32'/coin'/account' (pre-v4.7.0), and pre-v4.7.0 transparent keys are
    // plain system randomness. A wallet without a mnemonic therefore has no
    // derivation root for this account: its keys are a bag of imported
    // material whose secrets (including the legacy seed itself, from which
    // pre-v4.7.0 Sapling keys can be re-derived) are individually present in
    // the secret store.
    match mnemonic_seed_fingerprint(wallet) {
        Some(seed_fp) => {
            legacy.set_key_source(KeySource::Derived(DerivedKeySource::new(
                seed_fp,
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
        legacy_index,
    })
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
}
