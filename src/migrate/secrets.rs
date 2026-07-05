use anyhow::{Result, anyhow};

use zewif::{
    Data, SecretStore, SeedEntry, SeedFingerprint, SeedMaterial, SproutKeyEntry,
    TransparentKeyEntry, sapling::SaplingExtendedSpendingKey, sprout::SproutSpendingKey,
    transparent::TransparentSpendingKey,
};

use crate::{ZcashdWallet, migrate::addresses::sprout_address_string};

/// The ZIP-32 seed fingerprint of the wallet's mnemonic seed, if a mnemonic is
/// present. Taken from the mnemonic HD chain, where zcashd records it directly.
pub(crate) fn mnemonic_seed_fingerprint(wallet: &ZcashdWallet) -> Option<SeedFingerprint> {
    if wallet.bip39_mnemonic().mnemonic().is_empty() {
        return None;
    }
    SeedFingerprint::from_slice(wallet.mnemonic_hd_chain().seed_fp().as_slice()).ok()
}

/// The ZIP-32 seed fingerprint of the wallet's pre-mnemonic legacy HD seed, if
/// present. Recomputed from the seed bytes per ZIP-32 (the seed types no longer
/// carry the fingerprint).
pub(crate) fn legacy_seed_fingerprint(wallet: &ZcashdWallet) -> Result<Option<SeedFingerprint>> {
    let Some(seed) = wallet.legacy_hd_seed() else {
        return Ok(None);
    };
    let fp = zip32::fingerprint::SeedFingerprint::from_seed(seed.seed_data().as_ref())
        .ok_or_else(|| anyhow!("Legacy HD seed has an invalid length for ZIP-32 fingerprinting"))?;
    Ok(Some(SeedFingerprint::new(fp.to_bytes())))
}

/// Build the document's secret store from all spending material the wallet
/// exposes: mnemonic and legacy seeds (keyed by ZIP-32 fingerprint),
/// standalone transparent private keys (keyed by public key), Sapling extended
/// spending keys (keyed by their extended full viewing key encoding), and
/// Sprout spending keys (keyed by address).
///
/// Returns `None` when no secret material is present (a viewing-only export).
pub(crate) fn build_secret_store(wallet: &ZcashdWallet) -> Result<Option<SecretStore>> {
    let mut store = SecretStore::new();

    // Seeds.
    if let Some(fp) = mnemonic_seed_fingerprint(wallet) {
        store.add_seed(SeedEntry::new(
            fp,
            SeedMaterial::Bip39Mnemonic(wallet.bip39_mnemonic().clone()),
        ));
    }
    if let (Some(fp), Some(seed)) = (legacy_seed_fingerprint(wallet)?, wallet.legacy_hd_seed()) {
        store.add_seed(SeedEntry::new(
            fp,
            SeedMaterial::LegacySeed(seed.clone()),
        ));
    }

    // Transparent private keys, keyed by public key. The legacy `key`/`keys`
    // records and the encrypted-comment `wkey` records both carry spendable
    // secp256k1 keys.
    for keypair in wallet.keys().keypairs() {
        match keypair.privkey().secp256k1_scalar() {
            Ok(scalar) => store.add_transparent_key(TransparentKeyEntry::new(
                Data::from_bytes(keypair.pubkey().as_slice()),
                TransparentSpendingKey::new(scalar),
            )),
            Err(e) => eprintln!(
                "warning: skipping transparent key with undecodable private key: {e}"
            ),
        }
    }
    if let Some(wallet_keys) = wallet.wallet_keys() {
        for wkey in wallet_keys.keypairs() {
            match wkey.privkey().secp256k1_scalar() {
                Ok(scalar) => store.add_transparent_key(TransparentKeyEntry::new(
                    Data::from_bytes(wkey.pubkey().as_slice()),
                    TransparentSpendingKey::new(scalar),
                )),
                Err(e) => eprintln!(
                    "warning: skipping wkey transparent key with undecodable private key: {e}"
                ),
            }
        }
    }

    // Sapling extended spending keys, keyed by their extended full viewing key
    // encoding (169 bytes, ZIP-32).
    for sapling_key in wallet.sapling_keys().keypairs() {
        let extsk = sapling_key.extsk();
        let fvk_bytes = sapling_extfvk_bytes(extsk)?;
        store.add_sapling_key(zewif::SaplingKeyEntry::new(
            Data::from_vec(fvk_bytes),
            SaplingExtendedSpendingKey::new(extsk.to_bytes()),
        ));
    }

    // Sprout spending keys, keyed by address.
    if let Some(sprout_keys) = wallet.sprout_keys() {
        for (address, sk) in sprout_keys.iter() {
            let address_str = sprout_address_string(address, wallet.network());
            let key_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&sk.key());
            store.add_sprout_key(SproutKeyEntry::new(
                address_str,
                SproutSpendingKey::new(Data::from_bytes(key_bytes)),
            ));
        }
    }

    let is_empty = store.seeds().is_empty()
        && store.transparent_keys().is_empty()
        && store.sapling_keys().is_empty()
        && store.sprout_keys().is_empty();

    Ok((!is_empty).then_some(store))
}

/// Serialize a Sapling extended spending key's corresponding extended full
/// viewing key into its canonical 169-byte ZIP-32 encoding.
fn sapling_extfvk_bytes(extsk: &::sapling::zip32::ExtendedSpendingKey) -> Result<Vec<u8>> {
    #[allow(deprecated)]
    let efvk = extsk.to_extended_full_viewing_key();
    let mut bytes = Vec::with_capacity(169);
    efvk.write(&mut bytes)
        .map_err(|e| anyhow!("Serializing Sapling extended full viewing key: {e}"))?;
    Ok(bytes)
}
