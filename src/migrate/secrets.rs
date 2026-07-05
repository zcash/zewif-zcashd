use anyhow::{Result, anyhow};

use zewif::{
    SecretStore, SeedEntry, SeedFingerprint, SeedMaterial, SproutKeyEntry,
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
    let fp = zip32::fingerprint::SeedFingerprint::from_seed(seed.as_slice())
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
        match transparent_key_entry(keypair.pubkey().as_slice(), keypair.privkey()) {
            Ok(entry) => store.add_transparent_key(entry),
            Err(e) => eprintln!("warning: skipping transparent key: {e}"),
        }
    }
    if let Some(wallet_keys) = wallet.wallet_keys() {
        for wkey in wallet_keys.keypairs() {
            match transparent_key_entry(wkey.pubkey().as_slice(), wkey.privkey()) {
                Ok(entry) => store.add_transparent_key(entry),
                Err(e) => eprintln!("warning: skipping wkey transparent key: {e}"),
            }
        }
    }

    // Sapling extended spending keys, keyed by their extended full viewing key
    // encoding (169 bytes, ZIP-32).
    for sapling_key in wallet.sapling_keys().keypairs() {
        let extsk = sapling_key.extsk();
        let fvk_bytes = sapling_extfvk_bytes(extsk)?;
        let fvk = zewif::sapling::SaplingExtendedFullViewingKey::from_vec(fvk_bytes)
            .map_err(|_| anyhow!("Sapling extended FVK encoding must be 169 bytes"))?;
        store.add_sapling_key(zewif::SaplingKeyEntry::new(
            fvk,
            SaplingExtendedSpendingKey::new(extsk.to_bytes()),
        ));
    }

    // Sprout spending keys, keyed by address.
    if let Some(sprout_keys) = wallet.sprout_keys() {
        for (address, sk) in sprout_keys.iter() {
            let address_str = sprout_address_string(address, wallet.network());
            let key_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&sk.key());
            // The canonical Sprout spending key encoding is the 2-byte
            // network version prefix followed by a_sk (zcashd
            // base58Prefixes[ZCSPENDING_KEY]).
            let prefix: [u8; 2] = match wallet.network() {
                zewif::Network::Mainnet => [0xAB, 0x36],
                _ => [0xAC, 0x08],
            };
            let mut encoded = [0u8; 34];
            encoded[..2].copy_from_slice(&prefix);
            encoded[2..].copy_from_slice(&key_bytes);
            store.add_sprout_key(SproutKeyEntry::new(
                address_str,
                SproutSpendingKey::new(encoded),
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

/// Builds a transparent secret-store entry from a serialized public key and
/// the corresponding private key record.
fn transparent_key_entry(
    pubkey: &[u8],
    privkey: &crate::zcashd_wallet::transparent::PrivKey,
) -> Result<TransparentKeyEntry> {
    let pubkey = zewif::transparent::TransparentPubKey::from_bytes(pubkey.to_vec())
        .map_err(|e| anyhow!("invalid public key: {e}"))?;
    let scalar = privkey
        .secp256k1_scalar()
        .map_err(|e| anyhow!("undecodable private key: {e}"))?;
    Ok(TransparentKeyEntry::new(
        pubkey,
        TransparentSpendingKey::new(scalar),
    ))
}
