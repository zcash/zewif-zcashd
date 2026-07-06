
use zewif::{
    SecretStore, SeedEntry, SeedFingerprint, SeedMaterial, SproutKeyEntry,
    TransparentKeyEntry, sapling::SaplingExtendedSpendingKey, sprout::SproutSpendingKey,
    transparent::TransparentSpendingKey,
};

use crate::migrate::MigrateError;
use crate::{ZcashdWallet, migrate::addresses::sprout_address_string};

/// The ZIP-32 seed fingerprint of the wallet's mnemonic seed, if a mnemonic is
/// present. Taken from the mnemonic HD chain, where zcashd records it directly.
pub(crate) fn mnemonic_seed_fingerprint(wallet: &ZcashdWallet) -> Option<SeedFingerprint> {
    if wallet.bip39_mnemonic().mnemonic().is_empty() {
        return None;
    }
    let bytes: [u8; 32] = wallet
        .mnemonic_hd_chain()
        .seed_fp()
        .as_slice()
        .try_into()
        .ok()?;
    Some(crate::zcashd_wallet::encode_seed_fingerprint(&bytes))
}

/// The ZIP-32 seed fingerprint of the wallet's pre-mnemonic legacy HD seed, if
/// present. Recomputed from the seed bytes per ZIP-32 (the seed types no longer
/// carry the fingerprint).
pub(crate) fn legacy_seed_fingerprint(wallet: &ZcashdWallet) -> Result<Option<SeedFingerprint>, MigrateError> {
    let Some(seed) = wallet.legacy_hd_seed() else {
        return Ok(None);
    };
    let fp = zip32::fingerprint::SeedFingerprint::from_seed(seed.as_slice())
        .ok_or(MigrateError::InvalidLegacySeedLength)?;
    Ok(Some(crate::zcashd_wallet::encode_seed_fingerprint(
        &fp.to_bytes(),
    )))
}

/// Build the document's secret store from all spending material the wallet
/// exposes: mnemonic and legacy seeds (keyed by ZIP-32 fingerprint),
/// standalone transparent private keys (keyed by public key), Sapling extended
/// spending keys (keyed by their extended full viewing key encoding), and
/// Sprout spending keys (keyed by address).
///
/// Returns `None` when no secret material is present (a viewing-only export).
pub(crate) fn build_secret_store(wallet: &ZcashdWallet) -> Result<Option<SecretStore>, MigrateError> {
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
    let mut transparent_sources: Vec<(&[u8], &crate::zcashd_wallet::transparent::PrivKey)> = wallet
        .keys()
        .keypairs()
        .map(|keypair| (keypair.pubkey().as_slice(), keypair.privkey()))
        .collect();
    if let Some(wallet_keys) = wallet.wallet_keys() {
        transparent_sources.extend(
            wallet_keys
                .keypairs()
                .map(|wkey| (wkey.pubkey().as_slice(), wkey.privkey())),
        );
    }
    // Emit in a deterministic (pubkey-sorted) order.
    transparent_sources.sort_by_key(|(pubkey, _)| *pubkey);
    for (pubkey, privkey) in transparent_sources {
        match transparent_key_entry(pubkey, privkey, wallet.network()) {
            Ok(entry) => store.add_transparent_key(entry),
            Err(e) => eprintln!("warning: skipping transparent key: {e}"),
        }
    }

    // Sapling extended spending keys, keyed by their extended full viewing key
    // encoding (169 bytes, ZIP-32).
    let (extsk_hrp, extfvk_hrp) = sapling_hrps(wallet.network());
    let mut sapling_entries: Vec<(String, String)> = wallet
        .sapling_keys()
        .keypairs()
        .map(|sapling_key| {
            let extsk = sapling_key.extsk();
            #[allow(deprecated)]
            let efvk = extsk.to_extended_full_viewing_key();
            (
                zcash_keys::encoding::encode_extended_full_viewing_key(extfvk_hrp, &efvk),
                zcash_keys::encoding::encode_extended_spending_key(extsk_hrp, extsk),
            )
        })
        .collect();
    // Emit in a deterministic (viewing-key-sorted) order.
    sapling_entries.sort();
    for (efvk, extsk) in sapling_entries {
        store.add_sapling_key(zewif::SaplingKeyEntry::new(
            zewif::sapling::SaplingExtendedFullViewingKey::new(efvk),
            SaplingExtendedSpendingKey::new(extsk),
        ));
    }

    // Sprout spending keys, keyed by address.
    if let Some(sprout_keys) = wallet.sprout_keys() {
        // Emit in a deterministic (address-sorted) order.
        let mut sprout_entries: Vec<(String, _)> = sprout_keys
            .iter()
            .map(|(address, sk)| (sprout_address_string(address, wallet.network()), sk))
            .collect();
        sprout_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (address_str, sk) in sprout_entries {
            let key_bytes: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&sk.key());
            // Canonical Base58Check encoding: the 2-byte network version
            // prefix (zcashd base58Prefixes[ZCSPENDING_KEY]) followed by
            // the padded a_sk, then check-encoded ("SK..." / "ST...").
            let prefix: [u8; 2] = match wallet.network() {
                zewif::Network::Mainnet => [0xAB, 0x36],
                _ => [0xAC, 0x08],
            };
            let mut payload = Vec::with_capacity(34);
            payload.extend_from_slice(&prefix);
            payload.extend_from_slice(&key_bytes);
            store.add_sprout_key(SproutKeyEntry::new(
                address_str,
                SproutSpendingKey::new(bs58::encode(payload).with_check().into_string()),
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
/// The ZIP 32 Bech32 Human-Readable Parts for Sapling extended keys on the
/// given network: (extended spending key, extended full viewing key).
fn sapling_hrps(network: &zewif::Network) -> (&'static str, &'static str) {
    use zcash_protocol::constants::{mainnet, regtest, testnet};
    match network {
        zewif::Network::Mainnet => (
            mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        ),
        zewif::Network::Testnet => (
            testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        ),
        _ => (
            regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        ),
    }
}

/// Builds a transparent secret-store entry from a serialized public key and
/// the corresponding private key record. The private key is emitted in its
/// canonical WIF Base58Check encoding; a compressed public key (33 bytes)
/// selects the compressed WIF form.
fn transparent_key_entry(
    pubkey: &[u8],
    privkey: &crate::zcashd_wallet::transparent::PrivKey,
    network: &zewif::Network,
) -> Result<TransparentKeyEntry, MigrateError> {
    let pubkey = zewif::transparent::TransparentPubKey::from_bytes(pubkey.to_vec())
        .map_err(MigrateError::InvalidTransparentPubKey)?;
    let scalar = privkey
        .secp256k1_scalar()
        .map_err(MigrateError::InvalidPrivateKey)?;
    let version: u8 = match network {
        zewif::Network::Mainnet => 0x80,
        _ => 0xEF,
    };
    let mut payload = Vec::with_capacity(34);
    payload.push(version);
    payload.extend_from_slice(&scalar);
    if pubkey.is_compressed() {
        payload.push(0x01);
    }
    let wif = bs58::encode(payload).with_check().into_string();
    Ok(TransparentKeyEntry::new(
        pubkey,
        TransparentSpendingKey::new(wif),
    ))
}
