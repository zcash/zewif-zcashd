use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow};
use secp256k1::PublicKey;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
use zcash_protocol::consensus;
use zcash_transparent::address::TransparentAddress;
use zip32::DiversifierIndex;

use zewif::{
    Address, Data, KeyScope, Network, ProtocolAddress, Script, UnifiedAddress,
    transparent::TransparentSpendAuthority,
};

use crate::{
    ZcashdWallet,
    migrate::{
        WalletAccounts,
        accounts::{derivation_info_from_keypath, scope_for_change},
        primitives::address_network_from_zewif,
    },
    zcashd_wallet::{
        ReceiverType,
        sprout::SproutPaymentAddress,
        transparent::{KeyPair, WatchScriptKind},
    },
};

/// Attach every address recoverable from the wallet to the appropriate
/// account: unified addresses to their unified account, and all transparent,
/// legacy Sapling, and Sprout addresses to the synthesized legacy account.
pub(crate) fn attach_addresses(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
    params: &impl consensus::Parameters,
) -> Result<()> {
    attach_transparent_addresses(wallet, accounts)?;
    attach_sapling_addresses(wallet, accounts)?;
    attach_sprout_addresses(wallet, accounts);
    attach_unified_addresses(wallet, accounts, params)?;
    Ok(())
}

/// Accumulated per-address transparent metadata, merged across zcashd's
/// several transparent-key sources (the key database, watch-only scripts, and
/// redeem scripts). The first non-`None` contribution wins.
#[derive(Default)]
struct TransparentInfo {
    spend_authority: Option<TransparentSpendAuthority>,
    scope: Option<KeyScope>,
    redeem_script: Option<Script>,
    pubkey: Option<Data>,
}

fn attach_transparent_addresses(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
) -> Result<()> {
    let network = wallet.network();
    let mut entries: HashMap<String, TransparentInfo> = HashMap::new();

    // The key database: every keypair (including reserved keypool keys, whose
    // public keys live here) yields a P2PKH address. HD-derived keys carry
    // their derivation; independently generated / imported keys are marked
    // `Imported` with the private key held in the secret store.
    for keypair in wallet.keys().keypairs() {
        let pk = PublicKey::from_slice(keypair.pubkey().as_slice())
            .context("parsing transparent public key from keypair")?;
        let addr_str = p2pkh_address_string(&pk, network);
        let (authority, scope) = transparent_spend_info(keypair);
        let entry = entries.entry(addr_str).or_default();
        entry.spend_authority.get_or_insert(authority);
        entry.scope.get_or_insert(scope);
    }

    // Watch-only imports (`importaddress` / `importpubkey`). P2PK entries carry
    // the public key and are surfaced at their P2PKH address; P2PKH entries are
    // bare watched addresses; P2SH entries pair with a redeem script (below).
    for watch in wallet.watch_scripts() {
        match watch.kind() {
            WatchScriptKind::P2PK(pubkey) => {
                match PublicKey::from_slice(pubkey.as_slice()) {
                    Ok(pk) => {
                        let addr_str = p2pkh_address_string(&pk, network);
                        let entry = entries.entry(addr_str).or_default();
                        entry.pubkey.get_or_insert(Data::from_bytes(pubkey.as_slice()));
                        entry.scope.get_or_insert(KeyScope::Foreign);
                    }
                    Err(_) => eprintln!(
                        "warning: watch-only P2PK script with unparsable public key dropped",
                    ),
                }
            }
            WatchScriptKind::P2PKH(_) | WatchScriptKind::P2SH(_) => {
                if let Some(addr_str) = watch.to_address_string(network) {
                    entries.entry(addr_str).or_default().scope.get_or_insert(KeyScope::Foreign);
                }
            }
            WatchScriptKind::Other(_) => eprintln!(
                "warning: watch-only script with no standard t-address encoding ({:?}) dropped",
                watch.kind(),
            ),
        }
    }

    // Redeem scripts (`cscript`) key by the P2SH address (the script hash is
    // both the CScriptID and the address's script hash).
    for (script_id, script) in wallet.cscripts() {
        let addr_str = script_id.to_string(network);
        let entry = entries.entry(addr_str).or_default();
        entry.redeem_script.get_or_insert(script.clone());
        entry.scope.get_or_insert(KeyScope::Foreign);
    }

    // Emit in a deterministic (address-sorted) order.
    let mut sorted: Vec<(String, TransparentInfo)> = entries.into_iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.cmp(b));

    let legacy = &mut accounts.accounts[accounts.legacy_index];
    for (addr_str, info) in sorted {
        let mut t_addr = zewif::transparent::Address::new(addr_str);
        if let Some(authority) = info.spend_authority {
            t_addr.set_spend_authority(authority);
        }
        // A watch-only public key is only carried when there is no spend
        // authority (otherwise it is derivable from the private key).
        if t_addr.spend_authority().is_none()
            && let Some(pubkey) = info.pubkey
        {
            t_addr.set_pubkey(pubkey);
        }
        if let Some(redeem_script) = info.redeem_script {
            t_addr.set_redeem_script(redeem_script);
        }
        let mut address = Address::new(ProtocolAddress::Transparent(t_addr));
        address.set_scope(info.scope.unwrap_or(KeyScope::External));
        legacy.add_address(address);
    }

    Ok(())
}

/// The spend authority and key scope for a transparent keypair: HD-derived
/// keys carry their derivation (change component determines the scope);
/// independently generated keys are `Imported` and treated as foreign.
fn transparent_spend_info(keypair: &KeyPair) -> (TransparentSpendAuthority, KeyScope) {
    if let Some(hd_path) = keypair.metadata().hd_keypath()
        && let Some(info) = derivation_info_from_keypath(hd_path)
    {
        let scope = scope_for_change(u32::from(info.change()));
        return (TransparentSpendAuthority::Derived(info), scope);
    }
    (TransparentSpendAuthority::Imported, KeyScope::Foreign)
}

fn p2pkh_address_string(pk: &PublicKey, network: &Network) -> String {
    let TransparentAddress::PublicKeyHash(hash) = TransparentAddress::from_pubkey(pk) else {
        unreachable!("from_pubkey always returns PublicKeyHash");
    };
    ZcashAddress::from_transparent_p2pkh(address_network_from_zewif(network), hash).to_string()
}

fn attach_sapling_addresses(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
) -> Result<()> {
    let network = wallet.network();
    let legacy_index = accounts.legacy_index;
    let mut emitted: HashSet<zewif::sapling::SaplingIncomingViewingKey> = HashSet::new();

    // Collect (address string, protocol address, scope) and emit sorted by
    // address, so the migrated wallet is reproducible across runs (the source
    // maps have no stable iteration order).
    let mut collected: Vec<(String, zewif::sapling::Address, KeyScope)> = Vec::new();

    // Spend-capable and view-only-with-default-address Sapling addresses have a
    // `sapzaddr` record.
    for (sapling_address, ivk) in wallet.sapling_z_addresses() {
        let addr_str = sapling_address.to_string(network);
        let mut sapling_addr = zewif::sapling::Address::new(addr_str.clone());
        sapling_addr.set_diversifier_index(sapling_address.diversifier().clone());
        collected.push((addr_str, sapling_addr, KeyScope::External));
        emitted.insert(*ivk);
    }

    // View-only extended FVKs imported with `addDefaultAddress=false` have no
    // companion `sapzaddr`; recover the canonical default address.
    for (ivk, extfvk) in wallet.sapling_extended_full_viewing_keys() {
        if !emitted.insert(*ivk) {
            continue;
        }
        let (_j, payment_address) = extfvk.to_diversifiable_full_viewing_key().default_address();
        let addr_str = ZcashAddress::from_sapling(
            address_network_from_zewif(network),
            payment_address.to_bytes(),
        )
        .to_string();
        // Imported view-only key material not derived from account keys.
        collected.push((
            addr_str.clone(),
            zewif::sapling::Address::new(addr_str),
            KeyScope::Foreign,
        ));
    }

    collected.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
    for (_, sapling_addr, scope) in collected {
        let mut address = Address::new(ProtocolAddress::Sapling(Box::new(sapling_addr)));
        address.set_scope(scope);
        accounts.accounts[legacy_index].add_address(address);
    }

    Ok(())
}

fn attach_sprout_addresses(wallet: &ZcashdWallet, accounts: &mut WalletAccounts) {
    let Some(sprout_keys) = wallet.sprout_keys() else {
        return;
    };
    let network = wallet.network();
    let legacy_index = accounts.legacy_index;

    let mut addrs: Vec<String> = sprout_keys
        .iter()
        .map(|(sprout_address, _sk)| sprout_address_string(sprout_address, network))
        .collect();
    addrs.sort();
    for addr_str in addrs {
        let mut address = Address::new(ProtocolAddress::Sprout(zewif::sprout::SproutAddress::new(
            addr_str,
        )));
        address.set_scope(KeyScope::External);
        accounts.accounts[legacy_index].add_address(address);
    }
}

fn attach_unified_addresses(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
    params: &impl consensus::Parameters,
) -> Result<()> {
    let unified_accounts = wallet.unified_accounts();

    for metadata in &unified_accounts.address_metadata {
        let ufvk = unified_accounts
            .full_viewing_keys
            .get(&metadata.key_id)
            .ok_or_else(|| {
                anyhow!(
                    "No UFVK found for unified address fingerprint {}",
                    metadata.key_id.to_hex()
                )
            })?;

        let j = DiversifierIndex::from(<[u8; 11]>::from(metadata.diversifier_index.clone()));
        let require = |present: bool| {
            if present {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            }
        };
        let request = UnifiedAddressRequest::custom(
            require(metadata.receiver_types.contains(&ReceiverType::P2PKH)),
            require(metadata.receiver_types.contains(&ReceiverType::Sapling)),
            require(metadata.receiver_types.contains(&ReceiverType::Orchard)),
        )
        .map_err(|e| anyhow!("Receiver types do not produce a valid Unified address: {e}"))?;

        let ua_str = ufvk.address(j, request)?.encode(params);

        let mut unified_address = UnifiedAddress::new(ua_str);
        unified_address.set_diversifier_index(metadata.diversifier_index.clone());

        let mut address =
            Address::new(ProtocolAddress::Unified(Box::new(unified_address)));
        address.set_scope(KeyScope::External);

        match accounts.ufvk_index.get(&metadata.key_id) {
            Some(&idx) => accounts.accounts[idx].add_address(address),
            None => accounts.accounts[accounts.legacy_index].add_address(address),
        }
    }

    Ok(())
}

/// Encode a Sprout payment address as its canonical `zc`-prefixed string.
pub(crate) fn sprout_address_string(addr: &SproutPaymentAddress, network: &Network) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(AsRef::<[u8; 32]>::as_ref(&addr.a_pk()));
    bytes[32..].copy_from_slice(AsRef::<[u8; 32]>::as_ref(&addr.pk_enc()));
    ZcashAddress::from_sprout(address_network_from_zewif(network), bytes).to_string()
}
