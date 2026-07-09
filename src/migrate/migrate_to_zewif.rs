use std::collections::BTreeMap;

use zcash_protocol::consensus::BranchId;
use zcash_protocol::local_consensus::LocalNetwork;
use zewif::{BlockHash, BlockHeight, Network, RegtestParams, Secrets, Zewif, ZewifWallet};

use crate::migrate::MigrateError;
use crate::ZcashdWallet;

use super::{
    attach_received_outputs, attach_sent_outputs, build_accounts, build_address_book,
    build_secret_store, convert_transactions,
    accounts::WalletAccounts,
    addresses::attach_addresses,
    transactions::collect_tx_heights,
};

/// How to determine a regtest network's network-upgrade activation schedule
/// when exporting a regtest wallet.
///
/// A zcashd `wallet.dat` does not record the regtest activation schedule (it
/// comes from node configuration, e.g. `-nuparams`), so the caller must supply
/// it for the exported document to describe the chain the wallet was recorded
/// against. This is ignored when exporting a mainnet or testnet wallet, whose
/// activation schedules are fixed by the protocol.
#[non_exhaustive]
pub enum RegtestActivations {
    /// The local consensus parameters the wallet was recorded against, supplied
    /// directly by the caller. This is the mode for an offline export, with no
    /// running node to consult.
    Local(LocalNetwork),
}

/// Builds the ZeWIF regtest activation schedule — a map from consensus branch ID
/// to activation height — from a set of local consensus parameters. Upgrades
/// that the parameters leave unactivated are omitted.
fn regtest_params_from_local(local: &LocalNetwork) -> RegtestParams {
    let mut activations = BTreeMap::new();
    for (height, branch_id) in [
        (local.overwinter, BranchId::Overwinter),
        (local.sapling, BranchId::Sapling),
        (local.blossom, BranchId::Blossom),
        (local.heartwood, BranchId::Heartwood),
        (local.canopy, BranchId::Canopy),
        (local.nu5, BranchId::Nu5),
        (local.nu6, BranchId::Nu6),
        (local.nu6_1, BranchId::Nu6_1),
        (local.nu6_2, BranchId::Nu6_2),
    ] {
        if let Some(height) = height {
            activations.insert(u32::from(branch_id), u32::from(height));
        }
    }
    #[cfg(zcash_unstable = "nu7")]
    if let Some(height) = local.nu7 {
        activations.insert(u32::from(BranchId::Nu7), u32::from(height));
    }
    RegtestParams::new(activations)
}

/// The network to record in the exported document.
///
/// For a regtest wallet with a caller-supplied activation schedule, that
/// schedule replaces the empty default the parser produces; in every other case
/// (a regtest wallet with no supplied schedule, or a mainnet/testnet wallet) the
/// wallet's own network is used unchanged.
fn export_network(network: &Network, regtest_activations: Option<&RegtestActivations>) -> Network {
    match (network, regtest_activations) {
        (Network::Regtest(_), Some(RegtestActivations::Local(local))) => {
            Network::Regtest(regtest_params_from_local(local))
        }
        _ => network.clone(),
    }
}

/// Migrate a parsed zcashd wallet into a ZeWIF document.
///
/// `export_height` is the chain tip height at export time, supplied by the
/// caller (zcashd's `wallet.dat` records only a block-hash locator, not a
/// numeric height). The export block hash is taken from that locator's tip.
///
/// `regtest_activations` supplies the network-upgrade activation schedule when
/// exporting a regtest wallet, which the `wallet.dat` does not record; see
/// [`RegtestActivations`]. Pass `None` to export a regtest wallet without a
/// schedule (an importer then trusts its own regtest parameters), or when
/// exporting a mainnet or testnet wallet.
pub fn migrate_to_zewif(
    wallet: &ZcashdWallet,
    export_height: BlockHeight,
    regtest_activations: Option<RegtestActivations>,
) -> Result<Zewif, MigrateError> {
    let params = wallet.network_info().to_address_encoding_network();

    let mut zewif = Zewif::new(export_height, best_block_hash(wallet));

    // Global transaction table (raw bytes + metadata).
    let transactions = convert_transactions(wallet)?;

    // Accounts, addresses, received and sent outputs.
    let mut accounts = build_accounts(wallet, &params)?;
    attach_addresses(wallet, &mut accounts, &params)?;
    attach_received_outputs(wallet, &mut accounts)?;
    attach_sent_outputs(wallet, &mut accounts)?;
    set_account_birthdays(wallet, &mut accounts);

    // Assemble the wallet.
    let mut zewif_wallet = ZewifWallet::new(export_network(
        wallet.network(),
        regtest_activations.as_ref(),
    ));
    for account in accounts.accounts {
        zewif_wallet.add_account(account);
    }
    for entry in build_address_book(wallet) {
        zewif_wallet.add_address_book_entry(entry);
    }
    zewif.add_wallet(zewif_wallet);

    for (txid, tx) in transactions {
        zewif.add_transaction(txid, tx);
    }

    // Sensitive material (omitted entirely for a viewing-only wallet).
    if let Some(store) = build_secret_store(wallet)? {
        zewif.set_secrets(Secrets::Plain(store));
    }

    Ok(zewif)
}

/// The export block hash: the tip of zcashd's best-block locator, or the zero
/// hash when the locator is empty (a freshly initialized wallet).
fn best_block_hash(wallet: &ZcashdWallet) -> BlockHash {
    wallet
        .bestblock()
        .blocks()
        .first()
        .map(|h| BlockHash::from_bytes((*h).into_bytes()))
        .unwrap_or_else(|| BlockHash::from_bytes([0u8; 32]))
}

/// Estimate each account's birthday height as the earliest mined height among
/// its relevant transactions. Only transactions that touched the Orchard
/// commitment tree have a recoverable height, so accounts with no such
/// transactions are left without a birthday (the importer must rescan from an
/// earlier point).
fn set_account_birthdays(wallet: &ZcashdWallet, accounts: &mut WalletAccounts) {
    let tx_heights = collect_tx_heights(wallet);
    for account in &mut accounts.accounts {
        let birthday = account
            .relevant_transactions()
            .keys()
            .filter_map(|txid| tx_heights.get(txid.as_bytes()).copied())
            .min();
        if let Some(height) = birthday {
            account.set_birthday_height(BlockHeight::from_u32(height));
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BlockHeight as ConsensusBlockHeight;

    use super::*;

    /// A regtest network activating every upgrade at a distinct height, so the
    /// branch-ID-to-height mapping can be checked unambiguously.
    fn distinct_local_network() -> LocalNetwork {
        LocalNetwork {
            overwinter: Some(ConsensusBlockHeight::from_u32(1)),
            sapling: Some(ConsensusBlockHeight::from_u32(2)),
            blossom: Some(ConsensusBlockHeight::from_u32(3)),
            heartwood: Some(ConsensusBlockHeight::from_u32(4)),
            canopy: Some(ConsensusBlockHeight::from_u32(5)),
            nu5: Some(ConsensusBlockHeight::from_u32(6)),
            nu6: Some(ConsensusBlockHeight::from_u32(7)),
            nu6_1: Some(ConsensusBlockHeight::from_u32(8)),
            nu6_2: Some(ConsensusBlockHeight::from_u32(9)),
            #[cfg(zcash_unstable = "nu7")]
            nu7: Some(ConsensusBlockHeight::from_u32(10)),
        }
    }

    #[test]
    fn local_network_converts_to_branch_id_keyed_schedule() {
        let params = regtest_params_from_local(&distinct_local_network());
        assert_eq!(
            params.activations().get(&u32::from(BranchId::Sapling)),
            Some(&2)
        );
        assert_eq!(params.activations().get(&u32::from(BranchId::Nu5)), Some(&6));
        assert_eq!(
            params.activations().get(&u32::from(BranchId::Nu6_2)),
            Some(&9)
        );
    }

    #[test]
    fn unactivated_upgrades_are_omitted() {
        let mut local = distinct_local_network();
        local.nu6_2 = None;
        let params = regtest_params_from_local(&local);
        assert!(
            params
                .activations()
                .get(&u32::from(BranchId::Nu6_2))
                .is_none()
        );
    }

    #[test]
    fn export_network_populates_regtest_schedule() {
        let activations = RegtestActivations::Local(distinct_local_network());
        let out = export_network(&Network::Regtest(RegtestParams::default()), Some(&activations));
        match out {
            Network::Regtest(params) => assert_eq!(
                params.activations().get(&u32::from(BranchId::Sapling)),
                Some(&2)
            ),
            other => panic!("expected a regtest network, got {other:?}"),
        }
    }

    #[test]
    fn export_network_regtest_without_activations_is_unchanged() {
        let network = Network::Regtest(RegtestParams::default());
        assert_eq!(export_network(&network, None), network);
    }

    #[test]
    fn export_network_ignores_activations_for_mainnet() {
        let activations = RegtestActivations::Local(distinct_local_network());
        assert_eq!(
            export_network(&Network::Mainnet, Some(&activations)),
            Network::Mainnet
        );
    }
}
