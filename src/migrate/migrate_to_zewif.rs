
use zewif::{BlockHash, BlockHeight, Secrets, Zewif, ZewifWallet};

use crate::migrate::MigrateError;
use crate::ZcashdWallet;

use super::{
    attach_received_outputs, attach_sent_outputs, build_accounts, build_address_book,
    build_secret_store, convert_transactions,
    accounts::WalletAccounts,
    addresses::attach_addresses,
    transactions::collect_tx_heights,
};

/// Migrate a parsed zcashd wallet into a ZeWIF document.
///
/// `export_height` is the chain tip height at export time, supplied by the
/// caller (zcashd's `wallet.dat` records only a block-hash locator, not a
/// numeric height). The export block hash is taken from that locator's tip.
pub fn migrate_to_zewif(
    wallet: &ZcashdWallet,
    export_height: BlockHeight,
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
    let mut zewif_wallet = ZewifWallet::new(wallet.network().clone());
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
