use std::collections::HashMap;

use anyhow::{Context, Result};
use zewif::{
    BlockHash, BlockHeight, Data, RawTxData, Transaction, TransactionData, TxBlockPosition, TxId,
};

use crate::{ZcashdWallet, zcashd_wallet::WalletTx};

/// Build the global transaction table and, as a by-product, a map from txid to
/// the block height at which each transaction was mined (recoverable only for
/// transactions that contributed to the Orchard note commitment tree).
pub(crate) fn convert_transactions(
    wallet: &ZcashdWallet,
) -> Result<HashMap<TxId, Transaction>> {
    let tx_heights = collect_tx_heights(wallet);
    let mut transactions = HashMap::new();
    for (txid, wtx) in wallet.transactions() {
        let tx = convert_transaction(*txid, wtx, &tx_heights)
            .with_context(|| format!("Failed to convert transaction {txid}"))?;
        transactions.insert(*txid, tx);
    }
    Ok(transactions)
}

/// The mined height of each transaction whose height zcashd records, keyed by
/// raw (internal-order) txid bytes. zcashd only retains per-transaction heights
/// for transactions that appended notes to the Orchard commitment tree.
pub(crate) fn collect_tx_heights(wallet: &ZcashdWallet) -> HashMap<[u8; 32], u32> {
    let mut heights = HashMap::new();
    for (txid, positions) in wallet.orchard_note_commitment_tree().note_positions() {
        heights.insert(*txid.as_ref(), u32::from(positions.tx_height()));
    }
    heights
}

fn convert_transaction(
    txid: TxId,
    wtx: &WalletTx,
    tx_heights: &HashMap<[u8; 32], u32>,
) -> Result<Transaction> {
    let mut tx = Transaction::new(txid);

    // Re-serialize the parsed transaction to its canonical bytes. The parser
    // asserts there is no trailing unparsed data, so the round-trip is exact.
    let mut raw = Vec::new();
    wtx.transaction()
        .write(&mut raw)
        .context("re-serializing parsed transaction to raw bytes")?;
    tx.set_tx_data(TransactionData::Raw(RawTxData::new(Data::from_vec(raw))));

    // Block linkage: a non-zero block hash and a non-negative in-block index
    // mean the transaction is mined.
    let block_hash = wtx.hash_block();
    if block_hash != BlockHash::from_bytes([0u8; 32]) && wtx.index() >= 0 {
        tx.set_block_position(TxBlockPosition::new(block_hash, wtx.index() as u32));
    }

    if let Some(height) = tx_heights.get(txid.as_bytes()) {
        tx.set_mined_height(BlockHeight::from_u32(*height));
    }

    let expiry = u32::from(wtx.transaction().expiry_height());
    if expiry != 0 {
        tx.set_expiry_height(BlockHeight::from_u32(expiry));
    }

    let time_received = wtx.time_received();
    if time_received > 0 {
        tx.set_created_time(time_received as i64);
    }

    Ok(tx)
}
