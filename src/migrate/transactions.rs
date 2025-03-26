use std::collections::HashMap;

use anyhow::{Result, Context};
use zewif::{u256, TxId};
use crate::ZcashdWallet;


/// Convert ZCashd transactions to Zewif format
pub fn convert_transactions(wallet: &ZcashdWallet) -> Result<HashMap<TxId, zewif::Transaction>> {
    let mut transactions = HashMap::new();

    for (tx_id, wallet_tx) in wallet.transactions() {
        let zewif_tx = convert_transaction(*tx_id, wallet_tx)
            .with_context(|| format!("Failed to convert transaction {}", tx_id))?;
        transactions.insert(*tx_id, zewif_tx);
    }

    Ok(transactions)
}

/// Convert a single ZCashd transaction to Zewif format
fn convert_transaction(tx_id: TxId, tx: &crate::WalletTx) -> Result<zewif::Transaction> {
    let mut zewif_tx = zewif::Transaction::new(tx_id);

    // Set raw transaction data
    if !tx.unparsed_data().is_empty() {
        zewif_tx.set_raw(tx.unparsed_data().clone());
    }

    // Add transaction metadata

    // Extract block hash if available
    let hash_block = tx.hash_block();
    if hash_block != u256::default() {
        // If the hash_block is not zero, the transaction is confirmed
        zewif_tx.set_block_hash(hash_block);

        // Set transaction status to confirmed
        zewif_tx.set_status(zewif::TransactionStatus::Confirmed);

        // Note: Block height would normally be derived by looking up the hash in a chain index
        // We don't have that capability here, but we could in future add a translation table
        // TODO: Add block height lookup when chain access is available
    } else {
        // Transaction is not confirmed
        zewif_tx.set_status(zewif::TransactionStatus::Pending);
    }

    // Extract timestamp
    let tx_time = tx.time_received();
    if tx_time > 0 {
        let timestamp = zewif::SecondsSinceEpoch::from(tx_time as u64);
        zewif_tx.set_timestamp(timestamp);
    }

    // Convert transparent inputs
    for tx_in in tx.vin() {
        let zewif_tx_in = zewif::TxIn::new(
            zewif::TxOutPoint::new(tx_in.prevout().txid(), tx_in.prevout().vout()),
            tx_in.script_sig().clone(),
            tx_in.sequence(),
        );
        zewif_tx.add_input(zewif_tx_in);
    }

    // Convert transparent outputs
    for tx_out in tx.vout() {
        let amount = tx_out.value();
        let script_pubkey = tx_out.script_pub_key().clone();

        let zewif_tx_out = zewif::TxOut::new(amount, script_pubkey);
        zewif_tx.add_output(zewif_tx_out);
    }

    // Access sapling note data hashmap for witness information if available
    let sapling_note_data = tx.sapling_note_data();

    // Convert Sapling spends and outputs
    match tx.sapling_bundle() {
        crate::SaplingBundle::V4(bundle_v4) => {
            // Convert Sapling spends
            for (idx, spend) in bundle_v4.spends().iter().enumerate() {
                let mut sapling_spend = zewif::sapling::SaplingSpendDescription::new();
                sapling_spend.set_spend_index(idx as u32);
                sapling_spend.set_value(Some(bundle_v4.amount()));
                sapling_spend.set_nullifier(spend.nullifier());
                sapling_spend.set_zkproof(spend.zkproof().clone());

                // We don't need to handle witness data for spends as they're already spent notes
                // We'll implement this in the future if needed

                zewif_tx.add_sapling_spend(sapling_spend);
            }

            // Convert Sapling outputs
            for (idx, output) in bundle_v4.outputs().iter().enumerate() {
                let mut sapling_output = zewif::sapling::SaplingOutputDescription::new();
                sapling_output.set_output_index(idx as u32);
                sapling_output.set_commitment(output.cmu());
                sapling_output.set_ephemeral_key(output.ephemeral_key());
                sapling_output.set_enc_ciphertext(output.enc_ciphertext().clone());

                // Find the matching note data for this output if available
                if let Some(note_data_map) = sapling_note_data {
                    for (outpoint, note_data) in note_data_map {
                        // Match output by commitment and position in the transaction
                        // (Finding exact output match may require more complex lookups in practice)
                        if outpoint.vout() == idx as u32 && outpoint.txid() == tx_id {
                            // Add witness data if available
                            if !note_data.witnesses().is_empty() {
                                // Get the best witness (the last one)
                                if let Some(witness) = note_data.witnesses().last() {
                                    // For the anchor, we would normally use the Merkle root
                                    // Since we don't have direct access to it, we'll create a placeholder
                                    // for now and improve it in a future implementation
                                    let anchor = u256::default();
                                    sapling_output.set_witness(Some((anchor, witness.clone())));
                                }
                            }

                            // We don't extract or decrypt memo fields during migration
                            // The memo is inside the encrypted ciphertext, but we preserve
                            // the whole ciphertext in the output description
                            // The receiving wallet is responsible for decrypting
                            // and extracting the memo with the appropriate keys
                            sapling_output.set_memo(None);

                            break;
                        }
                    }
                }

                zewif_tx.add_sapling_output(sapling_output);
            }
        }
        crate::SaplingBundle::V5(bundle_v5) => {
            // Processing for V5 bundles
            for (idx, spend) in bundle_v5.shielded_spends().iter().enumerate() {
                let mut sapling_spend = zewif::sapling::SaplingSpendDescription::new();
                sapling_spend.set_spend_index(idx as u32);
                sapling_spend.set_nullifier(spend.nullifier());
                sapling_spend.set_zkproof(spend.zkproof().clone());

                // We don't need to handle witness data for spends as they're already spent notes
                // We'll implement this in the future if needed

                zewif_tx.add_sapling_spend(sapling_spend);
            }

            for (idx, output) in bundle_v5.shielded_outputs().iter().enumerate() {
                let mut sapling_output = zewif::sapling::SaplingOutputDescription::new();
                sapling_output.set_output_index(idx as u32);
                sapling_output.set_commitment(output.cmu());
                sapling_output.set_ephemeral_key(output.ephemeral_key());
                sapling_output.set_enc_ciphertext(output.enc_ciphertext().clone());

                // Find the matching note data for this output if available
                if let Some(note_data_map) = sapling_note_data {
                    for (outpoint, note_data) in note_data_map {
                        // Match output by commitment and position in the transaction
                        if outpoint.vout() == idx as u32 && outpoint.txid() == tx_id {
                            // Add witness data if available
                            if !note_data.witnesses().is_empty() {
                                // Get the best witness (the last one)
                                if let Some(witness) = note_data.witnesses().last() {
                                    // For V5 bundle, we might not have a direct anchor available
                                    // We'll use a default anchor value for now and improve this
                                    // in a future implementation
                                    let anchor = u256::default();
                                    sapling_output.set_witness(Some((anchor, witness.clone())));
                                }
                            }

                            // We don't extract or decrypt memo fields during migration
                            // The memo is inside the encrypted ciphertext, but we preserve
                            // the whole ciphertext in the output description
                            // The receiving wallet is responsible for decrypting
                            // and extracting the memo with the appropriate keys
                            sapling_output.set_memo(None);

                            break;
                        }
                    }
                }

                zewif_tx.add_sapling_output(sapling_output);
            }
        }
    }

    // Convert Orchard actions
    if let Some(orchard_bundle) = tx.orchard_bundle().inner() {
        // Get Orchard transaction metadata which may contain witness information
        let orchard_tx_meta = tx.orchard_tx_meta();

        for (idx, action) in orchard_bundle.actions.iter().enumerate() {
            let mut orchard_action = zewif::OrchardActionDescription::new();
            orchard_action.set_action_index(idx as u32);
            orchard_action.set_nullifier(action.nf_old());
            orchard_action.set_commitment(action.cmx());
            orchard_action.set_enc_ciphertext(action.encrypted_note().enc_ciphertext().clone());

            // Extract witness data from Orchard metadata if available
            if let Some(meta) = orchard_tx_meta {
                // Currently we don't have direct access to the Orchard witness data
                // This will be implemented in the future when we have access to the proper API

                // The action_data is available but we can't extract witness data from it yet
                let _action_data = meta.action_data(idx as u32);

                // We don't extract or decrypt memo fields during migration
                // The memo is inside the encrypted ciphertext, but we preserve
                // the whole ciphertext in the action description
                // The receiving wallet is responsible for decrypting
                // and extracting the memo with the appropriate keys
                orchard_action.set_memo(None);
            }

            zewif_tx.add_orchard_action(orchard_action);
        }
    }

    // Convert Sprout JoinSplits if present
    if let Some(join_splits) = tx.join_splits() {
        for js in join_splits.descriptions() {
            let join_split = zewif::JoinSplitDescription::new(
                js.anchor(),
                js.nullifiers(),
                js.commitments(),
                js.zkproof().clone(),
            );
            zewif_tx.add_sprout_joinsplit(join_split);
        }
    }

    Ok(zewif_tx)
}
