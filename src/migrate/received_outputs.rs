use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use orchard::keys::{IncomingViewingKey as OrchardIvk, Scope};

use zewif::{
    Blob, CommitmentTreeData, ReceivedOutput, ReceivedOutputPool, SaplingOutputData,
    OrchardOutputData, SproutOutputData, TreePosition, TxId,
};

use crate::{
    ZcashdWallet,
    migrate::WalletAccounts,
    zcashd_wallet::{
        IncrementalMerkleTree,
        sapling::{SaplingNoteData, SaplingWitness},
    },
};

/// Attach the wallet's received shielded outputs to the accounts that can view
/// them.
///
/// Sapling and Sprout notes are all attributed to the synthesized legacy
/// account (standalone shielded addresses in zcashd belong to its legacy
/// pool). Orchard notes are routed to the unified account whose incoming
/// viewing key matches the action's, falling back to the legacy account when
/// no account matches.
///
/// Note commitment positions are recorded as [`CommitmentTreeData::Position`].
/// Full incremental witnesses are not reconstructed: zcashd's parsed witness
/// snapshot exposes only raw tree nodes with no path/root derivation, so
/// rebuilding a spec witness would require reimplementing the Sapling/Orchard
/// Merkle hashing. A position plus the account birthday is sufficient for an
/// importer with chain access to rebuild the witness by scanning forward.
///
/// Values, memos, and (for Orchard) nullifiers are omitted: they are
/// recoverable from the raw transaction (which the export carries) plus the
/// viewing key, and extracting them here would require trial decryption.
pub(crate) fn attach_received_outputs(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
) -> Result<()> {
    // account index -> txid -> received outputs
    let mut by_account: HashMap<usize, BTreeMap<TxId, Vec<ReceivedOutput>>> = HashMap::new();
    let legacy_index = accounts.legacy_index;

    let orchard_routes = orchard_ivk_routes(accounts);
    let orchard_positions = orchard_note_positions(wallet);

    for (txid, wtx) in wallet.transactions() {
        // Sapling notes -> legacy account.
        if let Some(note_data) = wtx.sapling_note_data() {
            for (outpoint, nd) in note_data {
                let tree_data = sapling_note_position(nd)
                    .map(|p| CommitmentTreeData::Position(TreePosition::new(p)));
                let nullifier = nd.nullifier().cloned();
                let output = ReceivedOutput::new(
                    outpoint.vout(),
                    ReceivedOutputPool::Sapling(SaplingOutputData::new(tree_data, nullifier)),
                );
                by_account
                    .entry(legacy_index)
                    .or_default()
                    .entry(outpoint.txid())
                    .or_default()
                    .push(output);
            }
        }

        // Orchard actions -> matching unified account (else legacy).
        if let Some(meta) = wtx.orchard_tx_meta() {
            let tx_positions = orchard_positions.get(txid.as_ref());
            for (action_index, ivk) in meta.receiving_keys() {
                let account_index = route_orchard(&orchard_routes, ivk).unwrap_or(legacy_index);
                let tree_data = tx_positions
                    .and_then(|m| m.get(action_index))
                    .map(|p| CommitmentTreeData::Position(TreePosition::new(*p)));
                let output = ReceivedOutput::new(
                    *action_index,
                    ReceivedOutputPool::Orchard(OrchardOutputData::new(tree_data, None)),
                );
                by_account
                    .entry(account_index)
                    .or_default()
                    .entry(*txid)
                    .or_default()
                    .push(output);
            }
        }

        // Sprout notes -> legacy account.
        for (outpoint, nd) in wtx.map_sprout_note_data() {
            let nullifier = nd
                .nullifer()
                .map(|n| Blob::<32>::new(n.into_bytes()));
            let output_index = 2 * outpoint.js() as u32 + outpoint.n() as u32;
            let sprout_txid = TxId::from_bytes(outpoint.hash().into_bytes());
            let output = ReceivedOutput::new(
                output_index,
                ReceivedOutputPool::Sprout(SproutOutputData::new(nullifier)),
            );
            by_account
                .entry(legacy_index)
                .or_default()
                .entry(sprout_txid)
                .or_default()
                .push(output);
        }
    }

    for (account_index, txns) in by_account {
        for (txid, mut outputs) in txns {
            // Deterministic ordering within a transaction: by pool, then by
            // output index (the source note maps have no stable iteration
            // order, and different pools can share an output index).
            outputs.sort_by_key(|o| (pool_rank(o), o.output_index()));
            accounts.accounts[account_index].add_relevant_transaction(txid, outputs);
        }
    }

    Ok(())
}

/// A stable ordering rank for a received output's pool, so that outputs from
/// different pools sharing an output index have a deterministic order.
fn pool_rank(output: &ReceivedOutput) -> u8 {
    match output.pool() {
        ReceivedOutputPool::Transparent(_) => 0,
        ReceivedOutputPool::Sprout(_) => 1,
        ReceivedOutputPool::Sapling(_) => 2,
        ReceivedOutputPool::Orchard(_) => 3,
        _ => 255,
    }
}

/// The external and internal Orchard incoming viewing keys of each unified
/// account, paired with its index in the accounts list.
fn orchard_ivk_routes(accounts: &WalletAccounts) -> Vec<(usize, Vec<OrchardIvk>)> {
    accounts
        .unified
        .iter()
        .map(|(idx, ufvk)| {
            let ivks = ufvk
                .orchard()
                .map(|fvk| vec![fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)])
                .unwrap_or_default();
            (*idx, ivks)
        })
        .collect()
}

fn route_orchard(routes: &[(usize, Vec<OrchardIvk>)], ivk: &OrchardIvk) -> Option<usize> {
    routes
        .iter()
        .find(|(_, ivks)| ivks.iter().any(|k| k == ivk))
        .map(|(idx, _)| *idx)
}

/// Orchard note commitment positions, keyed by raw txid bytes then by action
/// index within the transaction.
fn orchard_note_positions(wallet: &ZcashdWallet) -> HashMap<[u8; 32], HashMap<u32, u64>> {
    let mut out: HashMap<[u8; 32], HashMap<u32, u64>> = HashMap::new();
    for (txid, positions) in wallet.orchard_note_commitment_tree().note_positions() {
        let entry = out.entry(*txid.as_ref()).or_default();
        for (action_index, position) in positions.note_positions() {
            entry.insert(*action_index, u64::from(*position));
        }
    }
    out
}

/// The leaf position of a Sapling note, derived from the size of the note
/// commitment tree captured at the witness's creation (the note is the
/// most-recently-appended leaf, so `position = size - 1`). All cached witnesses
/// share the same creation-time tree, so the first suffices.
fn sapling_note_position(note_data: &SaplingNoteData) -> Option<u64> {
    let witness: &SaplingWitness = note_data.witnesses().first()?;
    merkle_tree_size(witness.tree()).checked_sub(1)
}

/// The number of leaves in a zcashd incremental Merkle tree, computed from its
/// structure: the `left`/`right` leaves plus, for each filled parent at level
/// `i`, the `2^(i+1)` leaves of the completed subtree it roots.
fn merkle_tree_size(tree: &IncrementalMerkleTree) -> u64 {
    let mut size = tree.left().is_some() as u64 + tree.right().is_some() as u64;
    for (i, parent) in tree.parents().iter().enumerate() {
        if parent.is_some() {
            size += 1u64 << (i + 1);
        }
    }
    size
}

#[cfg(test)]
mod tests {
    use super::merkle_tree_size;
    use crate::zcashd_wallet::{u256, IncrementalMerkleTree};

    fn node() -> u256 {
        u256::try_from(&[1u8; 32]).unwrap()
    }

    #[test]
    fn empty_tree_has_size_zero() {
        assert_eq!(merkle_tree_size(&IncrementalMerkleTree::new()), 0);
    }

    #[test]
    fn single_leaf_tree_has_size_one() {
        let mut tree = IncrementalMerkleTree::new();
        tree.set_left(node());
        assert_eq!(merkle_tree_size(&tree), 1);
    }

    #[test]
    fn two_leaves_have_size_two() {
        let mut tree = IncrementalMerkleTree::new();
        tree.set_left(node());
        tree.set_right(node());
        assert_eq!(merkle_tree_size(&tree), 2);
    }

    #[test]
    fn filled_parents_count_completed_subtrees() {
        // left + right (2 leaves) plus a filled parent at level 0 rooting a
        // completed 2-leaf subtree = 4 leaves; the most recent leaf is at
        // position 3.
        let mut tree = IncrementalMerkleTree::new();
        tree.set_left(node());
        tree.set_right(node());
        tree.push_parent(Some(node()));
        assert_eq!(merkle_tree_size(&tree), 4);

        // 1 leaf plus a filled parent at level 1 rooting a completed 4-leaf
        // subtree = 5 leaves (the most recent leaf is at position 4).
        let mut tree = IncrementalMerkleTree::new();
        tree.set_left(node());
        tree.push_parent(None);
        tree.push_parent(Some(node()));
        assert_eq!(merkle_tree_size(&tree), 1 + 4);
    }
}
