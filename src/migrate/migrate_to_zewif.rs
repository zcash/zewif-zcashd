use std::collections::HashMap;

use anyhow::Result;

use crate::ZcashdWallet;

use zewif::{self, Account, Position, TxId, ZewifTop, ZewifWallet, u256};

use super::{
    convert_sapling_addresses, convert_seed_material, convert_transactions,
    convert_transparent_addresses, convert_unified_accounts, initialize_address_registry,
};

/// Migrate a ZCashd wallet to the Zewif wallet format
pub fn migrate_to_zewif(wallet: &ZcashdWallet) -> Result<ZewifTop> {
    // Create a new ZewifTop
    let mut zewif_top = ZewifTop::new();

    // Convert seed material (mnemonic phrase)
    let seed_material = convert_seed_material(wallet)?;

    // Create a complete Zewif wallet
    let mut zewif_wallet = ZewifWallet::new(wallet.network());

    if let Some(seed_material) = seed_material {
        zewif_wallet.set_seed_material(seed_material);
    }

    // Process transactions and collect relevant transaction IDs
    let mut transactions = convert_transactions(wallet)?;

    // Convert orchard note commitment tree if available
    if !wallet
        .orchard_note_commitment_tree()
        .unparsed_data()
        .is_empty()
    {
        // Update transaction outputs with note positions from the note commitment tree
        update_transaction_positions(wallet, &mut transactions)?;
    }

    // If there are unified accounts, process them
    if let Some(unified_accounts) = wallet.unified_accounts() {
        // Create accounts based on unified_accounts structure
        let mut accounts_map = convert_unified_accounts(wallet, unified_accounts, &transactions)?;

        // Initialize address registry to track address-to-account relationships
        let address_registry = initialize_address_registry(wallet, unified_accounts)?;

        // Create a default account for addresses not associated with any other account
        let mut default_account = Account::new();
        default_account.set_name("Default Account");

        // Create a mutable reference for accounts_map to use in the conversion functions
        let mut accounts_map_ref = Some(&mut accounts_map);

        // Convert transparent addresses using the registry to assign to correct accounts
        convert_transparent_addresses(
            wallet,
            &mut default_account,
            Some(&address_registry),
            &mut accounts_map_ref,
        )?;

        // Convert sapling addresses using the registry to assign to correct accounts
        convert_sapling_addresses(
            wallet,
            &mut default_account,
            Some(&address_registry),
            &mut accounts_map_ref,
        )?;

        // Add the default account to accounts_map if it has any addresses
        if !default_account.addresses().is_empty() {
            accounts_map.insert(u256::default(), default_account);
        }

        // Add all accounts to the wallet
        for account in accounts_map.values() {
            zewif_wallet.add_account(account.clone());
        }
    } else {
        // No unified accounts - create a single default account
        let mut default_account = Account::new();
        default_account.set_name("Default Account");

        // Create a None reference for accounts_map
        let mut accounts_map_ref = None;

        // Convert transparent addresses (single account mode)
        convert_transparent_addresses(wallet, &mut default_account, None, &mut accounts_map_ref)?;

        // Convert sapling addresses (single account mode)
        convert_sapling_addresses(wallet, &mut default_account, None, &mut accounts_map_ref)?;

        // Add all transaction IDs to the default account's relevant transactions
        for txid in transactions.keys() {
            default_account.add_relevant_transaction(*txid);
        }

        // Add the default account to the wallet
        zewif_wallet.add_account(default_account);
    }

    // Add wallet and transactions to the ZewifTop
    zewif_top.add_wallet(zewif_wallet);
    zewif_top.set_transactions(transactions);

    Ok(zewif_top)
}

/// Update transaction outputs with note positions from the note commitment tree
fn update_transaction_positions(
    wallet: &ZcashdWallet,
    transactions: &mut HashMap<TxId, zewif::Transaction>,
) -> Result<()> {
    // Get the orchard note commitment tree from the wallet
    let note_commitment_tree = wallet.orchard_note_commitment_tree();

    // Check if we have a valid tree to process
    if note_commitment_tree.unparsed_data().is_empty() {
        // No tree data available
        eprintln!("No orchard note commitment tree data found in wallet");
        return Ok(());
    }

    // Parse the tree data if not already parsed
    if !note_commitment_tree.is_fully_parsed() {
        // Get a mutable copy we can parse - this is not optimal but allows us to work with the current API
        let mut tree_clone = note_commitment_tree.clone();
        if let Err(err) = tree_clone.parse_tree_data() {
            eprintln!("Failed to parse orchard note commitment tree: {}", err);
            // Continue with placeholder values if we can't parse the tree
            return use_placeholder_positions(transactions);
        }

        // Get the commitment positions from the parsed tree
        // Log summary information to help with debugging
        eprintln!("{}", tree_clone.get_tree_summary());

        // Get the map of commitment hashes to tree positions
        let commitment_positions = tree_clone.commitment_positions().clone();

        // Update transactions with real commitment positions from the tree
        update_transactions_with_positions(transactions, &commitment_positions)?;
    } else {
        // Tree was already parsed - use its positions directly
        let commitment_positions = note_commitment_tree.commitment_positions().clone();
        update_transactions_with_positions(transactions, &commitment_positions)?;
    }

    Ok(())
}

/// Use placeholder positions when we can't get real position information
pub fn use_placeholder_positions(
    transactions: &mut HashMap<TxId, zewif::Transaction>,
) -> Result<()> {
    eprintln!("Using placeholder positions for outputs (not ideal for production)");

    // Map to collect all actions and their placeholder positions
    let mut orchard_positions: HashMap<u256, Position> = HashMap::new();
    let mut sapling_positions: HashMap<u256, Position> = HashMap::new();

    // Create sequential placeholder positions
    let mut position_counter: u32 = 1; // Start from 1 to avoid Position(0)

    // First pass: collect all commitments and assign sequential positions
    for tx in transactions.values() {
        // Process Orchard actions
        if let Some(orchard_actions) = tx.orchard_actions() {
            for action in orchard_actions {
                let commitment = *action.commitment();
                if let std::collections::hash_map::Entry::Vacant(e) =
                    orchard_positions.entry(commitment)
                {
                    e.insert(Position::from(position_counter));
                    position_counter += 1;
                }
            }
        }

        // Process Sapling outputs
        if let Some(sapling_outputs) = tx.sapling_outputs() {
            for output in sapling_outputs {
                let commitment = *output.commitment();
                if let std::collections::hash_map::Entry::Vacant(e) =
                    sapling_positions.entry(commitment)
                {
                    e.insert(Position::from(position_counter));
                    position_counter += 1;
                }
            }
        }
    }

    // Second pass: update the transactions with our placeholder positions
    let mut all_positions = HashMap::new();
    all_positions.extend(orchard_positions);
    all_positions.extend(sapling_positions);

    update_transactions_with_positions(transactions, &all_positions)?;

    Ok(())
}

/// Update transaction outputs with positions from a position map
fn update_transactions_with_positions(
    transactions: &mut HashMap<TxId, zewif::Transaction>,
    commitment_positions: &HashMap<u256, Position>,
) -> Result<()> {
    // If we have no positions, there's nothing to do
    if commitment_positions.is_empty() {
        eprintln!("No commitment positions found to update transactions");
        return Ok(());
    }

    // Log how many positions we found for debugging
    eprintln!(
        "Found {} commitment positions to apply to transactions",
        commitment_positions.len()
    );

    // For each transaction, update its outputs with the correct positions
    for (_tx_id, tx) in transactions.iter_mut() {
        // Get mutable access to the transaction components

        // Update Orchard actions with positions
        let orchard_actions = tx.orchard_actions_mut();
        if let Some(actions) = orchard_actions {
            for action in actions {
                let commitment = action.commitment();
                if let Some(position) = commitment_positions.get(commitment) {
                    action.set_note_commitment_tree_position(*position);
                }
            }
        }

        // Update Sapling outputs with positions
        let sapling_outputs = tx.sapling_outputs_mut();
        if let Some(outputs) = sapling_outputs {
            for output in outputs {
                let commitment = output.commitment();
                if let Some(position) = commitment_positions.get(commitment) {
                    output.set_note_commitment_tree_position(*position);
                }
            }
        }
    }

    Ok(())
}

impl From<&ZcashdWallet> for Result<ZewifTop> {
    fn from(wallet: &ZcashdWallet) -> Self {
        migrate_to_zewif(wallet)
    }
}
