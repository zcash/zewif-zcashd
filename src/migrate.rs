use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use ripemd::{Digest, Ripemd160};
use sha2::Sha256;

use super::ZcashdWallet;

use zewif::{
    self, Account, AddressId, AddressRegistry, Position, ProtocolAddress, TxId, ZewifTop,
    ZewifWallet, sapling::SaplingIncomingViewingKey, u160, u256,
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

/// Convert ZCashd mnemonic seed to Zewif SeedMaterial
fn convert_seed_material(wallet: &ZcashdWallet) -> Result<Option<zewif::SeedMaterial>> {
    // Check if we have a mnemonic phrase
    if !wallet.bip39_mnemonic().mnemonic().is_empty() {
        return Ok(Some(zewif::SeedMaterial::Bip39Mnemonic(
            wallet.bip39_mnemonic().mnemonic().clone(),
        )));
    }
    // If no mnemonic, return None
    Ok(None)
}

/// Convert ZCashd transparent addresses to Zewif format
///
/// This function handles transparent address assignment:
/// - If registry is available, tries to map addresses to accounts
/// - Otherwise assigns all addresses to the default account
fn convert_transparent_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<u256, Account>>,
) -> Result<()> {
    // Flag for multi-account mode
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();

    // Process address_names which contain transparent addresses
    for (zcashd_address, name) in wallet.address_names() {
        // Create address components
        let transparent_address = zewif::TransparentAddress::new(zcashd_address.clone());
        let protocol_address = ProtocolAddress::Transparent(transparent_address);
        let mut zewif_address = zewif::Address::new(protocol_address);
        zewif_address.set_name(name.clone());

        // Set purpose if available
        if let Some(purpose) = wallet.address_purposes().get(zcashd_address) {
            zewif_address.set_purpose(purpose.clone());
        }

        // In multi-account mode, try to assign to the correct account
        let mut assigned = false;

        if multi_account_mode {
            let registry = address_registry.unwrap();
            let addr_id = AddressId::Transparent(zcashd_address.clone().into());

            if let Some(account_id) = registry.find_account(&addr_id) {
                if let Some(accounts) = accounts_map.as_mut() {
                    if let Some(target_account) = accounts.get_mut(account_id) {
                        // Add to the specified account
                        target_account.add_address(zewif_address.clone());
                        assigned = true;
                    }
                }
            }
        }

        // If not assigned to an account or in single-account mode, add to default account
        if !assigned {
            default_account.add_address(zewif_address);
        }
    }

    Ok(())
}

/// Convert ZCashd sapling addresses to Zewif format
///
/// This function handles sapling address assignment:
/// - If registry is available, tries to map addresses to accounts
/// - Otherwise assigns all addresses to the default account
fn convert_sapling_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<u256, Account>>,
) -> Result<()> {
    // Flag for multi-account mode
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();

    // Process sapling_z_addresses
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        let address_str = sapling_address.to_string(wallet.network());

        // Create a new ShieldedAddress
        let mut shielded_address = zewif::ShieldedAddress::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(viewing_key.to_owned());

        // Add spending key if available in sapling_keys
        if let Some(sapling_key) = find_sapling_key_for_ivk(wallet, viewing_key) {
            // Convert to Zewif spending key format
            let spending_key = convert_sapling_spending_key(sapling_key.key())
                .context("Failed to convert sapling spending key")?;
            shielded_address.set_spending_key(spending_key);
        }

        let protocol_address = zewif::ProtocolAddress::Shielded(shielded_address);
        let mut zewif_address = zewif::Address::new(protocol_address);

        // Set purpose if available - convert to Address type for lookup
        let zcashd_address = super::Address::from(address_str.clone());
        if let Some(purpose) = wallet.address_purposes().get(&zcashd_address) {
            zewif_address.set_purpose(purpose.clone());
        }

        // In multi-account mode, try to assign to the correct account
        let mut assigned = false;

        if multi_account_mode {
            let registry = address_registry.unwrap();
            let addr_id = AddressId::Sapling(address_str.clone());

            if let Some(account_id) = registry.find_account(&addr_id) {
                if let Some(accounts) = accounts_map.as_mut() {
                    if let Some(target_account) = accounts.get_mut(account_id) {
                        // Add to the specified account
                        target_account.add_address(zewif_address.clone());
                        assigned = true;
                    }
                }
            }
        }

        // If not assigned to an account or in single-account mode, add to default account
        if !assigned {
            default_account.add_address(zewif_address);
        }
    }

    Ok(())
}

/// Find a SaplingKey for a given incoming viewing key
fn find_sapling_key_for_ivk<'a>(
    wallet: &'a ZcashdWallet,
    ivk: &SaplingIncomingViewingKey,
) -> Option<&'a super::SaplingKey> {
    wallet.sapling_keys().get(ivk)
}

/// Convert ZCashd SaplingExtendedSpendingKey to Zewif SpendingKey
fn convert_sapling_spending_key(
    key: &zewif::sapling::SaplingExtendedSpendingKey,
) -> Result<zewif::SpendingKey> {
    // Create the Sapling spending key with all components including HD parameters
    // Since both structures use u256, we can directly use them without cloning
    let spending_key = zewif::SpendingKey::new_sapling_extended(
        key.expsk.ask,
        key.expsk.nsk,
        key.expsk.ovk,
        key.depth,
        key.parent_fvk_tag,
        key.child_index,
        key.chain_code,
        key.dk,
    );

    Ok(spending_key)
}

/// Extract all addresses involved in a transaction
fn extract_transaction_addresses(
    wallet: &ZcashdWallet,
    tx_id: TxId,
    tx: &super::WalletTx,
) -> Result<HashSet<String>> {
    let mut addresses = HashSet::new();
    let mut is_change_transaction = false;

    // Check if we have recipient mappings for this transaction
    if let Some(recipients) = wallet.send_recipients().get(&tx_id) {
        for recipient in recipients {
            // Add the unified address if it exists
            if !recipient.unified_address.is_empty() {
                addresses.insert(recipient.unified_address.clone());

                // Add a special tag to track unified addresses specifically
                addresses.insert(format!("ua:{}", recipient.unified_address.clone()));
            }

            // Add the recipient address based on the type
            match &recipient.recipient_address {
                super::RecipientAddress::Sapling(addr) => {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str.clone());
                    addresses.insert(format!("sapling_addr:{}", addr_str));
                }
                super::RecipientAddress::Orchard(addr) => {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str.clone());
                    addresses.insert(format!("orchard_addr:{}", addr_str));
                }
                super::RecipientAddress::KeyId(key_id) => {
                    // Convert P2PKH key hash to a Zcash address
                    let addr_str = key_id.to_string(wallet.network());
                    addresses.insert(addr_str.clone());
                    addresses.insert(format!("transparent_addr:{}", addr_str));
                }
                super::RecipientAddress::ScriptId(script_id) => {
                    // Convert P2SH script hash to a Zcash address
                    let addr_str = script_id.to_string(wallet.network());
                    addresses.insert(addr_str.clone());
                    addresses.insert(format!("transparent_script_addr:{}", addr_str));
                }
            }

            // Check if this is an internal address (change transaction)
            if !recipient.unified_address.is_empty() {
                if let Some(unified_accounts) = wallet.unified_accounts() {
                    // Check if this unified address belongs to our wallet
                    for addr_metadata in unified_accounts.address_metadata.values() {
                        // If we find this address in our metadata, it's likely a change address
                        if format!("{}", addr_metadata.key_id) == recipient.unified_address {
                            is_change_transaction = true;
                            addresses.insert(format!("change:{}", recipient.unified_address));
                            break;
                        }
                    }
                }
            }
        }
    }

    // For transparent inputs, extract addresses from the script signatures
    for tx_in in tx.vin() {
        // Track the previous transaction
        let txid_str = format!("{}", tx_in.prevout().txid());
        let input_addr = format!("input:{}:{}", txid_str, tx_in.prevout().vout());
        addresses.insert(input_addr);

        // Extract potential P2PKH or P2SH addresses from script signatures
        let script_data = tx_in.script_sig();

        // For P2PKH signatures, extract the pubkey
        if script_data.len() > 33 {
            // Check for compressed pubkey
            let potential_pubkey = &script_data[script_data.len() - 33..];
            if potential_pubkey[0] == 0x02 || potential_pubkey[0] == 0x03 {
                // Hash the pubkey to get the pubkey hash
                let mut sha256 = Sha256::new();
                sha256.update(potential_pubkey);
                let sha256_result = sha256.finalize();

                let mut ripemd160 = Ripemd160::new();
                ripemd160.update(sha256_result);
                let pubkey_hash = ripemd160.finalize();

                // Create a transparent P2PKH address
                let key_id = super::KeyId::from(
                    u160::from_slice(&pubkey_hash[..]).expect("Creating u160 from RIPEMD160 hash"),
                );
                let addr_str = key_id.to_string(wallet.network());
                addresses.insert(addr_str.clone());
                addresses.insert(format!("transparent_spend:{}", addr_str));

                // Check if this is one of our keys to better determine ownership
                for key in wallet.keys().keypairs() {
                    // Cannot directly convert PubKey to Address, so we'll check differently
                    // Get the address from our address book that might match this key
                    for (address, _) in wallet.address_names().iter() {
                        if address.to_string() == addr_str {
                            addresses.insert(format!("our_key:{}", addr_str));

                            // If we have an HD path, we can determine if this is change
                            if let Some(hd_path) = key.metadata().hd_keypath() {
                                if hd_path.contains("/1'/") || hd_path.contains("/1/") {
                                    // This is an internal key path, so this is likely change
                                    is_change_transaction = true;
                                    addresses.insert(format!("change_key:{}", addr_str));
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // For transparent outputs, extract addresses
    for (vout_idx, tx_out) in tx.vout().iter().enumerate() {
        let script_data = tx_out.script_pub_key();
        let mut output_address = String::new();

        // P2PKH detection
        if script_data.len() >= 25 && script_data[0] == 0x76 && script_data[1] == 0xA9 {
            if script_data[23] == 0x88 && script_data[24] == 0xAC {
                // Extract the pubkey hash and create an address
                let pubkey_hash = &script_data[3..23];
                let key_id = super::KeyId::from(
                    u160::from_slice(pubkey_hash).expect("Creating u160 from pubkey hash"),
                );
                let addr_str = key_id.to_string(wallet.network());
                addresses.insert(addr_str.clone());
                addresses.insert(format!("transparent_output:{}", addr_str));
                output_address = addr_str;
            }
        }
        // P2SH detection
        else if script_data.len() >= 23 && script_data[0] == 0xA9 && script_data[22] == 0x87 {
            // Extract the script hash and create an address
            let script_hash = &script_data[2..22];
            let script_id = super::ScriptId::from(
                u160::from_slice(script_hash).expect("Creating u160 from script hash"),
            );
            let addr_str = script_id.to_string(wallet.network());
            addresses.insert(addr_str.clone());
            addresses.insert(format!("transparent_script_output:{}", addr_str));
            output_address = addr_str;
        }

        // Check if this output is change
        if !output_address.is_empty() {
            // If this is our address and tx is from us, this is likely change
            if tx.is_from_me() && wallet.address_names().keys().any(|a| a.to_string() == output_address) {
                // Check if this address isn't in our address book (typical of change addresses)
                if is_likely_change_output(wallet, &output_address) {
                    is_change_transaction = true;
                    addresses.insert(format!("change_output:{}", output_address));
                }
            }
        }

        // Track all outputs
        let output_id = format!("output:{}:{}", tx_id, vout_idx);
        addresses.insert(output_id);
    }

    // Process Sapling spends and outputs with improved nullifier tracking
    match tx.sapling_bundle() {
        super::SaplingBundle::V4(bundle_v4) => {
            for spend in bundle_v4.spends() {
                // Track the nullifier
                let nullifier_hex = format!("{}", spend.nullifier());
                addresses.insert(format!("sapling_nullifier:{}", nullifier_hex));

                // If we have note data for this nullifier, find the address
                if let Some(sapling_note_data) = tx.sapling_note_data() {
                    for note_data in sapling_note_data.values() {
                        if let Some(nullifier) = note_data.nullifer() {
                            if nullifier == spend.nullifier() {
                                // Find the address and tag it as a spend
                                for (addr, ivk) in wallet.sapling_z_addresses() {
                                    if note_data.incoming_viewing_key() == ivk {
                                        let addr_str = addr.to_string(wallet.network());
                                        addresses.insert(addr_str.clone());
                                        addresses.insert(format!("sapling_spend:{}", addr_str));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for output in bundle_v4.outputs() {
                // Track the commitment
                let cm_hex = hex::encode(output.cmu().as_ref() as &[u8]);
                addresses.insert(format!("sapling_commitment:{}", cm_hex));

                // If we have note data for this output, find the address
                if let Some(sapling_note_data) = tx.sapling_note_data() {
                    for note_data in sapling_note_data.values() {
                        for (addr, ivk) in wallet.sapling_z_addresses() {
                            if note_data.incoming_viewing_key() == ivk {
                                let addr_str = addr.to_string(wallet.network());
                                addresses.insert(addr_str.clone());
                                addresses.insert(format!("sapling_receive:{}", addr_str));
                                break;
                            }
                        }
                    }
                }
            }
        }
        super::SaplingBundle::V5(bundle_v5) => {
            for spend in bundle_v5.shielded_spends() {
                let nullifier_hex = hex::encode(spend.nullifier().as_ref() as &[u8]);
                addresses.insert(format!("sapling_nullifier_v5:{}", nullifier_hex));

                // Also do nullifier-to-address mapping if possible
                for addr in wallet.sapling_z_addresses().keys() {
                    let addr_str = addr.to_string(wallet.network());
                    // Check if this nullifier belongs to our address
                    if is_nullifier_for_address(wallet, &nullifier_hex, &addr_str) {
                        addresses.insert(format!("sapling_spend_v5:{}", addr_str));
                    }
                }
            }

            for output in bundle_v5.shielded_outputs() {
                let cm_hex = hex::encode(output.cmu().as_ref() as &[u8]);
                addresses.insert(format!("sapling_commitment_v5:{}", cm_hex));
            }
        }
    }

    // Process sapling note data more thoroughly
    if let Some(sapling_note_data) = tx.sapling_note_data() {
        for (outpoint, note_data) in sapling_note_data {
            // For each note, find the corresponding address
            for (addr, ivk) in wallet.sapling_z_addresses() {
                if note_data.incoming_viewing_key() == ivk {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str.clone());

                    // Tag as input or output based on outpoint (outpoint is of type JSOutPoint)
                    let outpoint_str = format!("{:?}", outpoint);
                    addresses.insert(format!("sapling_note:{}", outpoint_str));

                    // If this note has a nullifier, it's been spent
                    if note_data.nullifer().is_some() {
                        addresses.insert(format!("sapling_spent_note:{}", addr_str));
                    } else {
                        addresses.insert(format!("sapling_unspent_note:{}", addr_str));
                    }
                    break;
                }
            }
        }
    }

    // Orchard action processing is done after sapling, so we don't need to process sapling note data again here

    // Improved Orchard action processing
    if let Some(orchard_bundle) = tx.orchard_bundle().inner() {
        for (idx, action) in orchard_bundle.actions.iter().enumerate() {
            // Track nullifiers
            let nullifier_hex = hex::encode(action.nf_old());
            addresses.insert(format!("orchard_nullifier:{}", nullifier_hex));

            // Track commitments
            let commitment_hex = hex::encode(action.cmx());
            addresses.insert(format!("orchard_commitment:{}", commitment_hex));

            // Extract additional metadata if available
            if let Some(orchard_meta) = tx.orchard_tx_meta() {
                if let Some(action_data) = orchard_meta.action_data(idx as u32) {
                    // Track action by index
                    addresses.insert(format!("orchard_action:{}:{}", tx_id, idx));

                    // Instead of trying to access note data directly, just track the action
                    // Action data typically contains commitment and value information
                    addresses.insert(format!("orchard_action_data:{}", hex::encode(action_data.as_ref() as &[u8])));


                    // If we have recipient data from the transaction, link it
                    if let Some(recipients) = wallet.send_recipients().get(&tx_id) {
                        for recipient in recipients {
                            if let super::RecipientAddress::Orchard(addr) = &recipient.recipient_address {
                                addresses.insert(format!("orchard_recipient:{}", addr.to_string(wallet.network())));
                            }
                        }
                    }
                }
            }

            // Add the action index as a unique identifier
            addresses.insert(format!("orchard_action_idx:{}:{}", tx_id, idx));
        }
    }

    // Tag transaction type
    if is_change_transaction {
        addresses.insert("transaction_type:change".to_string());
    } else if tx.is_from_me() {
        addresses.insert("transaction_type:send".to_string());
    } else {
        addresses.insert("transaction_type:receive".to_string());
    }

    // If the transaction is marked as "from me" but we don't have specific addresses
    if tx.is_from_me() && !addresses.iter().any(|a| a.starts_with("transparent_spend:") || a.starts_with("sapling_spend:") || a.starts_with("orchard_nullifier:")) {
        // Add all our addresses as potential sources, but mark them as uncertain
        for addr in wallet.sapling_z_addresses().keys() {
            let addr_str = addr.to_string(wallet.network());
            addresses.insert(format!("possible_source:{}", addr_str));
        }

        for addr in wallet.address_names().keys() {
            let addr_str: String = addr.clone().into();
            addresses.insert(format!("possible_source:{}", addr_str));
        }
    }

    // Always add the transaction ID as an identifier
    addresses.insert(format!("tx:{}", tx_id));

    Ok(addresses)
}

/// Check if a nullifier belongs to a specific address
fn is_nullifier_for_address(_wallet: &ZcashdWallet, _nullifier_hex: &str, _address: &str) -> bool {
    // In a production implementation, this would check if the nullifier was derived
    // from notes sent to the given address. For now, this is a placeholder.
    // TODO: Implement proper nullifier-to-address mapping if needed
    false
}

/// Check if an output address is likely a change address
fn is_likely_change_output(wallet: &ZcashdWallet, address: &str) -> bool {
    // In zcashd, change addresses are typically:
    // 1. Addresses that belong to the wallet
    // 2. Not in the address book (no associated name or purpose)
    // 3. Generated from internal key paths (m/44'/x'/y'/1/...)

    // Check if the address belongs to our wallet but has no name or purpose in the address book
    let has_address = wallet.address_names().keys().any(|a| a.to_string() == address);

    if !has_address {
        return false;
    }

    // Check if this address has a name or purpose
    let address_obj = wallet.address_names().keys().find(|a| a.to_string() == address);
    if let Some(addr) = address_obj {
        // If the address has a name or purpose, it's probably not change
        if let Some(name) = wallet.address_names().get(addr) {
            if !name.is_empty() {
                return false;
            }
        }

        if let Some(purpose) = wallet.address_purposes().get(addr) {
            if !purpose.is_empty() {
                return false;
            }
        }
    }

    // If it's in our wallet but doesn't have a name or purpose, it's likely change
    true
}

/// Convert ZCashd transactions to Zewif format
fn convert_transactions(wallet: &ZcashdWallet) -> Result<HashMap<TxId, zewif::Transaction>> {
    let mut transactions = HashMap::new();

    for (tx_id, wallet_tx) in wallet.transactions() {
        let zewif_tx = convert_transaction(*tx_id, wallet_tx)
            .with_context(|| format!("Failed to convert transaction {}", tx_id))?;
        transactions.insert(*tx_id, zewif_tx);
    }

    Ok(transactions)
}

/// Convert a single ZCashd transaction to Zewif format
fn convert_transaction(tx_id: TxId, tx: &super::WalletTx) -> Result<zewif::Transaction> {
    let mut zewif_tx = zewif::Transaction::new(tx_id);

    // Set raw transaction data
    if !tx.unparsed_data().is_empty() {
        zewif_tx.set_raw(tx.unparsed_data().clone());
    }

    // Add basic transaction metadata
    // Note: Block height would be derived from hash_block, but that's
    // not directly available in our implementation at the moment.
    // This would be implemented in a future enhancement.
    
    // Note transaction time for future implementation (to be implemented in "Extract Transaction Metadata" subtask)
    let _time_received = tx.time_received();

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
        super::SaplingBundle::V4(bundle_v4) => {
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
        super::SaplingBundle::V5(bundle_v5) => {
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

/// Find the account ID for a transparent address by looking at key metadata and relationships
fn find_account_for_transparent_address(
    wallet: &ZcashdWallet,
    unified_accounts: &super::UnifiedAccounts,
    address: &super::Address,
) -> Option<u256> {
    // First, check if this is a transparent receiver in a unified address
    // This requires looking up the pub key for this address and finding matching key metadata

    // 1. Look up HD paths and seed fingerprints for all keys
    for key in wallet.keys().keypairs() {
        // We can't directly convert from pubkey to address, so iterate through known addresses
        let addr_str = address.to_string();

        // Check if this address matches any in our address book
        for known_addr in wallet.address_names().keys() {
            if known_addr.to_string() == addr_str {
                // Found the address in our address book. Now check if we can link it to a key/account.

                // Check for HD paths that indicate unified accounts
                if let Some(hd_path) = key.metadata().hd_keypath() {
                    // HD paths for unified accounts follow a pattern like:
                    // m/44'/1'/account'/type'/idx' where:
                    // - account' is the account ID
                    // - type' is 0 for external addresses, 1 for internal (change) addresses
                    // - idx' is the address index

                    // If this is a unified account HD path, we can extract the account ID
                    if is_unified_account_keypath(hd_path) {
                        if let Some(account_id) = extract_account_id_from_keypath(hd_path) {
                            // Look for unified account with this account ID
                            return find_account_key_id_by_account_id(unified_accounts, account_id);
                        }
                    }
                }

                // If we have a key fingerprint, check if it matches any unified account
                if let Some(seed_fp) = key.metadata().seed_fp() {
                    return find_account_key_id_by_seed_fingerprint(unified_accounts, seed_fp);
                }
            }
        }
    }

    None
}

/// Find the account ID for a sapling address by looking at the viewing key relationships
fn find_account_for_sapling_address(
    wallet: &ZcashdWallet,
    unified_accounts: &super::UnifiedAccounts,
    _address: &super::SaplingZPaymentAddress,
    viewing_key: &zewif::sapling::SaplingIncomingViewingKey,
) -> Option<u256> {
    // Look up the full viewing key associated with this incoming viewing key
    if wallet.sapling_keys().get(viewing_key).is_some() {
        // SaplingKey doesn't directly expose metadata or extfvk
        // Instead, we'll rely on viewing key mappings in unified accounts

        // Check full viewing keys mapping in unified accounts
        // Rather than trying to get the FVK string, we'll use the viewing key we already have
        let ivk_str = viewing_key.to_string();
        for (key_id, viewing_key_str) in &unified_accounts.full_viewing_keys {
            // In a real implementation, we'd properly check if this IVK is derived from FVK
            // For now, we'll just check if the strings have some similarity
            if viewing_key_str.contains(&ivk_str) || ivk_str.contains(viewing_key_str) {
                return Some(*key_id);
            }
        }
    }

    None
}

/// Check if a key path follows the unified account pattern
fn is_unified_account_keypath(keypath: &str) -> bool {
    // Typical unified account key path: m/44'/cointype'/account'/type'/idx'
    let parts: Vec<&str> = keypath.split('/').collect();
    parts.len() >= 4 && parts[0] == "m" && parts[1].starts_with("44'")
}

/// Extract account ID from a unified account key path
fn extract_account_id_from_keypath(keypath: &str) -> Option<u32> {
    // Keypath format: m/44'/cointype'/account'/type'/idx'
    let parts: Vec<&str> = keypath.split('/').collect();
    if parts.len() >= 4 {
        if let Some(account_part) = parts.get(3) {
            if let Some(account_str) = account_part.strip_suffix('\'') {
                return account_str.parse::<u32>().ok();
            }
        }
    }
    None
}

/// Find the account key ID based on account ID
fn find_account_key_id_by_account_id(unified_accounts: &super::UnifiedAccounts, account_id: u32) -> Option<u256> {
    for (key_id, account_metadata) in &unified_accounts.account_metadata {
        if account_metadata.account_id() == account_id {
            return Some(*key_id);
        }
    }
    None
}

/// Find the account key ID based on seed fingerprint
fn find_account_key_id_by_seed_fingerprint(unified_accounts: &super::UnifiedAccounts, seed_fp: &zewif::Blob32) -> Option<u256> {
    let seed_fp_hex = hex::encode(seed_fp.as_ref());
    for (key_id, account_metadata) in &unified_accounts.account_metadata {
        // Convert the account's seed fingerprint to hex and compare
        let account_seed_fp_hex = format!("{}", account_metadata.seed_fingerprint());
        if account_seed_fp_hex == seed_fp_hex {
            return Some(*key_id);
        }
    }
    None
}

/// Initialize an AddressRegistry based on the unified accounts data
fn initialize_address_registry(
    wallet: &ZcashdWallet,
    unified_accounts: &super::UnifiedAccounts,
) -> Result<AddressRegistry> {
    let mut registry = AddressRegistry::new();

    // Step 1: Map the unified account addresses to their accounts
    for (address_id, address_metadata) in &unified_accounts.address_metadata {
        // Create an AddressId for this unified account address
        let addr_id = AddressId::from_unified_account_id(*address_id);

        // Register this address with its account's key_id
        registry.register(addr_id, address_metadata.key_id);
    }

    // Step 2: For each known transparent address, try to find its account
    for zcashd_address in wallet.address_names().keys() {
        // Create an AddressId for this transparent address
        let addr_id = AddressId::Transparent(zcashd_address.clone().into());

        // Check key metadata for HD path to determine the account
        if let Some(account_id) = find_account_for_transparent_address(wallet, unified_accounts, zcashd_address) {
            registry.register(addr_id, account_id);
        }
    }

    // Step 3: For each known sapling address, try to find its account
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        // Create an AddressId for this sapling address
        let addr_str = sapling_address.to_string(wallet.network());
        let addr_id = AddressId::Sapling(addr_str);

        // Find the account for this sapling address using its viewing key
        if let Some(account_id) = find_account_for_sapling_address(wallet, unified_accounts, sapling_address, viewing_key) {
            registry.register(addr_id, account_id);
        }
    }

    Ok(registry)
}

/// Convert ZCashd UnifiedAccounts to Zewif accounts
fn convert_unified_accounts(
    wallet: &ZcashdWallet,
    unified_accounts: &super::UnifiedAccounts,
    _transactions: &HashMap<TxId, zewif::Transaction>,
) -> Result<HashMap<u256, Account>> {
    let mut accounts_map = HashMap::new();

    // Step 1: Create an account for each UnifiedAccountMetadata
    for (key_id, account_metadata) in &unified_accounts.account_metadata {
        // Create a new account with the appropriate ZIP-32 account ID
        let mut account = Account::new();

        // Set the account name and ZIP-32 account ID
        let account_name = format!("Account #{}", account_metadata.account_id());
        account.set_name(account_name);
        account.set_zip32_account_id(account_metadata.account_id());

        // Store the account in our map using the key_id as the key
        accounts_map.insert(*key_id, account);
    }

    // If no accounts were created, create a default account
    if accounts_map.is_empty() {
        let mut default_account = Account::new();
        default_account.set_name("Default Account");
        accounts_map.insert(u256::default(), default_account);
    }

    // Step 2: Build an AddressRegistry to track address-to-account mappings
    let address_registry = initialize_address_registry(wallet, unified_accounts)?;

    // Step 3: Process all addresses and assign them to the appropriate accounts

    // Process transparent addresses
    for (zcashd_address, name) in wallet.address_names() {
        // Create an AddressId for this transparent address
        let addr_id = AddressId::Transparent(zcashd_address.clone().into());

        // Try to find which account this address belongs to using our registry
        let account_key_id = if let Some(key_id) = address_registry.find_account(&addr_id) {
            // Found a mapping in the registry
            *key_id
        } else {
            // No mapping found, fall back to the first account
            match accounts_map.keys().next() {
                Some(key) => *key,
                None => u256::default(),
            }
        };

        if let Some(account) = accounts_map.get_mut(&account_key_id) {
            let transparent_address = zewif::TransparentAddress::new(zcashd_address.clone());

            // Create a ZewifAddress from the TransparentAddress
            let protocol_address = ProtocolAddress::Transparent(transparent_address);
            let mut zewif_address = zewif::Address::new(protocol_address);
            zewif_address.set_name(name.clone());

            // Set purpose if available
            if let Some(purpose) = wallet.address_purposes().get(zcashd_address) {
                zewif_address.set_purpose(purpose.clone());
            }

            // Add the address to the account
            account.add_address(zewif_address);
        }
    }

    // Process sapling addresses
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        let address_str = sapling_address.to_string(wallet.network());

        // Create an AddressId for this sapling address
        let addr_id = AddressId::Sapling(address_str.clone());

        // Try to find which account this address belongs to using our registry
        let account_key_id = if let Some(key_id) = address_registry.find_account(&addr_id) {
            // Found a mapping in the registry
            *key_id
        } else {
            // No mapping found, fall back to the first account
            match accounts_map.keys().next() {
                Some(key) => *key,
                None => u256::default(),
            }
        };

        if let Some(account) = accounts_map.get_mut(&account_key_id) {
            let address_str = sapling_address.to_string(wallet.network());

            // Create a new ShieldedAddress
            let mut shielded_address = zewif::ShieldedAddress::new(address_str.clone());
            shielded_address.set_incoming_viewing_key(viewing_key.to_owned());

            // Add spending key if available in sapling_keys
            if let Some(sapling_key) = find_sapling_key_for_ivk(wallet, viewing_key) {
                // Convert to Zewif spending key format
                let spending_key = convert_sapling_spending_key(sapling_key.key())
                    .context("Failed to convert sapling spending key")?;
                shielded_address.set_spending_key(spending_key);
            }

            let protocol_address = zewif::ProtocolAddress::Shielded(shielded_address);
            let mut zewif_address = zewif::Address::new(protocol_address);

            // Set purpose if available - convert to Address type for lookup
            let zcashd_address = super::Address::from(address_str);
            if let Some(purpose) = wallet.address_purposes().get(&zcashd_address) {
                zewif_address.set_purpose(purpose.clone());
            }

            // Add the address to the account
            account.add_address(zewif_address);
        }
    }

    // Step 4: Process viewing keys in unified_accounts
    // Each full_viewing_key entry maps a key_id to a viewing key string
    for (key_id, viewing_key) in &unified_accounts.full_viewing_keys {
        // Find the account for this key_id
        if let Some(account) = accounts_map.get_mut(key_id) {
            // TODO: Process and add the viewing key to the account
            // This will be implemented when we add specific support for viewing keys

            // For now, just log that we have a viewing key for this account
            eprintln!(
                "Found viewing key for account {}: {}",
                account.name(),
                viewing_key
            );

            // Use the registry to find all addresses associated with this account
            let account_addresses = address_registry.find_addresses_for_account(key_id);
            if !account_addresses.is_empty() {
                eprintln!("  Account has {} addresses", account_addresses.len());
            }
        }
    }

    // Step 5: Assign transactions to relevant accounts based on address involvement
    // We'll use our AddressRegistry to find account associations

    // Analyze each transaction to find which addresses are involved
    for (txid, wallet_tx) in wallet.transactions() {
        // Extract all addresses involved in this transaction
        match extract_transaction_addresses(wallet, *txid, wallet_tx) {
            Ok(tx_addresses) => {
                let mut relevant_accounts = HashSet::new();
                let is_change_transaction = tx_addresses.contains("transaction_type:change");
                let transaction_type = if tx_addresses.contains("transaction_type:send") {
                    "send"
                } else if tx_addresses.contains("transaction_type:receive") {
                    "receive"
                } else {
                    "unknown"
                };

                // First pass: Look for explicit account mappings from standard addresses
                for address_str in &tx_addresses {
                    // Check for standard addresses that we can convert to AddressId
                    if let Ok(addr_id) = AddressId::from_address_string(address_str, wallet.network()) {
                        // Look up the account in our registry
                        if let Some(account_id) = address_registry.find_account(&addr_id) {
                            relevant_accounts.insert(*account_id);
                        }
                    }
                }

                // Second pass: Check for tagged addresses with better identifiers
                if relevant_accounts.is_empty() {
                    for address_str in &tx_addresses {
                        // Check for more specific tagged addresses
                        if address_str.starts_with("transparent_spend:") ||
                           address_str.starts_with("sapling_spend:") ||
                           address_str.starts_with("orchard_spend:") {
                            // This is a spending address - may indicate source account
                            let pure_addr = &address_str[(address_str.find(':').unwrap() + 1)..];
                            if let Ok(addr_id) = AddressId::from_address_string(pure_addr, wallet.network()) {
                                if let Some(account_id) = address_registry.find_account(&addr_id) {
                                    relevant_accounts.insert(*account_id);
                                }
                            }
                        } else if address_str.starts_with("transparent_output:") ||
                                  address_str.starts_with("sapling_receive:") ||
                                  address_str.starts_with("orchard_recipient:") {
                            // This is a receiving address
                            let pure_addr = &address_str[(address_str.find(':').unwrap() + 1)..];
                            if let Ok(addr_id) = AddressId::from_address_string(pure_addr, wallet.network()) {
                                if let Some(account_id) = address_registry.find_account(&addr_id) {
                                    relevant_accounts.insert(*account_id);
                                }
                            }
                        } else if address_str.starts_with("change:") || address_str.starts_with("change_key:") || address_str.starts_with("change_output:") {
                            // This is a change address - try to find its account
                            let pure_addr = &address_str[(address_str.find(':').unwrap() + 1)..];
                            if let Ok(addr_id) = AddressId::from_address_string(pure_addr, wallet.network()) {
                                if let Some(account_id) = address_registry.find_account(&addr_id) {
                                    // For change, we add ONLY the source account
                                    relevant_accounts.clear();
                                    relevant_accounts.insert(*account_id);
                                    break;  // Only need the source account for change
                                }
                            }
                        }
                    }
                }

                // If we still don't have accounts, use intelligent fallback strategy
                if relevant_accounts.is_empty() {
                    // Different strategies based on transaction type
                    if is_change_transaction {
                        // For change transactions, try to find the source account
                        if let Some(source_account) = find_source_account_for_transaction(wallet_tx, &tx_addresses, &address_registry) {
                            relevant_accounts.insert(source_account);
                        }
                    } else if transaction_type == "send" {
                        // For send transactions with no clear mappings, look for the source
                        if let Some(source_account) = find_source_account_for_transaction(wallet_tx, &tx_addresses, &address_registry) {
                            relevant_accounts.insert(source_account);
                        }
                    } else if transaction_type == "receive" {
                        // For receives, we could try to find the most likely recipient account
                        // Or fallback to the default account
                        if let Some(default_account) = find_default_account_id(&accounts_map) {
                            relevant_accounts.insert(default_account);
                        }
                    }
                }

                // Last resort: If we still couldn't determine relevant accounts,
                // select a single appropriate account rather than adding to all
                if relevant_accounts.is_empty() {
                    if let Some(default_account) = find_default_account_id(&accounts_map) {
                        // Only add to default account if we have one
                        relevant_accounts.insert(default_account);
                    } else {
                        // Otherwise, use the first account
                        if let Some(account_id) = accounts_map.keys().next() {
                            relevant_accounts.insert(*account_id);
                        }
                    }
                }

                // Add the transaction to relevant accounts
                for account_id in relevant_accounts {
                    if let Some(account) = accounts_map.get_mut(&account_id) {
                        account.add_relevant_transaction(*txid);
                    }
                }
            }
            Err(e) => {
                // Log the error but use a smarter fallback
                eprintln!("Error analyzing transaction {}: {}", txid, e);

                // Even in error cases, try to assign to the default account if possible
                if let Some(default_account_id) = find_default_account_id(&accounts_map) {
                    if let Some(account) = accounts_map.get_mut(&default_account_id) {
                        account.add_relevant_transaction(*txid);
                    }
                } else {
                    // Only as a last resort, add to all accounts
                    for account in accounts_map.values_mut() {
                        account.add_relevant_transaction(*txid);
                    }
                }
            }
        }
    }

    Ok(accounts_map)
}

/// Find the source account for a transaction based on transaction data and extracted addresses
fn find_source_account_for_transaction(
    wallet_tx: &super::WalletTx,
    addresses: &HashSet<String>,
    address_registry: &AddressRegistry,
) -> Option<u256> {
    // Network for parsing addresses - use mainnet as default
    let network = zewif::Network::Main; // WalletTx doesn't expose network directly

    // For outgoing transactions, check if we have explicit spending addresses
    if wallet_tx.is_from_me() {
        for address_str in addresses {
            // First, look for explicitly tagged spend addresses
            if address_str.starts_with("transparent_spend:") ||
               address_str.starts_with("sapling_spend:") ||
               address_str.starts_with("orchard_nullifier:") {

                let pure_addr = &address_str[(address_str.find(':').unwrap() + 1)..];

                // Try to convert to AddressId and find its account
                if let Ok(addr_id) = AddressId::from_address_string(pure_addr, network) {
                    if let Some(account_id) = address_registry.find_account(&addr_id) {
                        return Some(*account_id);
                    }
                }
            }

            // Next, check for change addresses (these are most reliable for source account)
            if address_str.starts_with("change:") || address_str.starts_with("change_key:") || address_str.starts_with("change_output:") {
                let pure_addr = &address_str[(address_str.find(':').unwrap() + 1)..];

                if let Ok(addr_id) = AddressId::from_address_string(pure_addr, network) {
                    if let Some(account_id) = address_registry.find_account(&addr_id) {
                        return Some(*account_id);
                    }
                }
            }
        }
    }

    None
}

/// Find the default account ID from a list of accounts
fn find_default_account_id(accounts_map: &HashMap<u256, Account>) -> Option<u256> {
    // First look for an account named "Default Account"
    for (id, account) in accounts_map {
        if account.name() == "Default Account" {
            return Some(*id);
        }
    }

    // Fallback: use the first account with ID 0
    for (id, account) in accounts_map {
        if account.zip32_account_id() == Some(0) {
            return Some(*id);
        }
    }

    // Last resort: just use the first account
    accounts_map.keys().next().copied()
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
                if let std::collections::hash_map::Entry::Vacant(e) = orchard_positions.entry(commitment) {
                    e.insert(Position::from(position_counter));
                    position_counter += 1;
                }
            }
        }

        // Process Sapling outputs
        if let Some(sapling_outputs) = tx.sapling_outputs() {
            for output in sapling_outputs {
                let commitment = *output.commitment();
                if let std::collections::hash_map::Entry::Vacant(e) = sapling_positions.entry(commitment) {
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
    eprintln!("Found {} commitment positions to apply to transactions", commitment_positions.len());

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