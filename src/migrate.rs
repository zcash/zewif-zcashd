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

    // Check if we have recipient mappings for this transaction
    if let Some(recipients) = wallet.send_recipients().get(&tx_id) {
        for recipient in recipients {
            // Add the unified address if it exists
            if !recipient.unified_address.is_empty() {
                addresses.insert(recipient.unified_address.clone());
            }

            // Add the recipient address based on the type
            match &recipient.recipient_address {
                super::RecipientAddress::Sapling(addr) => {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str);
                }
                super::RecipientAddress::Orchard(addr) => {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str);
                }
                super::RecipientAddress::KeyId(key_id) => {
                    // Convert P2PKH key hash to a Zcash address
                    let addr_str = key_id.to_string(wallet.network());
                    addresses.insert(addr_str);
                }
                super::RecipientAddress::ScriptId(script_id) => {
                    // Convert P2SH script hash to a Zcash address
                    let addr_str = script_id.to_string(wallet.network());
                    addresses.insert(addr_str);
                }
            }
        }
    }

    // For transparent inputs, extract addresses from the script signatures
    for tx_in in tx.vin() {
        // We'll derive a unique identifier from the previous outpoint to ensure we capture this transaction
        let txid_str = format!("{}", tx_in.prevout().txid());
        let input_addr = format!("input:{}:{}", txid_str, tx_in.prevout().vout());
        addresses.insert(input_addr);

        // Extract potential P2PKH or P2SH addresses from script signatures
        let script_data = tx_in.script_sig();

        // We're looking for common script signature patterns that might contain addresses
        // P2PKH scriptSigs typically have format: <sig> <pubkey>
        // P2SH scriptSigs typically have format: <...> <redeemscript>

        // For P2PKH signatures, the pubkey is near the end and we can extract it
        if script_data.len() > 33 {
            // Minimum size for a compressed pubkey (33 bytes)
            let potential_pubkey = &script_data[script_data.len() - 33..];

            // Check if it could be a compressed pubkey (starts with 0x02 or 0x03)
            if potential_pubkey[0] == 0x02 || potential_pubkey[0] == 0x03 {
                // Hash the pubkey to get the pubkey hash (RIPEMD160(SHA256(pubkey)))
                // First calculate SHA256 hash
                let mut sha256 = Sha256::new();
                sha256.update(potential_pubkey);
                let sha256_result = sha256.finalize();

                // Calculate RIPEMD160 hash of the SHA256 result
                let mut ripemd160 = Ripemd160::new();
                ripemd160.update(sha256_result);
                let pubkey_hash = ripemd160.finalize();

                // Create a transparent P2PKH address from this pubkey hash
                // Create a KeyId for consistent address encoding
                let key_id = super::KeyId::from(
                    u160::from_slice(&pubkey_hash[..]).expect("Creating u160 from RIPEMD160 hash"),
                );
                addresses.insert(key_id.to_string(wallet.network()));
            }
        }
    }

    // For transparent outputs, extract addresses from the scriptPubKey
    for (vout_idx, tx_out) in tx.vout().iter().enumerate() {
        let script_data = tx_out.script_pub_key();

        // P2PKH detection - match the pattern: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        if script_data.len() >= 25 && script_data[0] == 0x76 && script_data[1] == 0xA9 {
            if script_data.len() >= 25 && script_data[23] == 0x88 && script_data[24] == 0xAC {
                // The pubkey hash is 20 bytes starting at offset 3
                let pubkey_hash = &script_data[3..23];

                // Convert to a proper P2PKH Zcash address using KeyId
                let key_id = super::KeyId::from(
                    u160::from_slice(pubkey_hash).expect("Creating u160 from pubkey hash"),
                );
                addresses.insert(key_id.to_string(wallet.network()));
            }
        }
        // P2SH detection - match the pattern: OP_HASH160 <scriptHash> OP_EQUAL
        else if script_data.len() >= 23
            && script_data[0] == 0xA9
            && script_data.len() >= 23
            && script_data[22] == 0x87
        {
            // The script hash is 20 bytes starting at offset 2
            let script_hash = &script_data[2..22];

            // Convert to a proper P2SH Zcash address using ScriptId
            let script_id = super::ScriptId::from(
                u160::from_slice(script_hash).expect("Creating u160 from script hash"),
            );
            addresses.insert(script_id.to_string(wallet.network()));
        }

        // Always add an output identifier that links to this transaction
        let output_addr = format!("output:{}:{}", tx_id, vout_idx);
        addresses.insert(output_addr);
    }

    // For Sapling spends and outputs
    match tx.sapling_bundle() {
        super::SaplingBundle::V4(bundle_v4) => {
            for spend in bundle_v4.spends() {
                // The nullifier uniquely identifies the spend
                // Use AsRef to get a reference to the underlying bytes
                let nullifier_hex = format!("{}", spend.nullifier());
                addresses.insert(format!("sapling_spend:{}", nullifier_hex));

                // If we have note data for this nullifier, we might find the address
                if let Some(sapling_note_data) = tx.sapling_note_data() {
                    for note_data in sapling_note_data.values() {
                        if let Some(nullifier) = note_data.nullifer() {
                            if nullifier == spend.nullifier() {
                                // Find the address for this viewing key
                                for (addr, ivk) in wallet.sapling_z_addresses() {
                                    if note_data.incoming_viewing_key() == ivk {
                                        let addr_str = addr.to_string(wallet.network());
                                        addresses.insert(addr_str);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for output in bundle_v4.outputs() {
                // The commitment uniquely identifies the output
                // Use AsRef to get a reference to the underlying bytes
                let cm_hex = hex::encode(output.cmu().as_ref() as &[u8]);
                addresses.insert(format!("sapling_output:{}", cm_hex));

                // If we have note data for this output, we might find the address
                if let Some(sapling_note_data) = tx.sapling_note_data() {
                    for note_data in sapling_note_data.values() {
                        // We'd need to link the outpoint to this specific output
                        // Since we don't have enough information, we'll use the IVK
                        for (addr, ivk) in wallet.sapling_z_addresses() {
                            if note_data.incoming_viewing_key() == ivk {
                                let addr_str = addr.to_string(wallet.network());
                                addresses.insert(addr_str);
                                break;
                            }
                        }
                    }
                }
            }
        }
        super::SaplingBundle::V5(bundle_v5) => {
            // Similar processing for V5 bundles
            // V5 has the same structure for spends and outputs
            for spend in bundle_v5.shielded_spends() {
                // Use AsRef to get a reference to the underlying bytes
                let nullifier_hex = hex::encode(spend.nullifier().as_ref() as &[u8]);
                addresses.insert(format!("sapling_spend_v5:{}", nullifier_hex));
            }

            for output in bundle_v5.shielded_outputs() {
                // Use AsRef to get a reference to the underlying bytes
                let cm_hex = hex::encode(output.cmu().as_ref() as &[u8]);
                addresses.insert(format!("sapling_output_v5:{}", cm_hex));
            }
        }
    }

    // Process sapling note data directly
    if let Some(sapling_note_data) = tx.sapling_note_data() {
        for note_data in sapling_note_data.values() {
            // If we have the incoming viewing key, we can find the corresponding address
            for (addr, ivk) in wallet.sapling_z_addresses() {
                if note_data.incoming_viewing_key() == ivk {
                    let addr_str = addr.to_string(wallet.network());
                    addresses.insert(addr_str);
                    break;
                }
            }
        }
    }

    // Handle Orchard actions if present
    if let Some(orchard_bundle) = tx.orchard_bundle().inner() {
        // Extract data from Orchard actions
        for (idx, action) in orchard_bundle.actions.iter().enumerate() {
            // Add standard identifiers like nullifier and commitment
            let nullifier_hex = hex::encode(action.nf_old());
            addresses.insert(format!("orchard_nullifier:{}", nullifier_hex));

            // Extract potential address information if available
            if let Some(orchard_meta) = tx.orchard_tx_meta() {
                if let Some(_action_data) = orchard_meta.action_data(idx as u32) {
                    // Try to recover the Orchard address components if we have enough data
                    // We don't have direct access to the receiver's complete address data here,
                    // but in a complete implementation, we'd follow the path:
                    // output_data -> full viewing key -> orchard receiver -> derive address

                    // For now, since we're missing the full path, we'll use what we have
                    // to create a unique identifier that links to metadata
                    let output_id = format!("orchard_output:{}:{}", tx_id, idx);
                    addresses.insert(output_id);

                    // If the outgoing viewing key is related to ours, we can possibly
                    // derive additional information, but that's complex and
                    // would be out of scope for this implementation
                }
            }

            // Include any Orchard address we know of directly (e.g., from recipient mappings)
            // which would have been added already when processing recipient_mappings

            // Also add the action index as a unique identifier
            addresses.insert(format!("orchard_action_idx:{}:{}", tx_id, idx));
        }
    }

    // If the transaction is marked as "from me", and we don't have other identifying information,
    // use all our addresses as potential sources
    if tx.is_from_me() && addresses.is_empty() {
        for addr in wallet.sapling_z_addresses().keys() {
            let addr_str = addr.to_string(wallet.network());
            addresses.insert(addr_str);
        }

        // Also add transparent addresses if any are associated with this wallet
        for addr in wallet.address_names().keys() {
            addresses.insert(addr.clone().into());
        }
    }

    // Add the transaction ID itself as a last resort identifier
    addresses.insert(format!("tx:{}", tx_id));

    Ok(addresses)
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
    // Convert block height if we can infer it from hash_block
    // For this prototype, we'll just leave it as None

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
                zewif_tx.add_sapling_spend(sapling_spend);
            }

            // Convert Sapling outputs
            for (idx, output) in bundle_v4.outputs().iter().enumerate() {
                let mut sapling_output = zewif::sapling::SaplingOutputDescription::new();
                sapling_output.set_output_index(idx as u32);
                sapling_output.set_commitment(output.cmu());
                sapling_output.set_ephemeral_key(output.ephemeral_key());
                sapling_output.set_enc_ciphertext(output.enc_ciphertext().clone());
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
                zewif_tx.add_sapling_spend(sapling_spend);
            }

            for (idx, output) in bundle_v5.shielded_outputs().iter().enumerate() {
                let mut sapling_output = zewif::sapling::SaplingOutputDescription::new();
                sapling_output.set_output_index(idx as u32);
                sapling_output.set_commitment(output.cmu());
                sapling_output.set_ephemeral_key(output.ephemeral_key());
                sapling_output.set_enc_ciphertext(output.enc_ciphertext().clone());
                zewif_tx.add_sapling_output(sapling_output);
            }
        }
    }

    // Convert Orchard actions
    if let Some(orchard_bundle) = tx.orchard_bundle().inner() {
        for (idx, action) in orchard_bundle.actions.iter().enumerate() {
            let mut orchard_action = zewif::OrchardActionDescription::new();
            orchard_action.set_action_index(idx as u32);
            orchard_action.set_nullifier(action.nf_old());
            orchard_action.set_commitment(action.cmx());
            orchard_action.set_enc_ciphertext(action.encrypted_note().enc_ciphertext().clone());
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
        let _addr_id = AddressId::Transparent(zcashd_address.into());

        // TODO: When we have explicit mappings, use those here
        // For now, this will be done in the convert_transparent_addresses function
        // based on the zcashd.address_name key structure
    }

    // Step 3: For each known sapling address, try to find its account
    for sapling_address in wallet.sapling_z_addresses().keys() {
        // Create an AddressId for this sapling address
        let addr_str = sapling_address.to_string(wallet.network());
        let _addr_id = AddressId::Sapling(addr_str);

        // TODO: When we have explicit mappings, use those here
        // For now, this will be done in the convert_sapling_addresses function
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
        let addr_id = AddressId::Transparent(zcashd_address.into());

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
            let transparent_address = zewif::TransparentAddress::new(zcashd_address);

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

                // Determine which accounts the transaction is relevant to
                for address_str in tx_addresses {
                    // Try to convert the address string to an AddressId
                    if let Ok(addr_id) =
                        AddressId::from_address_string(&address_str, wallet.network())
                    {
                        // Look up the account in our registry
                        if let Some(account_id) = address_registry.find_account(&addr_id) {
                            relevant_accounts.insert(*account_id);
                        }
                    }

                    // For any addresses we didn't find in the registry,
                    // we'll rely on the accounts we've already collected
                }

                // If we couldn't determine relevant accounts, add to all accounts as fallback
                if relevant_accounts.is_empty() {
                    for account_id in accounts_map.keys() {
                        relevant_accounts.insert(*account_id);
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
                // Log the error and fall back to adding the transaction to all accounts
                eprintln!("Error analyzing transaction {}: {}", txid, e);
                for account in accounts_map.values_mut() {
                    account.add_relevant_transaction(*txid);
                }
            }
        }
    }

    Ok(accounts_map)
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
fn use_placeholder_positions(
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
