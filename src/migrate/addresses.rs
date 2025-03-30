use anyhow::{Result, Context};

use std::collections::HashMap;

use zewif::{u256, Account, AddressId, AddressRegistry, ProtocolAddress, UnifiedAddress};

use crate::ZcashdWallet;

use super::keys::{convert_sapling_spending_key, find_sapling_key_for_ivk};

/// Convert ZCashd transparent addresses to Zewif format
///
/// This function handles transparent address assignment:
/// - If registry is available, tries to map addresses to accounts
/// - Otherwise assigns all addresses to the default account
pub fn convert_transparent_addresses(
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
pub fn convert_sapling_addresses(
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

        // Create a new ShieldedAddress and preserve the incoming viewing key
        // This is critical for maintaining the ability to detect incoming transactions
        // Note: We preserve IVKs but not FVKs, as FVKs can be derived from spending keys when needed
        let mut shielded_address = zewif::ShieldedAddress::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(viewing_key.to_owned()); // Preserve the IVK exactly as in source wallet

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
        let zcashd_address = crate::Address::from(address_str.clone());
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

/// Convert ZCashd unified addresses to Zewif format
///
/// This function handles unified address extraction and assignment:
/// - Extracts unified addresses from UnifiedAddressMetadata
/// - Preserves diversifier indices and receiver types
/// - Assigns unified addresses to appropriate accounts using the registry
pub fn convert_unified_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<u256, Account>>,
) -> Result<()> {
    // Only process if we have unified accounts
    let unified_accounts = match wallet.unified_accounts() {
        Some(ua) => ua,
        None => return Ok(()),
    };

    // Multi-account mode is active when we have both a registry and accounts map
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();

    // Process unified address metadata entries
    for (address_id, metadata) in &unified_accounts.address_metadata {
        // Create a unified address with a placeholder string
        // NOTE: The wallet.dat file does NOT store the complete unified address strings directly.
        // Instead, it stores the metadata (key_id, diversifier_index, receiver_types) needed to
        // derive the actual unified addresses at runtime when the wallet is operational.
        // 
        // In a fully-operational wallet, unified addresses would be derived using:
        // 1. The wallet's keys (spending or viewing keys)
        // 2. The diversifier index stored here
        // 3. Knowledge of which receiver types to include
        //
        // Since we're focused on data preservation rather than operational wallet functionality,
        // we use a placeholder string but correctly preserve the critical derivation metadata
        // (diversifier_index and receiver_types) which is what's actually stored in wallet.dat.
        let id_bytes: &[u8] = address_id.as_ref(); // u256 implements AsRef<[u8]>
        let ua_string = format!("ua:{}", hex::encode(id_bytes));
        let mut unified_address = UnifiedAddress::new(ua_string.clone());

        // Set the diversifier index
        unified_address.set_diversifier_index(metadata.diversifier_index.clone());

        // Set the receiver types
        unified_address.set_receiver_types(metadata.receiver_types.clone());

        // Try to find transparent and sapling components for this unified address
        // from already processed addresses in the wallet

        // Create a unified address protocol address
        let protocol_address = ProtocolAddress::Unified(Box::new(unified_address));
        let mut zewif_address = zewif::Address::new(protocol_address);

        // Set a descriptive name for the unified address
        // Use first 4 bytes of the u256 as a short identifier
        let id_bytes: &[u8] = address_id.as_ref(); // u256 implements AsRef<[u8]>
        let id_prefix = if id_bytes.len() >= 4 {
            &id_bytes[0..4]
        } else {
            id_bytes // In case the bytes are somehow shorter than 4
        };
        zewif_address.set_name(format!("Unified Address {}", hex::encode(id_prefix)));
        
        // Set purpose if available - though we may not have explicit purposes for unified addresses
        // in current wallet structure, this is here for future compatibility
        
        // In multi-account mode, try to assign to the correct account
        let mut assigned = false;

        if multi_account_mode {
            let registry = address_registry.unwrap();
            let addr_id = AddressId::UnifiedAccountAddress(*address_id);

            if let Some(account_id) = registry.find_account(&addr_id) {
                if let Some(accounts) = accounts_map.as_mut() {
                    if let Some(target_account) = accounts.get_mut(account_id) {
                        // Add to the specified account
                        target_account.add_address(zewif_address.clone());
                        assigned = true;
                    }
                }
            } else {
                // Try with the Unified variant if UnifiedAccountAddress didn't work
                let addr_id = AddressId::Unified(ua_string.clone());
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
        }

        // If not assigned to an account or in single-account mode, add to default account
        if !assigned {
            default_account.add_address(zewif_address);
        }
    }

    Ok(())
}