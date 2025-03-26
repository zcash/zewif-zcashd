use anyhow::{Result, Context};

use std::collections::HashMap;

use zewif::{u256, Account, AddressId, AddressRegistry, ProtocolAddress};

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
