use std::collections::BTreeMap;

use zewif::AddressBookEntry;

use crate::ZcashdWallet;

/// Build the wallet's address book from zcashd's `name` and `purpose` records,
/// plus the destination unified addresses recorded in `recipientmapping`
/// (tagged as `send`). Entries are keyed by address string and returned in
/// deterministic (address-sorted) order.
pub(crate) fn build_address_book(wallet: &ZcashdWallet) -> Vec<AddressBookEntry> {
    let mut entries: BTreeMap<String, AddressBookEntry> = BTreeMap::new();

    for (address, name) in wallet.address_names() {
        let addr_str: String = address.clone().into();
        let entry = entries
            .entry(addr_str.clone())
            .or_insert_with(|| AddressBookEntry::new(addr_str.clone()));
        if !name.is_empty() {
            entry.set_label(name.clone());
        }
    }

    for (address, purpose) in wallet.address_purposes() {
        let addr_str: String = address.clone().into();
        let entry = entries
            .entry(addr_str.clone())
            .or_insert_with(|| AddressBookEntry::new(addr_str.clone()));
        if !purpose.is_empty() {
            entry.set_purpose(purpose.clone());
        }
    }

    // Destination unified addresses the wallet has sent to.
    for mappings in wallet.send_recipients().values() {
        for mapping in mappings {
            if mapping.unified_address.is_empty() {
                continue;
            }
            let entry = entries
                .entry(mapping.unified_address.clone())
                .or_insert_with(|| AddressBookEntry::new(mapping.unified_address.clone()));
            if entry.purpose().is_none() {
                entry.set_purpose("send");
            }
        }
    }

    entries.into_values().collect()
}
