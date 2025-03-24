use std::collections::HashMap;

use zewif::u256;

use super::{UnifiedAccountMetadata, UnifiedAddressMetadata};

#[derive(Debug, Clone, PartialEq)]
pub struct UnifiedAccounts {
    pub address_metadata: HashMap<u256, UnifiedAddressMetadata>,
    pub full_viewing_keys: HashMap<u256, String>,
    pub account_metadata: HashMap<u256, UnifiedAccountMetadata>,
}

impl UnifiedAccounts {
    pub fn new(
        address_metadata: HashMap<u256, UnifiedAddressMetadata>,
        full_viewing_keys: HashMap<u256, String>,
        account_metadata: HashMap<u256, UnifiedAccountMetadata>,
    ) -> Self {
        Self {
            address_metadata,
            full_viewing_keys,
            account_metadata,
        }
    }
}
