use std::collections::HashMap;

use zewif::Account;

use crate::zcashd_wallet::UfvkFingerprint;

pub struct AccountRegistry {
    accounts: Vec<Account>,
    key_index: HashMap<UfvkFingerprint, usize>,
}

impl AccountRegistry {
    pub fn empty() -> Self {
        AccountRegistry {
            accounts: vec![],
            key_index: HashMap::new(),
        }
    }

    /// The accounts tracked by this registry.
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Maps a UFVK fingerprint to the index of its account in [`Self::accounts`].
    pub fn key_index(&self) -> &HashMap<UfvkFingerprint, usize> {
        &self.key_index
    }
}
