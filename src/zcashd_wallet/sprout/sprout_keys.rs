use std::collections::HashMap;

use super::{SproutPaymentAddress, SproutSpendingKey};

#[derive(Clone, PartialEq)]
pub struct SproutKeys(HashMap<SproutPaymentAddress, SproutSpendingKey>);

impl SproutKeys {
    pub fn new(map: HashMap<SproutPaymentAddress, SproutSpendingKey>) -> Self {
        Self(map)
    }

    pub fn keypairs(&self) -> impl Iterator<Item = &SproutSpendingKey> {
        self.0.values()
    }

    /// Iterates over the `(payment address, spending key)` pairs, exposing the
    /// address needed to key each Sprout secret by its address.
    pub fn iter(&self) -> impl Iterator<Item = (&SproutPaymentAddress, &SproutSpendingKey)> {
        self.0.iter()
    }
}

impl std::fmt::Debug for SproutKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut a = f.debug_list();
        for keypair in self.keypairs() {
            a.entry(keypair);
        }
        a.finish()
    }
}
