use std::collections::HashMap;

use crate::zcashd_wallet::SecondsSinceEpoch;

use super::{PrivKey, PubKey};

#[derive(Clone, PartialEq)]
pub struct WalletKeys(HashMap<PubKey, WalletKey>);

impl WalletKeys {
    pub fn new(map: HashMap<PubKey, WalletKey>) -> Self {
        Self(map)
    }

    pub fn keypairs(&self) -> impl Iterator<Item = &WalletKey> {
        self.0.values()
    }
}

impl std::fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut a = f.debug_list();
        for keypair in self.keypairs() {
            a.entry(keypair);
        }
        a.finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WalletKey {
    pubkey: PubKey,
    privkey: PrivKey,
    time_created: SecondsSinceEpoch,
    time_expires: SecondsSinceEpoch,
    comment: String,
}

impl WalletKey {
    pub fn new(
        pubkey: PubKey,
        privkey: PrivKey,
        time_created: SecondsSinceEpoch,
        time_expires: SecondsSinceEpoch,
        comment: String,
    ) -> Self {
        Self {
            pubkey,
            privkey,
            time_created,
            time_expires,
            comment,
        }
    }

    pub fn pubkey(&self) -> &PubKey {
        &self.pubkey
    }

    pub fn privkey(&self) -> &PrivKey {
        &self.privkey
    }

    pub fn time_created(&self) -> SecondsSinceEpoch {
        self.time_created
    }

    pub fn time_expires(&self) -> SecondsSinceEpoch {
        self.time_expires
    }

    pub fn comment(&self) -> &String {
        &self.comment
    }
}
