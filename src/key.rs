use anyhow::{Result, bail};

use zewif::{Data, hash256};

use super::{KeyMetadata, PrivKey, PubKey};

#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    pubkey: PubKey,
    privkey: PrivKey,
    metadata: KeyMetadata,
}

impl Key {
    pub fn pubkey(&self) -> &PubKey {
        &self.pubkey
    }

    pub fn privkey(&self) -> &PrivKey {
        &self.privkey
    }

    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }
}

impl Key {
    pub fn new(pubkey: PubKey, privkey: PrivKey, metadata: KeyMetadata) -> Result<Self> {
        let hash = hash256(Data::concat(&[&pubkey, &privkey]));
        if hash != privkey.hash() {
            bail!("Invalid keypair: pubkey and privkey do not match");
        }
        Ok(Self { pubkey, privkey, metadata })
    }
}
