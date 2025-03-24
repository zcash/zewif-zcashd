use anyhow::Result;
use zcash_address::{ToAddress, ZcashAddress};

use zewif::{Network, u160};
use zewif::{parse, parser::prelude::*};

use super::zewif_network_to_zcash_address_network;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(u160);

impl KeyId {
    pub fn to_string(&self, network: Network) -> String {
        // Create proper 20-byte array for the pubkey hash
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(self.0.as_ref());

        // Create a transparent P2PKH address using the proper constructor
        let addr = ZcashAddress::from_transparent_p2pkh(zewif_network_to_zcash_address_network(network), pubkey_hash);
        addr.to_string()
    }
}

impl Parse for KeyId {
    fn parse(p: &mut Parser) -> Result<Self> {
        let key_id = parse!(p, "key_id")?;
        Ok(KeyId(key_id))
    }
}

impl From<u160> for KeyId {
    fn from(key_id: u160) -> Self {
        KeyId(key_id)
    }
}

impl From<KeyId> for u160 {
    fn from(key_id: KeyId) -> Self {
        key_id.0
    }
}
