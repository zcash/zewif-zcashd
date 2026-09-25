use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zcash_address::{ToAddress, ZcashAddress};

use crate::{parse, parser::prelude::*, zcashd_wallet::u160};
use zewif::Network;

use crate::migrate::primitives::address_network_from_zewif;

use super::PubKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(u160);

impl KeyId {
    /// The key id of a public key: the RIPEMD-160 of the SHA-256 of the key's
    /// serialization as stored (zcashd's `CPubKey::GetID()`).
    ///
    /// zcashd hashes the stored bytes without normalization, so a key stored
    /// uncompressed has a different id — and P2PKH address — than the same
    /// point stored compressed.
    pub fn from_pubkey(pubkey: &PubKey) -> Self {
        let hash = Ripemd160::digest(Sha256::digest(pubkey.as_slice()));
        let id = u160::from_slice(hash.as_slice()).expect("RIPEMD-160 output is 20 bytes");
        KeyId(id)
    }

    pub fn to_string(&self, network: &Network) -> String {
        // Create proper 20-byte array for the pubkey hash
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(self.0.as_ref());

        // Create a transparent P2PKH address using the proper constructor
        let addr =
            ZcashAddress::from_transparent_p2pkh(address_network_from_zewif(network), pubkey_hash);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Compressed and uncompressed SEC1 serializations of the secp256k1
    /// generator point, with the RIPEMD-160(SHA-256(serialization)) of each:
    /// the standard Bitcoin test vectors for the secret key 1.
    const G_COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const HASH160_G_COMPRESSED: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
    const HASH160_G_UNCOMPRESSED: &str = "91b24bf9f5288532960ac687abb035127b1d28a5";

    fn pubkey(sec1_hex: &str) -> PubKey {
        let bytes = hex::decode(sec1_hex).unwrap();
        // `PubKey` parses from its wallet encoding: a CompactSize length
        // prefix (a single byte for both serialized forms) and the key bytes.
        let mut buf = vec![u8::try_from(bytes.len()).unwrap()];
        buf.extend_from_slice(&bytes);
        PubKey::parse_buf(&buf, false).unwrap()
    }

    fn key_id(hash160_hex: &str) -> KeyId {
        KeyId::from(u160::from_slice(&hex::decode(hash160_hex).unwrap()).unwrap())
    }

    #[test]
    fn from_pubkey_hashes_the_serialization_as_stored() {
        assert_eq!(
            KeyId::from_pubkey(&pubkey(G_COMPRESSED)),
            key_id(HASH160_G_COMPRESSED)
        );
        assert_eq!(
            KeyId::from_pubkey(&pubkey(G_UNCOMPRESSED)),
            key_id(HASH160_G_UNCOMPRESSED)
        );
    }
}
