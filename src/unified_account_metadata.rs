use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::u256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnifiedAccountMetadata {
    seed_fingerprint: u256,
    bip_44_coin_type: u32,
    account_id: u32,
    key_id: u256,
}

impl UnifiedAccountMetadata {
    pub fn seed_fingerprint(&self) -> u256 {
        self.seed_fingerprint
    }

    pub fn bip_44_coin_type(&self) -> u32 {
        self.bip_44_coin_type
    }

    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    pub fn key_id(&self) -> u256 {
        self.key_id
    }
}

impl Parse for UnifiedAccountMetadata {
    fn parse(p: &mut Parser) -> Result<Self> {
        let seed_fingerprint = parse!(p, "seed_fingerprint")?;
        let bip_44_coin_type = parse!(p, "bip_44_coin_type")?;
        let account_id = parse!(p, "account_id")?;
        let key_id = parse!(p, "key_id")?;
        Ok(Self {
            seed_fingerprint,
            bip_44_coin_type,
            account_id,
            key_id,
        })
    }
}
