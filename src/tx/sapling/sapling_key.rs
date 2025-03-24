use anyhow::Result;

use zewif::sapling::{SaplingExtendedSpendingKey, SaplingIncomingViewingKey};

use super::super::super::KeyMetadata;

#[derive(Debug, Clone, PartialEq)]
pub struct SaplingKey {
    ivk: SaplingIncomingViewingKey,
    key: SaplingExtendedSpendingKey,
    metadata: KeyMetadata,
}

impl SaplingKey {
    pub fn new(
        ivk: SaplingIncomingViewingKey,
        key: SaplingExtendedSpendingKey,
        metadata: KeyMetadata,
    ) -> Result<Self> {
        Ok(Self { ivk, key, metadata })
    }

    pub fn ivk(&self) -> &SaplingIncomingViewingKey {
        &self.ivk
    }

    pub fn key(&self) -> &SaplingExtendedSpendingKey {
        &self.key
    }

    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }
}
