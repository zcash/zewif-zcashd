use std::collections::HashSet;

use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Blob, ReceiverType, u256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedAddressMetadata {
    pub key_id: u256,
    pub diversifier_index: Blob<11>,
    pub receiver_types: HashSet<ReceiverType>,
}

impl Parse for UnifiedAddressMetadata {
    fn parse(p: &mut Parser) -> Result<Self> {
        let key_id = parse!(p, "key_id")?;
        let diversifier_index = parse!(p, "diversifier_index")?;
        let receiver_types = parse!(p, "receiver_types")?;
        Ok(Self { key_id, diversifier_index, receiver_types })
    }
}
