use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::TxId;

pub type SaplingOutPoint = OutPoint;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    txid: TxId,
    vout: u32,
}

impl OutPoint {
    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn vout(&self) -> u32 {
        self.vout
    }
}

impl Parse for OutPoint {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self { txid: parse!(p, "txid")?, vout: parse!(p, "vout")? })
    }
}
