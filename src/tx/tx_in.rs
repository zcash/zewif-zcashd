use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::Script;

use super::OutPoint;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxIn {
    prevout: OutPoint,
    script_sig: Script,
    sequence: u32,
}

impl TxIn {
    pub fn prevout(&self) -> &OutPoint {
        &self.prevout
    }

    pub fn script_sig(&self) -> &Script {
        &self.script_sig
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }
}

impl Parse for TxIn {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            prevout: parse!(p, "txin prevout")?,
            script_sig: parse!(p, "txin script_sig")?,
            sequence: parse!(p, "txin sequence")?,
        })
    }
}
