use anyhow::Result;

use zewif::{Amount, Script};
use zewif::{parse, parser::prelude::*};

#[derive(Debug, Clone, PartialEq)]
pub struct TxOut {
    value: Amount,
    script_pub_key: Script,
}

impl TxOut {
    pub fn value(&self) -> Amount {
        self.value
    }

    pub fn script_pub_key(&self) -> &Script {
        &self.script_pub_key
    }
}

impl Parse for TxOut {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            value: parse!(p, "value")?,
            script_pub_key: parse!(p, "script_pub_key")?,
        })
    }
}
