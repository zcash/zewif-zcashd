use anyhow::Result;

use zewif::u256;
use zewif::{parse, parser::prelude::*};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JSOutPoint {
    hash: u256,
    js: u64,
    n: u8,
}

impl JSOutPoint {
    pub fn hash(&self) -> u256 {
        self.hash
    }

    pub fn js(&self) -> u64 {
        self.js
    }

    pub fn n(&self) -> u8 {
        self.n
    }
}

impl Parse for JSOutPoint {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            hash: parse!(p, "hash")?,
            js: parse!(p, "js")?,
            n: parse!(p, "n")?,
        })
    }
}
