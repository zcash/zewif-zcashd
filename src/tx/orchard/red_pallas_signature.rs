use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::u256;

#[derive(Debug, Clone, PartialEq)]
pub struct RedPallasSignature {
    r_bytes: u256,
    s_bytes: u256,
}

impl RedPallasSignature {
    /// Returns the r component of the signature.
    pub fn r_bytes(&self) -> u256 {
        self.r_bytes
    }

    /// Returns the s component of the signature.
    pub fn s_bytes(&self) -> u256 {
        self.s_bytes
    }
}

impl Parse for RedPallasSignature {
    fn parse(parser: &mut Parser) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            r_bytes: parse!(parser, "r_bytes")?,
            s_bytes: parse!(parser, "s_bytes")?,
        })
    }
}
