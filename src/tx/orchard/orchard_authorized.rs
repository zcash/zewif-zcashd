use anyhow::Result;

use zewif::Data;
use zewif::{parse, parser::prelude::*};

use super::RedPallasSignature;

#[derive(Debug, Clone, PartialEq)]
pub struct OrchardAuthorized {
    proof: Data,
    binding_signature: RedPallasSignature,
}

impl OrchardAuthorized {
    pub fn new(proof: Data, binding_signature: RedPallasSignature) -> Self {
        Self { proof, binding_signature }
    }

    pub fn proof(&self) -> &Data {
        &self.proof
    }

    pub fn binding_signature(&self) -> &RedPallasSignature {
        &self.binding_signature
    }
}

impl Parse for OrchardAuthorized {
    fn parse(parser: &mut Parser) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            proof: parse!(parser, "proof")?,
            binding_signature: parse!(parser, "binding_signature")?,
        })
    }
}
