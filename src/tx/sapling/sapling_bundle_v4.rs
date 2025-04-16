use anyhow::Result;

use zewif::{Amount, Blob64};
use zewif::{parse, parser::prelude::*};

use super::super::{OutputV4, SpendV4};

#[derive(Debug, Clone, PartialEq)]
pub struct SaplingBundleV4 {
    amount: Amount,
    spends: Vec<SpendV4>,
    outputs: Vec<OutputV4>,
    binding_sig: Option<Blob64>,
}

impl SaplingBundleV4 {
    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn spends(&self) -> &[SpendV4] {
        &self.spends
    }

    pub fn outputs(&self) -> &[OutputV4] {
        &self.outputs
    }

    pub fn binding_sig(&self) -> Option<&Blob64> {
        self.binding_sig.as_ref()
    }

    pub fn set_binding_sig(&mut self, binding_sig: Blob64) {
        self.binding_sig = Some(binding_sig);
    }

    pub fn have_actions(&self) -> bool {
        !(self.spends.is_empty() && self.outputs.is_empty())
    }
}

impl Default for SaplingBundleV4 {
    fn default() -> Self {
        Self {
            amount: Amount::zero(),
            spends: Vec::new(),
            outputs: Vec::new(),
            binding_sig: None,
        }
    }
}

impl Parse for SaplingBundleV4 {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            amount: parse!(p, "amount")?,
            spends: parse!(p, "spends")?,
            outputs: parse!(p, "outputs")?,
            binding_sig: None,
        })
    }
}
