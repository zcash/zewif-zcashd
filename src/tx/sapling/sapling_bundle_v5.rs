use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Amount, Blob64, GrothProof, u256};

use super::{OutputDescription, OutputV5, SpendDescription, SpendV5};

#[derive(Debug, Clone, PartialEq)]
pub struct SaplingBundleV5 {
    shielded_spends: Vec<SpendDescription>,
    shielded_outputs: Vec<OutputDescription>,
    value_balance: Amount,
    authorization: Option<Blob64>,
}

impl SaplingBundleV5 {
    pub fn shielded_spends(&self) -> &Vec<SpendDescription> {
        &self.shielded_spends
    }

    pub fn shielded_outputs(&self) -> &Vec<OutputDescription> {
        &self.shielded_outputs
    }

    pub fn value_balance(&self) -> Amount {
        self.value_balance
    }

    pub fn authorization(&self) -> Option<&Blob64> {
        self.authorization.as_ref()
    }
}

impl Parse for SaplingBundleV5 {
    fn parse(p: &mut Parser) -> Result<Self> {
        let sd_v5s = parse!(p, Vec<SpendV5>, "spends")?;
        let od_v5s = parse!(p, Vec<OutputV5>, "outputs")?;
        let n_spends = sd_v5s.len();
        let n_outputs = od_v5s.len();
        let value_balance = if n_spends > 0 || n_outputs > 0 {
            parse!(p, "amount")?
        } else {
            Amount::zero()
        };

        let anchor = if n_spends > 0 {
            Some(parse!(p, u256, "anchor")?)
        } else {
            None
        };

        let v_spend_proofs: Vec<GrothProof> = parse_fixed_length_vec(p, n_spends)?;
        let v_spend_auth_sigs: Vec<Blob64> = parse_fixed_length_vec(p, n_spends)?;
        let v_output_proofs: Vec<GrothProof> = parse_fixed_length_vec(p, n_outputs)?;

        let binding_sig: Option<Blob64> = if n_spends > 0 || n_outputs > 0 {
            Some(parse!(p, "binding_sig")?)
        } else {
            None
        };

        let shielded_spends = sd_v5s
            .into_iter()
            .zip(v_spend_proofs.into_iter().zip(v_spend_auth_sigs))
            .map(|(sd_5, (zkproof, spend_auth_sig))| {
                // the following `unwrap` is safe because we know n_spends > 0.
                sd_5.into_spend_description(anchor.unwrap(), zkproof, spend_auth_sig)
            })
            .collect();

        let shielded_outputs = od_v5s
            .into_iter()
            .zip(v_output_proofs)
            .map(|(od_5, zkproof)| od_5.into_output_description(zkproof))
            .collect();

        Ok(Self {
            shielded_spends,
            shielded_outputs,
            value_balance,
            authorization: binding_sig,
        })
    }
}
