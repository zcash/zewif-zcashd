use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Blob, GrothProof, u256};

#[derive(Debug, Clone, PartialEq)]
pub struct SpendV4 {
    cv: u256,
    anchor: u256,
    nullifier: u256,
    rk: u256,
    zkproof: GrothProof,
    spend_auth_sig: Blob<64>,
}

impl SpendV4 {
    pub fn cv(&self) -> u256 {
        self.cv
    }

    pub fn anchor(&self) -> u256 {
        self.anchor
    }

    pub fn nullifier(&self) -> u256 {
        self.nullifier
    }

    pub fn rk(&self) -> u256 {
        self.rk
    }

    pub fn zkproof(&self) -> &GrothProof {
        &self.zkproof
    }

    pub fn spend_auth_sig(&self) -> &Blob<64> {
        &self.spend_auth_sig
    }
}

impl Parse for SpendV4 {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            cv: parse!(p, "cv")?,
            anchor: parse!(p, "anchor")?,
            nullifier: parse!(p, "nullifier")?,
            rk: parse!(p, "rk")?,
            zkproof: parse!(p, "zkproof")?,
            spend_auth_sig: parse!(p, "spend_auth_sig")?,
        })
    }
}
