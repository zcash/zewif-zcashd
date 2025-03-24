use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Blob64, GrothProof, u256};

#[derive(Debug, Clone, PartialEq)]
pub struct SpendV5 {
    cv: u256,
    nullifier: u256,
    rk: u256,
}

impl SpendV5 {
    pub fn into_spend_description(
        self,
        anchor: u256,
        zkproof: GrothProof,
        spend_auth_sig: Blob64,
    ) -> SpendDescription {
        SpendDescription {
            cv: self.cv(),
            anchor,
            nullifier: self.nullifier(),
            rk: self.rk(),
            zkproof,
            spend_auth_sig,
        }
    }

    pub fn cv(&self) -> u256 {
        self.cv
    }

    pub fn nullifier(&self) -> u256 {
        self.nullifier
    }

    pub fn rk(&self) -> u256 {
        self.rk
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpendDescription {
    cv: u256,
    anchor: u256,
    nullifier: u256,
    rk: u256,
    zkproof: GrothProof,
    spend_auth_sig: Blob64,
}

impl SpendDescription {
    pub fn nullifier(&self) -> u256 {
        self.nullifier
    }

    pub fn zkproof(&self) -> &GrothProof {
        &self.zkproof
    }
}

impl Parse for SpendV5 {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            cv: parse!(p, "cv")?,
            nullifier: parse!(p, "nullifier")?,
            rk: parse!(p, "rk")?,
        })
    }
}
