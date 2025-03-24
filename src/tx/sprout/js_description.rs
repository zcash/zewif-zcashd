use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Amount, Anchor, SproutProof, u256};

use super::NoteEncryptionCiphertext;

const ZC_NUM_JS_INPUTS: usize = 2;
const ZC_NUM_JS_OUTPUTS: usize = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct JSDescription {
    vpub_old: Amount,
    vpub_new: Amount,
    anchor: Anchor,
    nullifiers: [u256; ZC_NUM_JS_INPUTS],
    commitments: [u256; ZC_NUM_JS_OUTPUTS],
    ephemeral_key: u256,
    random_seed: u256,
    macs: [u256; ZC_NUM_JS_INPUTS],
    zkproof: SproutProof,
    ciphertexts: [NoteEncryptionCiphertext; ZC_NUM_JS_OUTPUTS],
}

impl JSDescription {
    pub fn vpub_old(&self) -> Amount {
        self.vpub_old
    }

    pub fn vpub_new(&self) -> Amount {
        self.vpub_new
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    pub fn nullifiers(&self) -> [u256; ZC_NUM_JS_INPUTS] {
        self.nullifiers
    }

    pub fn commitments(&self) -> [u256; ZC_NUM_JS_OUTPUTS] {
        self.commitments
    }

    pub fn ephemeral_key(&self) -> u256 {
        self.ephemeral_key
    }

    pub fn random_seed(&self) -> u256 {
        self.random_seed
    }

    pub fn macs(&self) -> [u256; ZC_NUM_JS_INPUTS] {
        self.macs
    }

    pub fn zkproof(&self) -> &SproutProof {
        &self.zkproof
    }

    pub fn ciphertexts(&self) -> &[NoteEncryptionCiphertext; ZC_NUM_JS_OUTPUTS] {
        &self.ciphertexts
    }
}

impl ParseWithParam<bool> for JSDescription {
    fn parse(p: &mut Parser, use_groth: bool) -> Result<Self> {
        Ok(Self {
            vpub_old: parse!(p, "vpub_old")?,
            vpub_new: parse!(p, "vpub_new")?,
            anchor: parse!(p, "anchor")?,
            nullifiers: parse!(p, "nullifiers")?,
            commitments: parse!(p, "commitments")?,
            ephemeral_key: parse!(p, "ephemeral_key")?,
            random_seed: parse!(p, "random_seed")?,
            macs: parse!(p, "macs")?,
            zkproof: parse!(p, param = use_groth, "zkproof")?,
            ciphertexts: parse!(p, "ciphertexts")?,
        })
    }
}
