use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Blob, GrothProof, u256};

const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rseed (or rcm prior to ZIP 212)
const AEAD_TAG_SIZE: usize = 16;
const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

const OUT_PLAINTEXT_SIZE: usize = 32 + // pk_d
    32; // esk
const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

#[derive(Debug, Clone, PartialEq)]
pub struct OutputV4 {
    cv: u256,
    cmu: u256,
    ephemeral_key: u256,
    enc_ciphertext: Blob<ENC_CIPHERTEXT_SIZE>,
    out_ciphertext: Blob<OUT_CIPHERTEXT_SIZE>,
    zkproof: GrothProof,
}

impl OutputV4 {
    pub fn cv(&self) -> u256 {
        self.cv
    }

    pub fn cmu(&self) -> u256 {
        self.cmu
    }

    pub fn ephemeral_key(&self) -> u256 {
        self.ephemeral_key
    }

    pub fn enc_ciphertext(&self) -> &Blob<ENC_CIPHERTEXT_SIZE> {
        &self.enc_ciphertext
    }

    pub fn out_ciphertext(&self) -> &Blob<OUT_CIPHERTEXT_SIZE> {
        &self.out_ciphertext
    }

    pub fn zkproof(&self) -> &GrothProof {
        &self.zkproof
    }
}

impl Parse for OutputV4 {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            cv: parse!(p, "cv")?,
            cmu: parse!(p, "cmu")?,
            ephemeral_key: parse!(p, "ephemeral_key")?,
            enc_ciphertext: parse!(p, "enc_ciphertext")?,
            out_ciphertext: parse!(p, "out_ciphertext")?,
            zkproof: parse!(p, "zkproof")?,
        })
    }
}
