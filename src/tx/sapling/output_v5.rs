use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::{Blob, GrothProof, u256};

#[derive(Debug, Clone, PartialEq)]
pub struct OutputV5 {
    cv: u256,
    cmu: u256,
    ephemeral_key: u256,
    enc_ciphertext: Blob<580>,
    out_ciphertext: Blob<80>,
}

impl OutputV5 {
    #[allow(dead_code)]
    pub fn cv(&self) -> u256 {
        self.cv
    }

    #[allow(dead_code)]
    pub fn cmu(&self) -> u256 {
        self.cmu
    }

    #[allow(dead_code)]
    pub fn ephemeral_key(&self) -> u256 {
        self.ephemeral_key
    }

    #[allow(dead_code)]
    pub fn enc_ciphertext(&self) -> &Blob<580> {
        &self.enc_ciphertext
    }

    #[allow(dead_code)]
    pub fn out_ciphertext(&self) -> &Blob<80> {
        &self.out_ciphertext
    }
}

impl OutputV5 {
    pub fn into_output_description(self, zkproof: GrothProof) -> OutputDescription {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputDescription {
    cv: u256,
    cmu: u256,
    ephemeral_key: u256,
    enc_ciphertext: Blob<580>,
    out_ciphertext: Blob<80>,
    zkproof: GrothProof,
}

impl OutputDescription {
    pub fn cmu(&self) -> u256 {
        self.cmu
    }

    pub fn ephemeral_key(&self) -> u256 {
        self.ephemeral_key
    }

    pub fn enc_ciphertext(&self) -> &Blob<580> {
        &self.enc_ciphertext
    }
}

impl Parse for OutputV5 {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            cv: parse!(p, "cv")?,
            cmu: parse!(p, "cmu")?,
            ephemeral_key: parse!(p, "ephemeral_key")?,
            enc_ciphertext: parse!(p, "enc_ciphertext")?,
            out_ciphertext: parse!(p, "out_ciphertext")?,
        })
    }
}
