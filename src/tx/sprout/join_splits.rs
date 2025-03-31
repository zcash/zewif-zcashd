use anyhow::Result;

use zewif::blob;
use zewif::{parse, parser::prelude::*};

use super::JSDescription;

blob!(Ed25519Signature, 64, "An Ed25519 signature used in Zcash transactions.");
blob!(Ed25519VerificationKey, 32, "An Ed25519 verification key used in Zcash transactions.");

#[derive(Debug, Clone, PartialEq)]
pub struct JoinSplits {
    descriptions: Vec<JSDescription>,
    pub_key: Option<Ed25519VerificationKey>,
    sig: Option<Ed25519Signature>,
}

impl JoinSplits {
    pub fn descriptions(&self) -> &[JSDescription] {
        &self.descriptions
    }

    pub fn pub_key(&self) -> Option<&Ed25519VerificationKey> {
        self.pub_key.as_ref()
    }

    pub fn sig(&self) -> Option<&Ed25519Signature> {
        self.sig.as_ref()
    }
}

impl ParseWithParam<bool> for JoinSplits {
    fn parse(p: &mut Parser, use_groth: bool) -> Result<Self> {
        let descriptions = parse!(p, Vec<JSDescription>, param = use_groth, "descriptions")?;
        if !descriptions.is_empty() {
            Ok(Self {
                descriptions,
                pub_key: Some(parse!(p, "pub_key")?),
                sig: Some(parse!(p, "sig")?),
            })
        } else {
            Ok(Self { descriptions, pub_key: None, sig: None })
        }
    }
}
