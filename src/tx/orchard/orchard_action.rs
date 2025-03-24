use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::u256;

use super::{OrchardSignature, TransmittedNoteCiphertext};

#[derive(Debug, Clone, PartialEq)]
pub struct OrchardAction {
    cv_net: u256,
    nf_old: u256,
    rk: u256,
    cmx: u256,
    encrypted_note: TransmittedNoteCiphertext,
    authorization: Option<OrchardSignature>,
}

impl OrchardAction {
    pub fn cv_net(&self) -> u256 {
        self.cv_net
    }

    pub fn nf_old(&self) -> u256 {
        self.nf_old
    }

    pub fn rk(&self) -> u256 {
        self.rk
    }

    pub fn cmx(&self) -> u256 {
        self.cmx
    }

    pub fn encrypted_note(&self) -> &TransmittedNoteCiphertext {
        &self.encrypted_note
    }

    pub fn authorization(&self) -> Option<&OrchardSignature> {
        self.authorization.as_ref()
    }

    pub fn set_authorization(&mut self, authorization: OrchardSignature) {
        self.authorization = Some(authorization);
    }
}

impl Parse for OrchardAction {
    fn parse(p: &mut Parser) -> Result<Self>
    where
        Self: Sized,
    {
        let cv_net = parse!(p, "cv_net")?;
        let nf_old = parse!(p, "nf")?;
        let rk = parse!(p, "rk")?;
        let cmx = parse!(p, "cmx")?;
        let encrypted_note = parse!(p, "encrypted_note")?;
        Ok(Self {
            cv_net,
            nf_old,
            rk,
            cmx,
            encrypted_note,
            authorization: None,
        })
    }
}
