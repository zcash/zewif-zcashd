use anyhow::Result;

use zewif::{parse, parser::prelude::*};
use zewif::Network;

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInfo {
    zcash: String,
    network: Network,
}

impl NetworkInfo {
    pub fn zcash(&self) -> &str {
        &self.zcash
    }

    pub fn identifier(&self) -> String {
        self.network.into()
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

impl Parse for NetworkInfo {
    fn parse(p: &mut Parser) -> Result<Self> {
        let (zcash, identifier): (String, String) = parse!(p, "(zcash, identifier)")?;
        let network = Network::try_from(identifier)?;
        Ok(Self { zcash, network })
    }
}
