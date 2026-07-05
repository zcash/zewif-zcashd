use anyhow::{Result, bail};
use zewif::Network;

use crate::{parse, parser::prelude::*};

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInfo {
    zcash: String,
    network: Network,
}

impl NetworkInfo {
    pub fn zcash(&self) -> &str {
        &self.zcash
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    pub fn to_address_encoding_network(&self) -> zcash_protocol::consensus::Network {
        use zcash_protocol::consensus::Network::*;
        match self.network {
            Network::Mainnet => MainNetwork,
            Network::Testnet => TestNetwork,
            // Regtest addresses are encoded as for the test network.
            Network::Regtest(_) => TestNetwork,
        }
    }
}

impl Parse for NetworkInfo {
    fn parse(p: &mut Parser) -> Result<Self> {
        let (zcash, identifier): (String, String) = parse!(p, "(zcash, identifier)")?;
        // zcashd records the network as one of the canonical identifier
        // strings emitted by `KeyConstants::NetworkIDString`.
        let network = match identifier.as_str() {
            "main" => Network::Mainnet,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest(Default::default()),
            other => bail!("Unrecognized zcashd network identifier: {other:?}"),
        };
        Ok(Self { zcash, network })
    }
}
