use zewif::Network;

use crate::{parse, parser::prelude::*};

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInfo {
    zcash: String,
    network: Network,
}

/// The client name zcashd writes as the first element of the `networkinfo`
/// pair: its `PACKAGE_NAME` (see `CWalletDB::WriteNetworkInfo`).
const ZCASHD_PACKAGE_NAME: &str = "Zcash";

impl NetworkInfo {
    /// Synthesizes the record contents zcashd would write for the given
    /// network. Used for wallets that predate the `networkinfo` record
    /// (zcashd 5.0.0), whose network must be supplied by the caller.
    pub fn for_network(network: Network) -> Self {
        Self {
            zcash: ZCASHD_PACKAGE_NAME.to_string(),
            network,
        }
    }

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
            other => {
                return Err(ParseErrorKind::UnrecognizedNetwork(other.to_string()).into());
            }
        };
        Ok(Self { zcash, network })
    }
}
