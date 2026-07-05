use zcash_protocol::consensus::NetworkType;
use zewif::Network;

pub(crate) fn address_network_from_zewif(network: &Network) -> NetworkType {
    match network {
        Network::Mainnet => NetworkType::Main,
        Network::Testnet => NetworkType::Test,
        Network::Regtest(_) => NetworkType::Regtest,
    }
}
