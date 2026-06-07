use zcash_protocol::consensus::NetworkType;
use zewif::Network;

pub(crate) fn convert_network(network: NetworkType) -> Network {
    match network {
        NetworkType::Main => Network::Main,
        NetworkType::Test => Network::Test,
        NetworkType::Regtest => Network::Regtest,
    }
}

pub(crate) fn address_network_from_zewif(network: Network) -> NetworkType {
    match network {
        Network::Main => NetworkType::Main,
        Network::Test => NetworkType::Test,
        Network::Regtest => NetworkType::Regtest,
    }
}
