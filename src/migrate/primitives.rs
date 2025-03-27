use zewif::Network;

pub(crate) fn convert_network(network: zcash_primitives::consensus::NetworkType) -> Network {
    match network {
        zcash_address::Network::Main => Network::Main,
        zcash_address::Network::Test => Network::Test,
        zcash_address::Network::Regtest => Network::Regtest,
    }
}

pub(crate) fn address_network_from_zewif(network: Network) -> zcash_address::Network {
    match network {
        Network::Main => zcash_address::Network::Main,
        Network::Test => zcash_address::Network::Test,
        Network::Regtest => zcash_address::Network::Regtest,
    }
}
