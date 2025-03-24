use zewif::Network;

pub fn zewif_network_to_zcash_address_network(network: Network) -> zcash_address::Network {
    match network {
        Network::Main => zcash_address::Network::Main,
        Network::Test => zcash_address::Network::Test,
        Network::Regtest => zcash_address::Network::Regtest,
    }
}
