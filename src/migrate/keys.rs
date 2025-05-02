use zewif::sapling::SaplingIncomingViewingKey;

use crate::ZcashdWallet;

/// Find a SaplingKey for a given incoming viewing key
pub fn find_sapling_key_for_ivk<'a>(
    wallet: &'a ZcashdWallet,
    ivk: &SaplingIncomingViewingKey,
) -> Option<&'a crate::SaplingKey> {
    wallet.sapling_keys().get(ivk)
}
