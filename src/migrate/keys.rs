use anyhow::Result;

use zewif::sapling::SaplingIncomingViewingKey;

use crate::ZcashdWallet;

/// Find a SaplingKey for a given incoming viewing key
pub fn find_sapling_key_for_ivk<'a>(
    wallet: &'a ZcashdWallet,
    ivk: &SaplingIncomingViewingKey,
) -> Option<&'a crate::SaplingKey> {
    wallet.sapling_keys().get(ivk)
}

/// Convert ZCashd SaplingExtendedSpendingKey to Zewif SpendingKey
pub fn convert_sapling_spending_key(
    key: &zewif::sapling::SaplingExtendedSpendingKey,
) -> Result<zewif::SpendingKey> {
    Ok(zewif::SpendingKey::Sapling(key.clone()))
}
