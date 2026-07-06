use zewif::{TxId, sapling::SaplingIncomingViewingKey};

use crate::{
    BdbDumpError, DumpError,
    migrate::MigrateError,
    parser::ParseError,
    zcashd_wallet::{sapling::SaplingZPaymentAddress, transparent::ScriptId},
};

/// The errors that can arise while reading a zcashd `wallet.dat` and
/// migrating its contents to a ZeWIF document.
///
/// This is the error type returned by the crate's top-level entry points;
/// each variant either wraps a layer-specific error or describes a
/// wallet-level integrity violation detected while assembling the parsed
/// wallet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record's binary contents could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// The `wallet.dat` file could not be dumped to records.
    #[error(transparent)]
    BdbDump(#[from] BdbDumpError),

    /// A record expected to be present in the wallet database was missing
    /// or ambiguous.
    #[error(transparent)]
    Dump(#[from] DumpError),

    /// The parsed wallet could not be migrated to a ZeWIF document.
    #[error(transparent)]
    Migrate(#[from] MigrateError),

    /// A key record set and its metadata record set differ in size.
    #[error("mismatched {keyname:?} and {metadata_keyname:?} records")]
    MismatchedKeyMetadata {
        keyname: &'static str,
        metadata_keyname: &'static str,
    },

    /// A `sapextfvk` record's value byte was not the expected `'1'` marker.
    /// zcashd treats such records as "do not load this key", so their
    /// presence means the record is not what it claims to be.
    #[error("unexpected sapextfvk marker byte: {0:#04x} (expected 0x31)")]
    UnexpectedSapExtFvkMarker(u8),

    /// Two `sapextfvk` records decode to the same incoming viewing key.
    #[error("duplicate sapextfvk record for ivk {ivk:?}")]
    DuplicateSaplingExtFvk { ivk: SaplingIncomingViewingKey },

    /// A `unifiedaddrmeta` record's value was not the expected zero.
    #[error("unexpected value for UnifiedAddressMetadata: {0:#010x}")]
    UnexpectedUnifiedAddressMetadataValue(u32),

    /// A `unifiedaccount` record's value was not the expected zero.
    #[error("unexpected value for UnifiedAccountMetadata: {0:#010x}")]
    UnexpectedUnifiedAccountMetadataValue(u32),

    /// The `hdseed` record's payload was not exactly 32 bytes.
    #[error("legacy HD seed must be exactly 32 bytes")]
    InvalidLegacySeedLength,

    /// Two `name` records exist for one address.
    #[error("duplicate address in name records: {address}")]
    DuplicateAddressName { address: String },

    /// Two `purpose` records exist for one address.
    #[error("duplicate address in purpose records: {address}")]
    DuplicateAddressPurpose { address: String },

    /// Two `sapzaddr` records exist for one Sapling payment address.
    #[error("duplicate Sapling payment address: {address:?}")]
    DuplicateSaplingAddress { address: SaplingZPaymentAddress },

    /// Two `cscript` records exist for one script ID.
    #[error("duplicate cscript ScriptID: {script_id:?}")]
    DuplicateScriptId { script_id: ScriptId },

    /// Two `tx` records exist for one transaction ID.
    #[error("duplicate transaction: {txid:?}")]
    DuplicateTransaction { txid: TxId },
}
