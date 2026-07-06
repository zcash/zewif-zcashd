use zewif::TxId;

use crate::parser::ParseError;

/// Errors arising while migrating a parsed zcashd wallet to a ZeWIF
/// document.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// No UFVK was recorded for a unified account's fingerprint. The
    /// fingerprint is rendered in zcashd's display order for
    /// cross-referencing against zcashd output.
    #[error("no UFVK found for unified account fingerprint {fingerprint}")]
    MissingAccountUfvk { fingerprint: String },

    /// No UFVK was recorded for a unified address's key fingerprint. The
    /// fingerprint is rendered in zcashd's display order for
    /// cross-referencing against zcashd output.
    #[error("no UFVK found for unified address fingerprint {fingerprint}")]
    MissingAddressUfvk { fingerprint: String },

    /// A unified address's recorded receiver types do not form a valid
    /// unified address request.
    #[error("receiver types do not produce a valid unified address: {0}")]
    InvalidReceiverTypes(zcash_keys::keys::ReceiverRequirementError),

    /// A unified address could not be derived from its UFVK at the recorded
    /// diversifier index.
    #[error("deriving unified address: {0}")]
    UnifiedAddressDerivation(#[from] zcash_keys::keys::AddressGenerationError),

    /// A stored public key's bytes were not a valid secp256k1 public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] secp256k1::Error),

    /// A stored public key was not a structurally valid transparent public
    /// key.
    #[error("invalid transparent public key: {0}")]
    InvalidTransparentPubKey(#[source] zewif::Error),

    /// A stored private key's DER encoding could not be decoded.
    #[error("undecodable private key: {0}")]
    InvalidPrivateKey(#[source] ParseError),

    /// The legacy HD seed was not the 32 bytes required for ZIP 32
    /// fingerprinting.
    #[error("legacy HD seed has an invalid length for ZIP 32 fingerprinting")]
    InvalidLegacySeedLength,

    /// Converting a single wallet transaction failed.
    #[error("converting transaction {txid}: {source}")]
    TransactionConversion {
        txid: TxId,
        source: Box<MigrateError>,
    },

    /// Re-serializing a parsed transaction to its canonical bytes failed.
    #[error("re-serializing parsed transaction to raw bytes: {0}")]
    TransactionSerialization(#[source] std::io::Error),

    /// Stored wallet data could not be parsed during migration.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// A value violated an invariant enforced by the `zewif` data model.
    #[error(transparent)]
    Zewif(#[from] zewif::Error),
}
