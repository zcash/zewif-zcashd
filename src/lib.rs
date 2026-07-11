use zewif::mod_use;

mod error;
pub use error::Error;

mod_use!(bdb_dump);
mod_use!(zcashd_dump);
mod_use!(zcashd_parser);

pub mod migrate;
pub mod parser;
pub mod zcashd_wallet;
pub use migrate::{RegtestActivations, migrate_to_zewif};
pub use zcashd_wallet::ZcashdWallet;

/// Re-exported so callers can build an [`EncryptedKeyPolicy::Decrypt`]
/// passphrase for [`ZcashdParser::parse_dump_with_policy`] without depending on
/// `secrecy` directly.
pub use secrecy::SecretVec;
