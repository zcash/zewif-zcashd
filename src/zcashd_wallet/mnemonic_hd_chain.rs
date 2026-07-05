use anyhow::Result;


use crate::{parse, parser::prelude::*, zcashd_wallet::SecondsSinceEpoch};

#[derive(Clone, PartialEq)]
pub struct MnemonicHDChain {
    version: i32,
    seed_fp: [u8; 32],
    create_time: SecondsSinceEpoch,
    account_counter: u32,
    legacy_tkey_external_counter: u32,
    legacy_tkey_internal_counter: u32,
    legacy_sapling_key_counter: u32,
    mnemonic_seed_backup_confirmed: bool,
}

impl std::fmt::Debug for MnemonicHDChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicHDChain")
            .field("version", &self.version)
            .field("seed_fp", &hex::encode(self.seed_fp))
            .field("create_time", &self.create_time)
            .field("account_counter", &self.account_counter)
            .field(
                "legacy_tkey_external_counter",
                &self.legacy_tkey_external_counter,
            )
            .field(
                "legacy_tkey_internal_counter",
                &self.legacy_tkey_internal_counter,
            )
            .field(
                "legacy_sapling_key_counter",
                &self.legacy_sapling_key_counter,
            )
            .field(
                "mnemonic_seed_backup_confirmed",
                &self.mnemonic_seed_backup_confirmed,
            )
            .finish()
    }
}

impl MnemonicHDChain {
    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn seed_fp(&self) -> &[u8; 32] {
        &self.seed_fp
    }

    pub fn create_time(&self) -> SecondsSinceEpoch {
        self.create_time
    }

    pub fn account_counter(&self) -> u32 {
        self.account_counter
    }

    pub fn legacy_tkey_external_counter(&self) -> u32 {
        self.legacy_tkey_external_counter
    }

    pub fn legacy_tkey_internal_counter(&self) -> u32 {
        self.legacy_tkey_internal_counter
    }

    pub fn legacy_sapling_key_counter(&self) -> u32 {
        self.legacy_sapling_key_counter
    }

    pub fn mnemonic_seed_backup_confirmed(&self) -> bool {
        self.mnemonic_seed_backup_confirmed
    }
}

impl Parse for MnemonicHDChain {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self {
            version: parse!(p, "version")?,
            seed_fp: parse!(p, "seed_fp")?,
            create_time: parse!(p, "create_time")?,
            account_counter: parse!(p, "account_counter")?,
            legacy_tkey_external_counter: parse!(p, "legacy_tkey_external_counter")?,
            legacy_tkey_internal_counter: parse!(p, "legacy_tkey_internal_counter")?,
            legacy_sapling_key_counter: parse!(p, "legacy_sapling_key_counter")?,
            mnemonic_seed_backup_confirmed: parse!(p, "mnemonic_seed_backup_confirmed")?,
        })
    }
}
