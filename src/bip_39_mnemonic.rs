use anyhow::Result;

use zewif::{parse, u256, MnemonicLanguage};
use zewif::parser::prelude::*;

pub struct Bip39Mnemonic {
    mnemonic: String,
    language: Option<MnemonicLanguage>,
    fingerprint: Option<u256>,
}

impl std::fmt::Debug for Bip39Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("MnemonicSeed")
            .field("language", &self.language)
            .field("mnemonic", &self.mnemonic)
            .field("fingerprint", &&self.fingerprint)
            .finish()
    }
}

impl Bip39Mnemonic {
    pub fn new(mnemonic: String) -> Self {
        Self { mnemonic, language: None, fingerprint: None }
    }

    pub fn set_fingerprint(&mut self, fingerprint: u256) {
        self.fingerprint = Some(fingerprint);
    }

    pub fn mnemonic(&self) -> &String {
        &self.mnemonic
    }

    pub fn set_mnemonic(&mut self, mnemonic: String) {
        self.mnemonic = mnemonic;
    }

    pub fn language(&self) -> Option<&MnemonicLanguage> {
        self.language.as_ref()
    }

    pub fn fingerprint(&self) -> Option<&u256> {
        self.fingerprint.as_ref()
    }

    pub fn set_language(&mut self, language: MnemonicLanguage) {
        self.language = Some(language);
    }
}

impl Parse for Bip39Mnemonic {
    fn parse(p: &mut Parser) -> Result<Self> {
        let language = parse!(p, "language")?;
        let mnemonic = parse!(p, "mnemonic")?;
        let mut bip39_mnemonic = Self::new(mnemonic);
        bip39_mnemonic.set_language(language);
        Ok(bip39_mnemonic)
    }
}
