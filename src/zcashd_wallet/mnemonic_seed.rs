use secrecy::{SecretVec, Zeroize};
use zewif::{Bip39Mnemonic, MnemonicLanguage, SeedFingerprint};

use crate::zcashd_wallet::encode_seed_fingerprint;

/// A BIP-39 mnemonic together with the 64-byte BIP-39 seed and the ZIP 32
/// seed fingerprint derived from its phrase.
///
/// A value of this type can only be built from a phrase that parses, so the
/// seed and fingerprint it carries always belong to its mnemonic. The seed and
/// fingerprint are computed once, at construction, because BIP-39 seed
/// derivation runs 2048 rounds of PBKDF2-HMAC-SHA512. The value is immutable,
/// so the stored seed and fingerprint cannot drift from the mnemonic.
pub struct MnemonicSeed {
    mnemonic: Bip39Mnemonic,
    seed: SecretVec<u8>,
    fingerprint: SeedFingerprint,
}

impl std::fmt::Debug for MnemonicSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicSeed")
            .field("mnemonic", &self.mnemonic)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl MnemonicSeed {
    /// Derives the seed and seed fingerprint of a BIP-39 mnemonic.
    ///
    /// The function parses the phrase with the wordlist of the mnemonic's
    /// recorded language, or with the English wordlist when the mnemonic
    /// records no language. It derives the seed with an empty BIP-39
    /// passphrase, as zcashd does, and computes the ZIP 32 fingerprint of
    /// that seed.
    ///
    /// Returns [`MnemonicSeedError::UnsupportedLanguage`] when the recorded
    /// language has no BIP-39 wordlist, and
    /// [`MnemonicSeedError::InvalidPhrase`] when the phrase is not a valid
    /// mnemonic in its language.
    pub fn from_mnemonic(mnemonic: Bip39Mnemonic) -> Result<Self, MnemonicSeedError> {
        let language = mnemonic
            .language()
            .map_or(Ok(bip0039::BuiltInLanguage::English), bip39_language)?;
        let parsed = bip0039::AnyMnemonic::from_phrase(language, mnemonic.mnemonic())
            .map_err(|_| MnemonicSeedError::InvalidPhrase)?;
        let mut seed_bytes = parsed.to_seed("");
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&seed_bytes)
            .expect("a BIP-39 seed is 64 bytes, within the ZIP 32 seed length bounds")
            .to_bytes();
        let seed = SecretVec::new(seed_bytes.to_vec());
        seed_bytes.zeroize();
        Ok(MnemonicSeed {
            mnemonic,
            seed,
            fingerprint: encode_seed_fingerprint(&fingerprint),
        })
    }

    /// The mnemonic.
    pub fn mnemonic(&self) -> &Bip39Mnemonic {
        &self.mnemonic
    }

    /// The 64-byte BIP-39 seed derived from the mnemonic.
    pub fn seed(&self) -> &SecretVec<u8> {
        &self.seed
    }

    /// The ZIP 32 fingerprint of [`Self::seed`].
    pub fn fingerprint(&self) -> &SeedFingerprint {
        &self.fingerprint
    }

    /// Consumes the value and returns its mnemonic, seed and fingerprint.
    pub fn into_parts(self) -> (Bip39Mnemonic, SecretVec<u8>, SeedFingerprint) {
        (self.mnemonic, self.seed, self.fingerprint)
    }
}

/// The ways a wallet's recorded mnemonic can fail to yield a seed.
#[derive(Debug, thiserror::Error)]
pub enum MnemonicSeedError {
    /// The mnemonic records a language that has no BIP-39 wordlist.
    #[error("mnemonic language {0:?} has no BIP-39 wordlist")]
    UnsupportedLanguage(String),

    /// The phrase is not a valid BIP-39 mnemonic in its recorded language.
    #[error("the mnemonic phrase is not a valid BIP-39 mnemonic in its recorded language")]
    InvalidPhrase,

    /// The wallet's mnemonic HD chain record stores a seed fingerprint that
    /// differs from the fingerprint of the seed derived from the wallet's
    /// mnemonic phrase. zcashd writes both records from the same seed, so a
    /// difference means that one of the records is corrupt.
    #[error(
        "mnemonic HD chain records seed fingerprint {} but the mnemonic phrase derives {}",
        recorded.encoding(),
        derived.encoding()
    )]
    FingerprintMismatch {
        recorded: SeedFingerprint,
        derived: SeedFingerprint,
    },
}

/// Derives the seed of a wallet's recorded mnemonic and checks it against
/// the fingerprint stored in the wallet's mnemonic HD chain record.
///
/// Inputs are the wallet's `mnemonicphrase` record and the seed fingerprint
/// of its `mnemonichdchain` record, either of which may be absent.
///
/// Returns `Ok(None)` when the wallet records no mnemonic or an empty
/// phrase. Returns the errors of [`MnemonicSeed::from_mnemonic`], and
/// [`MnemonicSeedError::FingerprintMismatch`] when an HD chain fingerprint is
/// present and differs from the derived fingerprint.
pub(crate) fn recorded_mnemonic_seed(
    mnemonic: Option<&Bip39Mnemonic>,
    hd_chain_fingerprint: Option<&[u8; 32]>,
) -> Result<Option<MnemonicSeed>, MnemonicSeedError> {
    let Some(mnemonic) = mnemonic.filter(|m| !m.mnemonic().is_empty()) else {
        return Ok(None);
    };
    let seed = MnemonicSeed::from_mnemonic(mnemonic.clone())?;
    if let Some(recorded) = hd_chain_fingerprint.map(encode_seed_fingerprint)
        && recorded != seed.fingerprint
    {
        return Err(MnemonicSeedError::FingerprintMismatch {
            recorded,
            derived: seed.fingerprint,
        });
    }
    Ok(Some(seed))
}

/// The BIP-39 wordlist for a mnemonic language.
fn bip39_language(
    language: &MnemonicLanguage,
) -> Result<bip0039::BuiltInLanguage, MnemonicSeedError> {
    use bip0039::BuiltInLanguage as L;
    Ok(match language {
        MnemonicLanguage::English => L::English,
        MnemonicLanguage::SimplifiedChinese => L::ChineseSimplified,
        MnemonicLanguage::TraditionalChinese => L::ChineseTraditional,
        MnemonicLanguage::Czech => L::Czech,
        MnemonicLanguage::French => L::French,
        MnemonicLanguage::Italian => L::Italian,
        MnemonicLanguage::Japanese => L::Japanese,
        MnemonicLanguage::Korean => L::Korean,
        MnemonicLanguage::Portuguese => L::Portuguese,
        MnemonicLanguage::Spanish => L::Spanish,
        MnemonicLanguage::Other(tag) => {
            return Err(MnemonicSeedError::UnsupportedLanguage(tag.clone()));
        }
    })
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn spanish_phrase() -> (String, [u8; 64]) {
        let spanish = bip0039::Mnemonic::<bip0039::Spanish>::from_entropy(vec![0u8; 32])
            .expect("32 bytes of entropy");
        (spanish.phrase().to_string(), spanish.to_seed(""))
    }

    #[test]
    fn mnemonic_is_parsed_with_its_recorded_language() {
        let (phrase, expected_seed) = spanish_phrase();

        let seed = MnemonicSeed::from_mnemonic(Bip39Mnemonic::new(
            &phrase,
            Some(MnemonicLanguage::Spanish),
        ))
        .expect("a Spanish phrase parses as Spanish");
        assert_eq!(seed.seed().expose_secret().as_slice(), &expected_seed);
        let expected_fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&expected_seed)
            .expect("64-byte seed")
            .to_bytes();
        assert_eq!(
            seed.fingerprint(),
            &encode_seed_fingerprint(&expected_fingerprint)
        );

        assert!(matches!(
            MnemonicSeed::from_mnemonic(Bip39Mnemonic::new(
                &phrase,
                Some(MnemonicLanguage::English)
            )),
            Err(MnemonicSeedError::InvalidPhrase)
        ));
        assert!(matches!(
            MnemonicSeed::from_mnemonic(Bip39Mnemonic::new(&phrase, None)),
            Err(MnemonicSeedError::InvalidPhrase)
        ));
        assert!(matches!(
            MnemonicSeed::from_mnemonic(Bip39Mnemonic::new(
                &phrase,
                Some(MnemonicLanguage::Other("tlh".into()))
            )),
            Err(MnemonicSeedError::UnsupportedLanguage(tag)) if tag == "tlh"
        ));
    }

    #[test]
    fn recorded_mnemonic_seed_checks_the_hd_chain_fingerprint() {
        let (phrase, _) = spanish_phrase();
        let mnemonic = Bip39Mnemonic::new(&phrase, Some(MnemonicLanguage::Spanish));
        let derived = MnemonicSeed::from_mnemonic(mnemonic.clone()).expect("parses");
        let matching: [u8; 32] = zip32::fingerprint::SeedFingerprint::from_seed(
            derived.seed().expose_secret(),
        )
        .expect("64-byte seed")
        .to_bytes();

        let checked = recorded_mnemonic_seed(Some(&mnemonic), Some(&matching))
            .expect("matching fingerprints")
            .expect("a mnemonic is recorded");
        assert_eq!(checked.fingerprint(), derived.fingerprint());

        let unchecked = recorded_mnemonic_seed(Some(&mnemonic), None)
            .expect("no HD chain to check against")
            .expect("a mnemonic is recorded");
        assert_eq!(unchecked.fingerprint(), derived.fingerprint());

        let other = [0xEEu8; 32];
        assert!(matches!(
            recorded_mnemonic_seed(Some(&mnemonic), Some(&other)),
            Err(MnemonicSeedError::FingerprintMismatch { recorded, derived: d })
                if recorded == encode_seed_fingerprint(&other) && &d == derived.fingerprint()
        ));
    }

    #[test]
    fn absent_or_empty_mnemonic_yields_no_seed() {
        assert!(matches!(recorded_mnemonic_seed(None, None), Ok(None)));
        let empty = Bip39Mnemonic::new("", Some(MnemonicLanguage::English));
        assert!(matches!(
            recorded_mnemonic_seed(Some(&empty), Some(&[0xEE; 32])),
            Ok(None)
        ));
    }
}
