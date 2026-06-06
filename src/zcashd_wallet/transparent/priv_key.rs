use anyhow::{Result, anyhow, bail};

use zewif::Data;

use crate::{
    parse,
    parser::prelude::*,
    zcashd_wallet::{CompactSize, u256},
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PrivKey {
    data: Data,
    hash: u256,
}

impl PrivKey {
    pub fn data(&self) -> &Data {
        &self.data
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn hash(&self) -> u256 {
        self.hash
    }

    /// Extracts the 32-byte secp256k1 scalar from the SEC1 `EC PRIVATE KEY`
    /// DER blob stored by `zcashd`.
    ///
    /// Note: This could be eliminated if we used `Key::der_decode()` from
    /// zcash_keys 0.10.1, but this crate is intentionally pinned to
    /// zcash_keys 0.4.0 for compatibility with zcashd's dependencies.
    pub fn secp256k1_scalar(&self) -> Result<[u8; 32]> {
        let bytes = self.as_slice();
        let mut cursor = 0usize;

        if bytes.get(cursor).copied() != Some(0x30) {
            bail!("PrivKey: expected outer SEQUENCE tag (0x30)");
        }
        cursor += 1;

        // Parse the SEQUENCE length octets. Short form: a single byte < 0x80
        // gives the body length directly. Long form: the first byte's low 7
        // bits give the number of length octets that follow, big-endian.
        // (Indefinite form `0x80` is prohibited by DER and falls through to
        // the tag mismatch below.)
        let len_first = *bytes
            .get(cursor)
            .ok_or_else(|| anyhow!("PrivKey: truncated SEQUENCE length"))?;
        cursor += 1;
        let body_len: usize = if len_first & 0x80 == 0 {
            len_first as usize
        } else {
            let n = (len_first & 0x7f) as usize;
            let len_bytes = bytes
                .get(cursor..cursor.saturating_add(n))
                .ok_or_else(|| anyhow!("PrivKey: truncated long-form SEQUENCE length"))?;
            cursor += n;
            let mut acc: usize = 0;
            for &b in len_bytes {
                acc = acc
                    .checked_mul(256)
                    .and_then(|a| a.checked_add(b as usize))
                    .ok_or_else(|| anyhow!("PrivKey: SEQUENCE length overflow"))?;
            }
            acc
        };
        let body_end = cursor
            .checked_add(body_len)
            .ok_or_else(|| anyhow!("PrivKey: SEQUENCE end overflow"))?;
        if body_end != bytes.len() {
            bail!(
                "PrivKey: SEQUENCE length {} does not match length of blob remainder ({} bytes)",
                body_len,
                bytes.len().saturating_sub(cursor),
            );
        }

        // INTEGER version, value 1.
        if bytes.get(cursor..cursor.saturating_add(3)) != Some(&[0x02, 0x01, 0x01][..]) {
            bail!("PrivKey: expected INTEGER 1 version field after SEQUENCE");
        }
        cursor += 3;

        // OCTET STRING(32) holding the private scalar.
        if bytes.get(cursor..cursor.saturating_add(2)) != Some(&[0x04, 0x20][..]) {
            bail!("PrivKey: expected OCTET STRING(32) holding private scalar");
        }
        cursor += 2;

        let end = cursor
            .checked_add(32)
            .ok_or_else(|| anyhow!("PrivKey: scalar offset overflow"))?;
        let scalar_bytes = bytes
            .get(cursor..end)
            .ok_or_else(|| anyhow!("PrivKey: OCTET STRING(32) truncated"))?;
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(scalar_bytes);
        Ok(scalar)
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PrivKey({:?})", self.data())
    }
}

impl AsRef<Data> for PrivKey {
    fn as_ref(&self) -> &Data {
        self.data()
    }
}

impl AsRef<[u8]> for PrivKey {
    fn as_ref(&self) -> &[u8] {
        self.data().as_ref()
    }
}

impl Parse for PrivKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        let length = *parse!(p, CompactSize, "PrivKey size")?;
        if length != 214 && length != 279 {
            bail!("Invalid PrivKey size: {}", length);
        }
        let data = parse!(p, data = length, "PrivKey")?;
        let hash = parse!(p, "PrivKey hash")?;
        Ok(Self { data, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zewif::Data;

    fn make_compressed_blob(scalar: [u8; 32]) -> Data {
        // 30 81 D3 (SEQ 211) + 02 01 01 (INTEGER 1) + 04 20 <scalar> + filler to 214 bytes
        let mut blob = vec![0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x20];
        blob.extend_from_slice(&scalar);
        blob.resize(214, 0xAA);
        Data::from_slice(&blob)
    }

    fn make_uncompressed_blob(scalar: [u8; 32]) -> Data {
        // 30 82 01 13 (SEQ 275) + 02 01 01 (INTEGER 1) + 04 20 <scalar> + filler to 279 bytes
        let mut blob = vec![0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x01, 0x04, 0x20];
        blob.extend_from_slice(&scalar);
        blob.resize(279, 0xBB);
        Data::from_slice(&blob)
    }

    #[test]
    fn extracts_scalar_from_compressed_blob() {
        let scalar = [0x42u8; 32];
        let pk = PrivKey {
            data: make_compressed_blob(scalar),
            hash: u256::default(),
        };
        assert_eq!(pk.secp256k1_scalar().unwrap(), scalar);
    }

    #[test]
    fn extracts_scalar_from_uncompressed_blob() {
        let scalar = [0x99u8; 32];
        let pk = PrivKey {
            data: make_uncompressed_blob(scalar),
            hash: u256::default(),
        };
        assert_eq!(pk.secp256k1_scalar().unwrap(), scalar);
    }

    #[test]
    fn rejects_blob_without_marker() {
        let pk = PrivKey {
            data: Data::from_slice(&vec![0u8; 214]),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }

    #[test]
    fn rejects_blob_with_marker_at_wrong_offset() {
        // A blob whose outer shape is *not* a valid SEC1 SEQUENCE, but which
        // contains the `02 01 01 04 20` byte sequence somewhere in its body.
        // A naive window-search would return the 32 bytes following that
        // sequence; the structural parser must reject because byte 0 is not
        // the SEQUENCE tag.
        let mut data = vec![0xff; 10];
        data.extend_from_slice(&[0x02, 0x01, 0x01, 0x04, 0x20]);
        data.extend_from_slice(&[0x55; 32]);
        data.resize(214, 0xAA);
        let pk = PrivKey {
            data: Data::from_slice(&data),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }

    #[test]
    fn extracts_scalar_with_short_form_length() {
        // Synthetic blob using DER short-form SEQUENCE length (body < 128).
        // Realistic zcashd blobs always use long form, but the parser should
        // handle both.
        let scalar = [0x77u8; 32];
        let mut blob = vec![0x30, 50];
        blob.extend_from_slice(&[0x02, 0x01, 0x01, 0x04, 0x20]);
        blob.extend_from_slice(&scalar);
        blob.resize(2 + 50, 0xCC);
        let pk = PrivKey {
            data: Data::from_slice(&blob),
            hash: u256::default(),
        };
        assert_eq!(pk.secp256k1_scalar().unwrap(), scalar);
    }

    #[test]
    fn rejects_blob_with_undersized_sequence_length() {
        // SEQUENCE prologue claims body length 50, but the blob actually
        // extends to 214 bytes. Without the length-coverage check, the parser
        // would happily walk past the declared end and find the INTEGER tag
        // anyway; the check makes the structural mismatch surface here.
        let mut blob = vec![0x30, 50];
        blob.extend_from_slice(&[0x02, 0x01, 0x01, 0x04, 0x20]);
        blob.extend_from_slice(&[0x77; 32]);
        blob.resize(214, 0xAA);
        let pk = PrivKey {
            data: Data::from_slice(&blob),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }

    #[test]
    fn rejects_blob_with_oversized_sequence_length() {
        // SEQUENCE prologue claims body length 300, but the blob only
        // contains 214 bytes total. The length-coverage check rejects
        // declarations that run past the blob end, symmetric with the
        // undersized case above.
        let mut blob = vec![0x30, 0x82, 0x01, 0x2C, 0x02, 0x01, 0x01, 0x04, 0x20];
        blob.extend_from_slice(&[0x77; 32]);
        blob.resize(214, 0xAA);
        let pk = PrivKey {
            data: Data::from_slice(&blob),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }

    #[test]
    fn rejects_blob_with_wrong_version_integer() {
        // SEQUENCE prologue is valid, but the INTEGER version is 2 instead of
        // 1 — RFC 5915 only defines version 1, so this must be rejected.
        let mut blob = vec![0x30, 0x81, 0xD3, 0x02, 0x01, 0x02, 0x04, 0x20];
        blob.extend_from_slice(&[0x33; 32]);
        blob.resize(214, 0xAA);
        let pk = PrivKey {
            data: Data::from_slice(&blob),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }
}
