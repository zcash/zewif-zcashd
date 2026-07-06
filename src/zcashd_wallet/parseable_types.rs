//! Standard implementations of the Parse trait for common types.
//!
//! This module provides binary deserialization implementations for primitive types,
//! collections, and other standard types used throughout the ZeWIF codebase. The
//! implementations here serve as the foundation for parsing complex Zcash data structures.

use std::collections::{HashMap, HashSet};

use zcash_keys::keys::UnifiedFullViewingKey;
use zewif::{Data, SeedFingerprint, sapling::SaplingIncomingViewingKey};

use crate::{
    parse,
    parser::prelude::*,
    zcashd_wallet::{CompactSize, u256},
};

impl Parse for String {
    fn parse(p: &mut Parser) -> Result<Self> {
        let length = parse!(p, CompactSize, "string length")?;
        let bytes = parse!(p, bytes = *length, "string")?;
        String::from_utf8(bytes.to_vec()).with_frame("string")
    }
}

pub fn parse_string<T>(p: &mut Parser) -> Result<String>
where
    T: Parse + TryInto<usize>,
{
    let parsed = parse!(p, T, "string length")?;
    let length = parsed
        .try_into()
        .map_err(|_| ParseErrorKind::StringLengthOverflow)?;
    let bytes = parse!(p, bytes = length, "string data")?;
    String::from_utf8(bytes.to_vec()).with_frame("string")
}

impl Parse for bool {
    fn parse(p: &mut Parser) -> Result<Self> {
        let byte = parse!(p, u8, "bool")?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ParseErrorKind::InvalidBool(byte).into()),
        }
    }
}

impl Parse for u8 {
    fn parse(p: &mut Parser) -> Result<Self> {
        let bytes = p.next(1).with_frame("u8")?;
        Ok(bytes[0])
    }
}

impl Parse for u16 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<u16>();
        let bytes = p.next(SIZE).with_frame("u16")?;
        Ok(u16::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for u32 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<u32>();
        let bytes = p.next(SIZE).with_frame("u32")?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for u64 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<u64>();
        let bytes = p.next(SIZE).with_frame("u64")?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for i8 {
    fn parse(p: &mut Parser) -> Result<Self> {
        let bytes = p.next(1).with_frame("i8")?;
        Ok(bytes[0] as i8)
    }
}

impl Parse for i16 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<i16>();
        let bytes = p.next(SIZE).with_frame("i16")?;
        Ok(i16::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for i32 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<i32>();
        let bytes = p.next(SIZE).with_frame("i32")?;
        Ok(i32::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for i64 {
    fn parse(p: &mut Parser) -> Result<Self> {
        const SIZE: usize = std::mem::size_of::<i64>();
        let bytes = p.next(SIZE).with_frame("i64")?;
        Ok(i64::from_le_bytes(bytes.try_into().expect("`next` returns exactly SIZE bytes")))
    }
}

impl Parse for () {
    fn parse(_p: &mut Parser) -> Result<Self> {
        Ok(())
    }
}

pub fn parse_pair<T: Parse, U: Parse>(p: &mut Parser) -> Result<(T, U)> {
    let first = parse!(p, "first item of pair")?;
    let second = parse!(p, "second item of pair")?;
    Ok((first, second))
}

impl<T: Parse, U: Parse> Parse for (T, U) {
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_pair(p)
    }
}

pub fn parse_fixed_length_vec<T: Parse>(p: &mut Parser, length: usize) -> Result<Vec<T>> {
    let mut items = Vec::with_capacity(length);
    for i in 0..length {
        items.push(parse!(p, format!("array item {} of {}", i, length - 1))?);
    }
    Ok(items)
}

pub fn parse_fixed_length_vec_with_param<T: ParseWithParam<U>, U: Clone>(
    p: &mut Parser,
    length: usize,
    param: U,
) -> Result<Vec<T>> {
    let mut items = Vec::with_capacity(length);
    for i in 0..length {
        items.push(parse!(
            p,
            param = param.clone(),
            format!("array item {} of {}", i, length - 1)
        )?);
    }
    Ok(items)
}

pub fn parse_fixed_length_array<T: Parse, const N: usize>(p: &mut Parser) -> Result<[T; N]> {
    let items = parse_fixed_length_vec(p, N)?;
    let array: [T; N] = items
        .try_into()
        .unwrap_or_else(|_| unreachable!("`parse_fixed_length_vec` returns exactly N items"));
    Ok(array)
}

pub fn parse_fixed_length_array_with_param<T: ParseWithParam<U>, U: Clone, const N: usize>(
    p: &mut Parser,
    param: U,
) -> Result<[T; N]> {
    let items = parse_fixed_length_vec_with_param(p, N, param)?;
    let array: [T; N] = items
        .try_into()
        .unwrap_or_else(|_| unreachable!("`parse_fixed_length_vec_with_param` returns exactly N items"));
    Ok(array)
}

pub fn parse_vec<T: Parse>(p: &mut Parser) -> Result<Vec<T>> {
    let length = *parse!(p, CompactSize, "array length")?;
    parse_fixed_length_vec(p, length)
}

pub fn parse_vec_with_param<T: ParseWithParam<U>, U: Clone>(
    p: &mut Parser,
    param: U,
) -> Result<Vec<T>> {
    let length = *parse!(p, CompactSize, "array length")?;
    parse_fixed_length_vec_with_param(p, length, param)
}

impl<T: Parse, const N: usize> Parse for [T; N] {
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_fixed_length_array(p)
    }
}

impl<T: ParseWithParam<U>, U: Clone, const N: usize> ParseWithParam<U> for [T; N] {
    fn parse(p: &mut Parser, param: U) -> Result<Self> {
        parse_fixed_length_array_with_param(p, param)
    }
}

impl<T: Parse> Parse for Vec<T> {
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_vec(p)
    }
}

impl<T: ParseWithParam<U>, U: Clone> ParseWithParam<U> for Vec<T> {
    fn parse(p: &mut Parser, param: U) -> Result<Self> {
        parse_vec_with_param(p, param)
    }
}

pub fn parse_map<K: Parse, V: Parse>(p: &mut Parser) -> Result<Vec<(K, V)>> {
    let length = *parse!(p, CompactSize, "map length")?;
    let mut items = Vec::with_capacity(length);
    for _ in 0..length {
        items.push(parse_pair::<K, V>(p).with_frame("map item")?);
    }
    Ok(items)
}

pub fn parse_hashmap<K, V: Parse>(p: &mut Parser) -> Result<HashMap<K, V>>
where
    K: Parse + Eq + std::hash::Hash,
{
    Ok(parse_map::<K, V>(p)?.into_iter().collect())
}

impl<K: Parse, V: Parse> Parse for HashMap<K, V>
where
    K: Parse + Eq + std::hash::Hash,
{
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_hashmap(p)
    }
}

pub fn parse_hashset<T>(p: &mut Parser) -> Result<HashSet<T>>
where
    T: Parse + Eq + std::hash::Hash,
{
    let length = *parse!(p, CompactSize, "set length")?;
    let mut items = HashSet::with_capacity(length);
    for _ in 0..length {
        items.insert(parse!(p, "set item")?);
    }
    Ok(items)
}

impl<T: Parse + Eq + std::hash::Hash> Parse for HashSet<T> {
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_hashset(p)
    }
}

/// A container that optionally holds a value, serialized with a presence flag followed by the value if present.                      | 1 byte (discriminant: 0x00 = absent, 0x01 = present) + serialized value `T` if present.
pub fn parse_optional<T: Parse>(p: &mut Parser) -> Result<Option<T>> {
    match parse!(p, u8, "optional discriminant")? {
        0x00 => Ok(None),
        0x01 => Ok(Some(parse!(p, "optional value")?)),
        discriminant => Err(ParseErrorKind::InvalidOptionalDiscriminant(discriminant).into()),
    }
}

impl<T: Parse> Parse for Option<T> {
    fn parse(p: &mut Parser) -> Result<Self> {
        parse_optional(p)
    }
}


impl Parse for zewif::Data {
    /// Parses a variable-length `Data` instance from a binary parser.
    ///
    /// This implementation first reads a `CompactSize` value that indicates
    /// the length of the data, then reads that many bytes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The parser doesn't have enough bytes remaining
    /// - The CompactSize value cannot be parsed
    ///
    /// # Examples
    /// ```no_run
    /// # use zewif::Data;
    /// # use zewif_zcashd::parser::Parser;
    /// # use zewif_zcashd::parse;
    /// # use zewif_zcashd::parser::error::Result;
    /// #
    /// # fn example(parser: &mut Parser) -> Result<()> {
    /// // Parse a data structure with length prefix
    /// let data = parse!(parser, Data, "variable-length data")?;
    /// # Ok(())
    /// # }
    /// ```
    fn parse(p: &mut Parser) -> Result<Self> {
        let len = parse!(p, crate::zcashd_wallet::CompactSize, "Data length")?;
        let bytes = p.next(*len).with_frame("Data")?;
        Ok(Self::from_slice(bytes))
    }
}

impl Parse for zewif::Amount {
    fn parse(p: &mut Parser) -> Result<Self> {
        let zat_balance = parse!(p, i64, "Zat balance")?;
        Self::try_from(zat_balance)
            .map_err(|_| ParseErrorKind::InvalidAmount(zat_balance).into())
    }
}

impl Parse for zewif::BlockHash {
    /// Parses a `BlockHash` from a binary data stream.
    ///
    /// # Examples
    /// ```no_run
    /// # use zewif::BlockHash;
    /// # use zewif_zcashd::parser::Parser;
    /// # use zewif_zcashd::parse;
    /// # use zewif_zcashd::parser::error::Result;
    /// #
    /// # fn example(parser: &mut Parser) -> Result<()> {
    /// // Parse a transaction ID from a binary stream
    /// let txid = parse!(parser, BlockHash, "transaction ID")?;
    /// # Ok(())
    /// # }
    /// ```
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self::read(p)?)
    }
}

impl Parse for zewif::MnemonicLanguage {
    fn parse(p: &mut Parser) -> Result<Self> {
        let value = parse!(p, "language value")?;
        Ok(zewif::MnemonicLanguage::from_u32(value)?)
    }
}

impl Parse for zewif::Bip39Mnemonic {
    fn parse(p: &mut Parser) -> Result<Self> {
        let language = Some(parse!(p, zewif::MnemonicLanguage, "language")?);
        let mnemonic = parse!(p, String, "mnemonic")?;
        let bip39_mnemonic = Self::new(mnemonic, language);
        Ok(bip39_mnemonic)
    }
}

impl Parse for zewif::BlockHeight {
    fn parse(p: &mut Parser) -> Result<Self> {
        let height = parse!(p, u32, "BlockHeight")?;
        Ok(Self::from(height))
    }
}

impl Parse for zewif::Script {
    fn parse(p: &mut Parser) -> Result<Self> {
        let data: Data = parse!(p, "Script")?;
        Ok(Self::from(data))
    }
}

impl Parse for zewif::TxId {
    /// Parses a `TxId` from a binary data stream.
    ///
    /// # Examples
    /// ```no_run
    /// # use zewif::TxId;
    /// # use zewif_zcashd::parser::Parser;
    /// # use zewif_zcashd::parse;
    /// # use zewif_zcashd::parser::error::Result;
    /// #
    /// # fn example(parser: &mut Parser) -> Result<()> {
    /// // Parse a transaction ID from a binary stream
    /// let txid = parse!(parser, TxId, "transaction ID")?;
    /// # Ok(())
    /// # }
    /// ```
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(Self::read(p)?)
    }
}

impl Parse for SeedFingerprint {
    fn parse(p: &mut Parser) -> Result<Self> {
        let bytes: [u8; 32] = parse!(p, "seed_fingerprint")?;
        Ok(crate::zcashd_wallet::encode_seed_fingerprint(&bytes))
    }
}

impl Parse for SaplingIncomingViewingKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        let ivk_data: u256 = parse!(p, "sapling ivk")?;
        Ok(SaplingIncomingViewingKey::new(ivk_data.into_bytes()))
    }
}

impl Parse for ::sapling::zip32::ExtendedFullViewingKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(::sapling::zip32::ExtendedFullViewingKey::read(p)?)
    }
}

impl Parse for ::sapling::zip32::ExtendedSpendingKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        Ok(::sapling::zip32::ExtendedSpendingKey::read(p)?)
    }
}

impl Parse for UnifiedFullViewingKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        use zcash_address::unified::Encoding;

        let ufvk_str: String = parse!(p, "ufvk string")?;
        let (_, ufvk) = zcash_address::unified::Ufvk::decode(&ufvk_str)?;
        Ok(Self::parse(&ufvk)?)
    }
}

impl Parse for ::orchard::keys::IncomingViewingKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        let bytes: [u8; 64] = parse!(p, "orchard IVK")?;
        ::orchard::keys::IncomingViewingKey::from_bytes(&bytes)
            .into_option()
            .ok_or_else(|| ParseErrorKind::InvalidOrchardIvk.into())
    }
}
