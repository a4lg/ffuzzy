// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Block size handlings and block hash parameters / utilities.

use core::cmp::Ordering;

/// A type to represent relation between two block sizes.
///
/// Because the core comparison method can only compare two block hashes
/// with the same block size, we cannot compare two fuzzy hashes if their
/// block sizes are not near enough.
///
/// There are three cases where we can perform actual block hash comparison:
///
/// 1. **Equals** ([`NearEq`](Self::NearEq))  
///    `bs_a == bs_b`
/// 2. **Less than** ([`NearLt`](Self::NearLt))  
///    `bs_a < bs_b && bs_a * 2 == bs_b`
/// 3. **Greater than** ([`NearGt`](Self::NearGt))  
///    `bs_a > bs_b && bs_a == bs_b * 2`
///
/// This type represents those *near* cases (three variants) and the case which
/// two fuzzy hashes cannot perform a block hash comparison, the *far* case
/// (the [`Far`](Self::Far) variant).
///
/// A value of this type can be retrieved by using
/// [`block_size::compare_sizes()`](crate::block_size::compare_sizes()) or
/// [`FuzzyHashData::compare_block_sizes()`](crate::hash::FuzzyHashData::compare_block_sizes()).
///
/// Note: in this crate, it can efficiently handle such relations by using the
/// [*base-2 logarithms* form of the block size](crate::hash::FuzzyHashData#block-size)
/// (no multiplication required).
///
/// # Compatibility Note
///
/// Since the version 0.3, the representation of this enum is no longer
/// specified as specific representation of this enum is not important.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSizeRelation {
    /// Two block sizes are *near* and the block hash 2 (one with a larger block
    /// size) of the left side (of comparison) can be compared with the block
    /// hash 1 (one with a smaller block size) of the right side.
    NearLt,
    /// Two block sizes are not just *near* but the same.
    /// We compare both block hashes with the other and take the maximum value
    /// for the output.
    NearEq,
    /// Two block sizes are *near* and the block hash 1 (one with a smaller
    /// block size) of the left side (of comparison) can be compared with the
    /// block hash 2 (one with a larger block size) of the right side.
    NearGt,
    /// Two block sizes are *far* and a block hash comparison
    /// cannot be performed.
    Far,
}

impl BlockSizeRelation {
    /// Checks whether a given value denotes one of the three *near* cases.
    pub fn is_near(&self) -> bool {
        !matches!(self, BlockSizeRelation::Far)
    }
}

/// Utility related to block size part of the fuzzy hash.
///
/// See also: ["Block Size" section of `FuzzyHashData`](crate::hash::FuzzyHashData#block-size)
pub mod block_size {
    use super::*;

    /// The minimum block size of a fuzzy hash.
    ///
    /// Any block size generated by ssdeep can be represented as
    /// ([`MIN`] * 2<sup>n</sup>).
    ///
    /// This is the smallest valid value of the block size part of a fuzzy hash.
    pub const MIN: u32 = 3;

    /// The number of valid block sizes.
    ///
    /// [`NUM_VALID`] is the smallest value which 2<sup>n</sup> exceeds
    /// [`u32::MAX`] and this value itself is not valid as a *base-2 logarithm*
    /// form of the block size (in fact, this is the *smallest* invalid value)
    /// in the fuzzy hash object.
    ///
    /// Note that, it *can* however be a valid *effective base-2 logarithm* form
    /// of the block size of the block hash 2 where the (base) block size (as in
    /// a fuzzy hash) is the largest valid one.
    /// Some low level methods may accept this value (in [`u8`]) as a *base-2
    /// logarithm* form of the block size (explicitly documented in such cases).
    pub const NUM_VALID: usize = 31;

    /// The range representing the valid *base-2 logarithm* form of the block size
    /// (used while testing).
    #[cfg(any(test, doc))]
    pub(crate) const RANGE_LOG_VALID: core::ops::Range<u8> = 0..block_size::NUM_VALID as u8;

    /// Checks whether a given block size is valid.
    #[inline]
    pub const fn is_valid(block_size: u32) -> bool {
        (block_size % MIN == 0) && (block_size / MIN).is_power_of_two()
    }

    /// Checks whether *base-2 logarithm* form of the block size is valid.
    #[inline(always)]
    pub const fn is_log_valid(log_block_size: u8) -> bool {
        log_block_size < NUM_VALID as u8
    }

    /// The internal implementation of [`from_log_unchecked()`].
    #[inline(always)]
    pub(crate) const fn from_log_internal_const(log_block_size: u8) -> u32 {
        MIN << log_block_size
    }

    /// The internal implementation of [`from_log_unchecked()`].
    #[inline(always)]
    pub(crate) fn from_log_internal(log_block_size: u8) -> u32 {
        debug_assert!(is_log_valid(log_block_size));
        from_log_internal_const(log_block_size)
    }

    /// Converts *base-2 logarithm* form of the block size to the actual one
    /// without checking validity of the block size.
    ///
    /// # Safety
    ///
    /// `log_block_size` must be valid.
    ///
    /// See also:
    /// ["Block Size" section of `FuzzyHashData`](crate::hash::FuzzyHashData#block-size)
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn from_log_unchecked(log_block_size: u8) -> u32 {
        from_log_internal(log_block_size)
    }

    /// Converts *base-2 logarithm* form of the block size to the actual one.
    ///
    /// It returns [`None`] if `log_block_size` is not valid.
    ///
    /// See also:
    /// ["Block Size" section of `FuzzyHashData`](crate::hash::FuzzyHashData#block-size)
    #[inline]
    pub fn from_log(log_block_size: u8) -> Option<u32> {
        is_log_valid(log_block_size).then(|| from_log_internal(log_block_size))
    }

    /// Precomputed block size strings.
    ///
    /// All valid block sizes are precomputed as raw strings to avoid
    /// calling [`u32::to_string()`](std::string::ToString::to_string())
    /// from [`FuzzyHash::to_string()`](crate::hash::FuzzyHash::to_string()).
    pub(crate) const BLOCK_SIZES_STR: [&str; NUM_VALID] = [
        "3",
        "6",
        "12",
        "24",
        "48",
        "96",
        "192",
        "384",
        "768",
        "1536",
        "3072",
        "6144",
        "12288",
        "24576",
        "49152",
        "98304",
        "196608",
        "393216",
        "786432",
        "1572864",
        "3145728",
        "6291456",
        "12582912",
        "25165824",
        "50331648",
        "100663296",
        "201326592",
        "402653184",
        "805306368",
        "1610612736",
        "3221225472",
    ];

    /// Maximum length of the precomputed block size strings.
    pub(crate) const MAX_BLOCK_SIZE_LEN_IN_CHARS: usize =
        BLOCK_SIZES_STR[BLOCK_SIZES_STR.len() - 1].len();

    /// The custom constant for a variant of de Bruijn sequence to convert
    /// all valid block size values into the unique index.
    ///
    /// # Internal Notes
    ///
    /// It uses a custom variant of de Bruijn sequence for conversion.
    /// This is a result of a manual search so that we can have unique index
    /// values for all `(3<<i) for i in 0..31`.  Note that:
    ///
    /// *   `block_size::MIN == 3`
    /// *   `block_size::NUM_VALID == 31`
    const LOG_DEBRUIJN_CONSTANT: u32 = 0x017713ca;

    /// The function to convert a block size into an index of
    /// a variant of de Bruijn sequence.
    #[inline(always)]
    const fn debruijn_index(block_size: u32) -> usize {
        (block_size.wrapping_mul(LOG_DEBRUIJN_CONSTANT) >> 27) as usize
    }

    /// The custom table for a variant of de Bruijn sequence to convert
    /// all valid block size values into the *base-2 logarithm* form.
    ///
    /// The element `[0x1f]` is unused (and assigned an invalid number `0xff`).
    ///
    /// See [`LOG_DEBRUIJN_CONSTANT`] for internal notes.
    #[rustfmt::skip]
    const LOG_DEBRUIJN_TABLE: [u8; 32] = [
        0x00, 0x01, 0x02, 0x06, 0x03, 0x0b, 0x07, 0x10,
        0x04, 0x0e, 0x0c, 0x18, 0x08, 0x15, 0x11, 0x1a,
        0x1e, 0x05, 0x0a, 0x0f, 0x0d, 0x17, 0x14, 0x19,
        0x1d, 0x09, 0x16, 0x13, 0x1c, 0x12, 0x1b, 0xff,
    ];

    /// The internal implementation of [`log_from_valid_unchecked()`].
    #[inline(always)]
    pub(crate) fn log_from_valid_internal(block_size: u32) -> u8 {
        debug_assert!(is_valid(block_size));
        LOG_DEBRUIJN_TABLE[debruijn_index(block_size)] // grcov-excl-br-line:ARRAY
    }

    /// Computes the *base-2 logarithm* form of a valid block size
    /// but do not check whether the block size is valid.
    ///
    /// This is the same as computing `n` for a valid block size
    /// which can be represented as ([`MIN`] * 2<sup>n</sup>) (`0 <= n`).
    ///
    /// # Safety
    ///
    /// If `block_size` is not valid, the result will be unpredictable.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn log_from_valid_unchecked(block_size: u32) -> u8 {
        log_from_valid_internal(block_size)
    }

    /// Computes the *base-2 logarithm* form of a valid block size.
    ///
    /// This is the same as computing `n` for a valid block size
    /// which can be represented as ([`MIN`] * 2<sup>n</sup>) (`0 <= n`).
    ///
    /// # Usage Constraints
    ///
    /// *   `block_size` must be valid.
    #[inline(always)]
    pub fn log_from_valid(block_size: u32) -> u8 {
        assert!(is_valid(block_size));
        log_from_valid_internal(block_size)
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// form a *near* relation (one of the three *near* cases).
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn is_near(lhs: u8, rhs: u8) -> bool {
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        // Optimize using u32
        u32::wrapping_sub(lhs as u32, rhs as u32).wrapping_add(1) <= 2
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// form a [`BlockSizeRelation::NearEq`] relation.
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn is_near_eq(lhs: u8, rhs: u8) -> bool {
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        lhs == rhs
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// form a [`BlockSizeRelation::NearLt`] relation.
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn is_near_lt(lhs: u8, rhs: u8) -> bool {
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        // Optimize using i32
        (rhs as i32) - (lhs as i32) == 1
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// form a [`BlockSizeRelation::NearGt`] relation.
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn is_near_gt(lhs: u8, rhs: u8) -> bool {
        is_near_lt(rhs, lhs)
    }

    /// Compare two *base-2 logarithm* forms of the block size values to
    /// determine the relation between two block sizes.
    ///
    /// The result is the one of the [`BlockSizeRelation`] values, representing
    /// the relation between two block sizes.
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn compare_sizes(lhs: u8, rhs: u8) -> BlockSizeRelation {
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        // Optimize using i32
        match (lhs as i32) - (rhs as i32) {
            -1 => BlockSizeRelation::NearLt,
            0 => BlockSizeRelation::NearEq,
            1 => BlockSizeRelation::NearGt,
            _ => BlockSizeRelation::Far,
        }
    }

    /// Compares two *base-2 logarithm* forms of the block size values
    /// for ordering.
    ///
    /// Both arguments must be valid.
    #[inline(always)]
    pub fn cmp(lhs: u8, rhs: u8) -> Ordering {
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        u8::cmp(&lhs, &rhs)
    }
}

/// Utilities related to block hash part of the fuzzy hash.
///
/// See also: ["Block Hashes" section of `FuzzyHashData`](crate::hash::FuzzyHashData#block-hashes)
pub mod block_hash {
    /// The number of alphabets used in the block hash part of a fuzzy hash.
    ///
    /// It is same as the number of Base64 alphabets and the block hash part is
    /// represented as variable number of Base64 alphabets.
    /// However, ssdeep does not use Base64 encoding
    /// (since ssdeep generates a 6-bit hash value per "piece").
    pub const ALPHABET_SIZE: usize = 64;

    /// The maximum size of the block hash.
    ///
    /// ssdeep is a fuzzy *hash*.  We should be able to easily interchange
    /// the hash value and storing 6-bit hash values for all pieces is not useful
    /// enough.
    /// This constant limits the number of "pieces" to store in each block hash.
    ///
    /// Note that, since ssdeep is not a cryptographic hash and is in variable
    /// length, it's important to limit the size of the block hash to prevent
    /// an adversary to generate a number of "pieces" by placing an adversarial
    /// pattern (that would make the resulting hash huge if the size of the
    /// block hash is not limited properly).
    pub const FULL_SIZE: usize = 64;

    /// The half (truncated) size of the block hash.
    ///
    /// This is the half of [`FULL_SIZE`].
    ///
    /// Normally, the second block hash is truncated to this size.
    ///
    /// See also:
    /// ["Truncation" section of `FuzzyHashData`](crate::hash::FuzzyHashData#truncation)
    pub const HALF_SIZE: usize = FULL_SIZE / 2;

    /// The maximum size of the sequence so that the same character can be
    /// repeated in a normalized block hash.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](crate::hash::FuzzyHashData#normalization)
    pub const MAX_SEQUENCE_SIZE: usize = 3;

    /// The minimum length of the common substring to compute edit distance
    /// between two block hashes.
    ///
    /// To score similarity between two block hashes with the same block size,
    /// ssdeep expects that two block hashes are similar enough.
    /// In specific, ssdeep expects that they
    /// [have a common substring](crate::compare::position_array::BlockHashPositionArrayImpl::has_common_substring)
    /// of a length [`MIN_LCS_FOR_COMPARISON`] or longer to reduce the
    /// possibility of false matches by chance.
    ///
    /// If we couldn't find such a common substring, the low level block hash
    /// comparison method returns zero (meaning, not similar).
    ///
    /// Finding such common substrings is a special case of finding a
    /// [longest common substring (LCS)](https://en.wikipedia.org/wiki/Longest_common_substring).
    ///
    /// For instance, those two strings:
    ///
    /// *  `+r/kcOpEYXB+0ZJ`
    /// *  `7ocOpEYXB+0ZF29`
    ///
    /// have a common substring `cOpEYXB+0Z` (length 10), long enough
    /// (≧ [`MIN_LCS_FOR_COMPARISON`]) to compute the edit distance to compute
    /// the similarity score.
    ///
    /// See also: ["Fuzzy Hash Comparison" section of `FuzzyHashData`](crate::hash::FuzzyHashData#fuzzy-hash-comparison)
    pub const MIN_LCS_FOR_COMPARISON: usize = 7;

    /// Numeric windows of a block hash, each value representing unique value
    /// corresponding a substring of length [`MIN_LCS_FOR_COMPARISON`].
    ///
    /// An object with this type is created by either of those methods
    /// (*normalized forms only*):
    ///
    /// *   [`FuzzyHashData::block_hash_1_numeric_windows()`](crate::hash::FuzzyHashData::block_hash_1_numeric_windows())
    /// *   [`FuzzyHashData::block_hash_2_numeric_windows()`](crate::hash::FuzzyHashData::block_hash_2_numeric_windows())
    ///
    /// Unlike [`block_hash_1_windows()`](crate::hash::FuzzyHashData::block_hash_1_windows()) and
    /// [`block_hash_2_windows()`](crate::hash::FuzzyHashData::block_hash_2_windows()),
    /// each element of this iterator is a numeric value.
    ///
    /// This numeric form has an one-to-one correspondence with the original
    /// substring (and is compressed).  In the current ssdeep-compatible
    /// configuration, each value is a 42-bit unsigned integer, generated from
    /// seven (7) hash characters (consuming 6 bits each).
    ///
    /// See also: [`FuzzyHashData::block_hash_1_windows()`](crate::hash::FuzzyHashData::block_hash_1_windows())
    ///
    /// *Note*:
    /// 7 equals [`MIN_LCS_FOR_COMPARISON`] and
    /// 6 equals the base-2 logarithm of [`ALPHABET_SIZE`].
    pub struct NumericWindows<'a> {
        /// Remaining block hash portion to compute numeric windows.
        v: &'a [u8],
        /// The "last" value of the numeric windows iterator
        /// (an incomplete value when no values are generated yet).
        ///
        /// The [`Self::next()`] value can be retrieved by
        /// [shifting this value](Self::ILOG2_OF_ALPHABETS),
        /// [masking](Self::MASK) and then adding the first byte of [`Self::v`].
        hash: u64,
    }

    /// Numeric windows of a block hash, each value representing unique value
    /// corresponding a substring of length [`MIN_LCS_FOR_COMPARISON`] *and*
    /// the block size.
    ///
    /// An object with this type is created by either of those methods
    /// (*normalized forms only*):
    ///
    /// *   [`FuzzyHashData::block_hash_1_index_windows()`](crate::hash::FuzzyHashData::block_hash_1_index_windows())
    /// *   [`FuzzyHashData::block_hash_2_index_windows()`](crate::hash::FuzzyHashData::block_hash_2_index_windows())
    ///
    /// This is similar to that of [`NumericWindows`] but each numeric value
    /// *also* contains the *base-2 logarithm* form of the block size
    /// (at highest bits).
    ///
    /// This numeric form has an one-to-one correspondence with the original
    /// substring plus the block size.  In the current ssdeep-compatible
    /// configuration, each value is a 47-bit unsigned integer, generated from
    /// low 42-bit value from [`NumericWindows`] and high 5-bit value from
    /// the block size.
    pub struct IndexWindows<'a> {
        /// Inner [`NumericWindows`] object.
        inner: NumericWindows<'a>,
        /// The *base-2 logarithm* form of the block size.
        log_block_size: u8,
    }

    impl<'a> NumericWindows<'a> {
        /*
            TODO:
            Once MSRV of 1.57 is acceptable, ILOG2_OF_ALPHABETS and MASK
            can be calculated dynamically.
            If MSRV of 1.67 is acceptable, its definition will be more natural.
        */

        /// A Base-2 logarithm of [`ALPHABET_SIZE`].
        pub(crate) const ILOG2_OF_ALPHABETS: u32 = 6;

        /// The width of a substring (in a numeric form) in bits.
        pub const BITS: u32 = (MIN_LCS_FOR_COMPARISON as u32) * Self::ILOG2_OF_ALPHABETS;

        /// The mask value corresponding [`BITS`](Self::BITS).
        pub const MASK: u64 = (1u64 << Self::BITS).wrapping_sub(1);

        /// Creates a new object from an existing block hash.
        #[inline]
        pub(crate) fn new(block_hash: &'a [u8]) -> Self {
            if block_hash.len() < MIN_LCS_FOR_COMPARISON {
                Self { v: &[], hash: 0 }
            } else {
                // grcov-excl-br-start
                Self {
                    v: &block_hash[MIN_LCS_FOR_COMPARISON - 1..],
                    hash: block_hash[..MIN_LCS_FOR_COMPARISON - 1]
                        .iter()
                        .enumerate()
                        .map(|(i, &value)| {
                            (value as u64)
                                << (Self::ILOG2_OF_ALPHABETS
                                    * (MIN_LCS_FOR_COMPARISON - 2 - i) as u32)
                        })
                        .fold(
                            0u64,
                            #[inline(always)]
                            |x, y| x | y,
                        ),
                }
                // grcov-excl-br-stop
            }
        }
    }

    impl<'a> IndexWindows<'a> {
        /// The actual number of bits consumed by the block size.
        pub(crate) const BLOCK_SIZE_BITS: u32 = 5;

        /// The width of a substring (in a numeric form) in bits.
        pub const BITS: u32 = NumericWindows::BITS + Self::BLOCK_SIZE_BITS;

        /// The mask value corresponding [`BITS`](Self::BITS).
        pub const MASK: u64 = (1u64 << Self::BITS).wrapping_sub(1);

        /// Creates a new object from an existing block hash and the block size.
        #[inline]
        pub(crate) fn new(block_hash: &'a [u8], log_block_size: u8) -> Self {
            Self {
                inner: NumericWindows::new(block_hash),
                log_block_size,
            }
        }
    }

    impl Iterator for NumericWindows<'_> {
        type Item = u64;

        #[inline]
        fn next(&mut self) -> Option<Self::Item> {
            if let Some((&value, rest)) = self.v.split_first() {
                self.hash = ((self.hash << Self::ILOG2_OF_ALPHABETS) | (value as u64)) & Self::MASK;
                self.v = rest;
                Some(self.hash)
            } else {
                None
            }
        }

        #[inline]
        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.v.len(), Some(self.v.len()))
        }
    }

    impl Iterator for IndexWindows<'_> {
        type Item = u64;

        #[inline(always)]
        fn next(&mut self) -> Option<Self::Item> {
            self.inner.next().map(
                #[inline(always)]
                |x| (x | ((self.log_block_size as u64) << NumericWindows::BITS)),
            )
        }

        #[inline(always)]
        fn size_hint(&self) -> (usize, Option<usize>) {
            self.inner.size_hint()
        }
    }

    impl ExactSizeIterator for NumericWindows<'_> {
        #[inline]
        fn len(&self) -> usize {
            self.v.len()
        }
    }

    impl ExactSizeIterator for IndexWindows<'_> {
        #[inline]
        fn len(&self) -> usize {
            self.inner.len()
        }
    }

    #[allow(unsafe_code)]
    #[cfg(all(feature = "unsafe-guarantee", feature = "unstable"))]
    unsafe impl core::iter::TrustedLen for NumericWindows<'_> {}
    #[allow(unsafe_code)]
    #[cfg(all(feature = "unsafe-guarantee", feature = "unstable"))]
    unsafe impl core::iter::TrustedLen for IndexWindows<'_> {}

    impl core::iter::FusedIterator for NumericWindows<'_> {}
    impl core::iter::FusedIterator for IndexWindows<'_> {}
}

/// A generic type to constrain given block hash size using [`ConstrainedBlockHashSize`].
pub struct BlockHashSize<const N: usize> {}
/// A generic type to constrain given two block hash sizes using [`ConstrainedBlockHashSizes`].
pub struct BlockHashSizes<const S1: usize, const S2: usize> {}

/// Private module to declare sealed block hash constraints.
mod private {
    use super::{block_hash, BlockHashSize, BlockHashSizes};

    /// A trait to constrain block hash size.
    ///
    /// This type is implemented for [`BlockHashSize`] with following sizes:
    ///
    /// *   [`block_hash::FULL_SIZE`]
    /// *   [`block_hash::HALF_SIZE`]
    ///
    /// This is a sealed trait.
    pub trait SealedBlockHashSize {}
    impl SealedBlockHashSize for BlockHashSize<{ block_hash::FULL_SIZE }> {}
    impl SealedBlockHashSize for BlockHashSize<{ block_hash::HALF_SIZE }> {}

    /// A trait to constrain block hash sizes.
    ///
    /// This type is implemented for [`BlockHashSizes`] with following sizes:
    ///
    /// *   [`block_hash::FULL_SIZE`] and [`block_hash::FULL_SIZE`]
    /// *   [`block_hash::FULL_SIZE`] and [`block_hash::HALF_SIZE`]
    ///
    /// This is a sealed trait.
    pub trait SealedBlockHashSizes {}
    impl SealedBlockHashSizes for BlockHashSizes<{ block_hash::FULL_SIZE }, { block_hash::FULL_SIZE }> {}
    impl SealedBlockHashSizes for BlockHashSizes<{ block_hash::FULL_SIZE }, { block_hash::HALF_SIZE }> {}
}

/// A trait to constrain block hash size.
///
/// This type is implemented for [`BlockHashSize`] with following sizes:
///
/// *   [`block_hash::FULL_SIZE`]
/// *   [`block_hash::HALF_SIZE`]
///
/// Note that this trait is intentionally designed to be non-extensible
/// (using the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html)).
pub trait ConstrainedBlockHashSize: private::SealedBlockHashSize {
    /// The maximum size of a block hash.
    const SIZE: usize;
}
impl<const SZ_BH: usize> ConstrainedBlockHashSize for BlockHashSize<SZ_BH>
where
    BlockHashSize<SZ_BH>: private::SealedBlockHashSize,
{
    const SIZE: usize = SZ_BH;
}

/// A trait to constrain block hash sizes.
///
/// This type is implemented for [`BlockHashSizes`] with following sizes:
///
/// *   [`block_hash::FULL_SIZE`] and [`block_hash::FULL_SIZE`]
/// *   [`block_hash::FULL_SIZE`] and [`block_hash::HALF_SIZE`]
///
/// Note that this trait is intentionally designed to be non-extensible
/// (using the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html)).
pub trait ConstrainedBlockHashSizes: private::SealedBlockHashSizes {
    /// The maximum size of the block hash 1.
    const MAX_BLOCK_HASH_SIZE_1: usize;
    /// The maximum size of the block hash 2.
    const MAX_BLOCK_HASH_SIZE_2: usize;
}
impl<const S1: usize, const S2: usize> ConstrainedBlockHashSizes for BlockHashSizes<S1, S2>
where
    BlockHashSizes<S1, S2>: private::SealedBlockHashSizes,
{
    const MAX_BLOCK_HASH_SIZE_1: usize = S1;
    const MAX_BLOCK_HASH_SIZE_2: usize = S2;
}

/// Constant assertions related to this module.
#[doc(hidden)]
mod const_asserts {
    use super::{block_hash, block_size};
    use static_assertions::{const_assert, const_assert_eq, const_assert_ne};

    // We must restrict alphabet size to number of Base64 alphabets.
    // It minimizes memory usage of FuzzyHashCompareTarget.
    const_assert_eq!(block_hash::ALPHABET_SIZE, 64);

    // FULL_SIZE must be even.
    const_assert!(block_hash::FULL_SIZE % 2 == 0);

    // Compare with original ssdeep constants
    // fuzzy.h: SPAMSUM_LENGTH
    const_assert_eq!(block_hash::FULL_SIZE, 64);
    // fuzzy.c: MIN_BLOCKSIZE
    const_assert_eq!(block_size::MIN, 3);
    // fuzzy.c: NUM_BLOCKHASHES
    const_assert_eq!(block_size::NUM_VALID, 31);
    // fuzzy.c: (implementation of memcpy_eliminate_sequences)
    const_assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);

    // NUM_VALID + 1 must be a valid u8 value.
    const_assert_ne!(block_size::NUM_VALID as u8, u8::MAX);

    // MAX_SEQUENCE_SIZE: fits in u32 and safe to add 1 (in either u32 or usize)
    const_assert!(block_hash::MAX_SEQUENCE_SIZE < 0xffff_ffff);
    const_assert_ne!(block_hash::MAX_SEQUENCE_SIZE, usize::MAX);

    // block_size::NUM_VALID - 1 indicates the largest n so that
    // (block_size::MIN << n) fits in 32-bits.
    const_assert!((block_size::MIN as u64) << (block_size::NUM_VALID - 1) <= u32::MAX as u64);
    const_assert!((block_size::MIN as u64) << block_size::NUM_VALID > u32::MAX as u64);

    // For block_hash::NumericWindow
    const_assert!(block_hash::MIN_LCS_FOR_COMPARISON > 0);
}

mod tests;
