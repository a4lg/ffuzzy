// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

use core::cmp::Ordering;
use crate::macros::{optionally_unsafe, invariant};


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
/// In this crate, it can efficiently handle such relations by using the
/// [*base-2 logarithms* form of the block size](crate::FuzzyHashData#block-size)
/// (no multiplication required).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSizeRelation {
    /// Two block sizes are *far* and a block hash comparison
    /// cannot be performed.
    Far,
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
}

impl BlockSizeRelation {
    /// Checks whether a given value denotes one of the three *near* cases.
    pub fn is_near(&self) -> bool {
        !matches!(self, BlockSizeRelation::Far)
    }
}


/// Utility related to block size part of the fuzzy hash.
///
/// See also: ["Block Size" section of `FuzzyHashData`](crate::FuzzyHashData#block-size)
#[allow(non_snake_case)]
pub mod BlockSize {
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
    /// `NUM_VALID` is the smallest value which 2<sup>n</sup>
    /// exceeds [`u32::MAX`].
    pub const NUM_VALID: usize = 31;

    /// Checks whether a given block size is valid.
    #[inline]
    pub(crate) fn is_valid(block_size: u32) -> bool {
        (block_size % MIN == 0) && (block_size / MIN).is_power_of_two()
    }

    /// Checks whether *base-2 logarithm* form of the block size is valid.
    #[inline(always)]
    pub const fn is_log_valid(log_block_size: u8) -> bool {
        log_block_size < NUM_VALID as u8
    }

    /// Converts *base-2 logarithm* form of the block size to the actual one
    /// without checking validity of the block size.
    ///
    /// `log_block_size` must be valid.
    ///
    /// See also:
    /// ["Block Size" section of `FuzzyHashData`](crate::FuzzyHashData#block-size)
    #[inline(always)]
    pub(crate) const fn from_log_unchecked(log_block_size: u8) -> u32 {
        MIN << log_block_size
    }

    /// Converts *base-2 logarithm* form of the block size to the actual one.
    ///
    /// It returns [`None`] if `log_block_size` is not valid.
    ///
    /// See also:
    /// ["Block Size" section of `FuzzyHashData`](crate::FuzzyHashData#block-size)
    #[inline]
    pub fn from_log(log_block_size: u8) -> Option<u32> {
        if is_log_valid(log_block_size) {
            Some(from_log_unchecked(log_block_size))
        }
        else {
            None
        }
    }

    /// Precomputed block size strings.
    ///
    /// All valid block sizes are precomputed as raw strings to avoid
    /// calling [`u32::to_string`](std::string::ToString::to_string)
    /// from [`FuzzyHash::to_string`](crate::FuzzyHash::to_string).
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
    /// *   `BlockSize::MIN == 3`
    /// *   `BlockSize::NUM_VALID == 31`
    const LOG_DEBRUIJN_CONSTANT: u32 = 0x05773e35;

    /// The custom table for a variant of de Bruijn sequence to convert
    /// all valid block size values into the *base-2 logarithm* form.
    ///
    /// The element `[0x11]` is unused (and assigned an invalid number `0xff`).
    ///
    /// See [`LOG_DEBRUIJN_CONSTANT`] for internal notes.
    const LOG_DEBRUIJN_TABLE: [u8; 32] = [
        0x04, 0x05, 0x00, 0x06, 0x01, 0x0b, 0x07, 0x19,
        0x02, 0x17, 0x15, 0x0c, 0x08, 0x0e, 0x11, 0x1a,
        0x03, 0xff, 0x0a, 0x18, 0x16, 0x14, 0x0d, 0x10,
        0x1e, 0x09, 0x13, 0x0f, 0x1d, 0x12, 0x1c, 0x1b,
    ];

    /// The internal implementation of [`log_from_valid_unchecked`].
    #[inline(always)]
    pub(crate) fn log_from_valid_internal(block_size: u32) -> u8 {
        let value = LOG_DEBRUIJN_TABLE[(block_size.wrapping_mul(LOG_DEBRUIJN_CONSTANT) >> 27) as usize]; // grcov-excl-br-line:ARRAY
        debug_assert!(is_valid(block_size));
        optionally_unsafe! {
            invariant!((value as usize) < NUM_VALID);
        }
        value
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
    #[cfg(feature = "unsafe")]
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
        debug_assert!(is_log_valid(lhs));
        debug_assert!(is_log_valid(rhs));
        is_near_lt(rhs, lhs)
    }

    /// Compare two *base-2 logarithm* forms of the block size values to
    /// determine the relation between two block sizes.
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


/// Utility (constants) related to block hash part of the fuzzy hash.
///
/// See also: ["Block Hashes" section of `FuzzyHashData`](crate::FuzzyHashData#block-hashes)
#[allow(non_snake_case)]
pub mod BlockHash {
    /// The number of alphabets used in the block hash part of a fuzzy hash.
    ///
    /// It is same as the number of Base64 alphabets and the block hash part is
    /// represented as variable number of Base64 alphabets.
    /// However, ssdeep does not use Base64 encoding
    /// (since ssdeep generates a 6-bit hash value per "piece").
    pub const ALPHABET_SIZE: usize = 64;

    /// The maximum size of each block hash.
    ///
    /// ssdeep is a fuzzy *hash*.  We should be able to easily interchange
    /// the hash value and storing 6-bit hash values for all pieces is not useful
    /// enough.
    /// This constant limits the number of "pieces" to store in each block hash.
    ///
    /// Note that, since ssdeep is not a cryptographic hash, it's important to
    /// limit the size of the block hash to prevent an adversary to generate a
    /// number of "pieces" by placing an adversarial pattern (that would make
    /// the resulting hash huge if the size of the block hash is not limited
    /// properly).
    pub const FULL_SIZE: usize = 64;

    /// The half size of each block hash.
    ///
    /// This is used when a fuzzy hash is generated.
    /// Normally, the second block hash is truncated to this size.
    pub const HALF_SIZE: usize = FULL_SIZE / 2;

    /// The maximum size of the sequence so that the same character can be
    /// repeated in a block hash.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](crate::FuzzyHashData#normalization)
    pub const MAX_SEQUENCE_SIZE: usize = 3;
}


/// A generic type to constrain given block hash size using [`ConstrainedBlockHashSize`].
pub struct BlockHashSize<const N: usize> {}
/// A generic type to constrain given two block hash sizes using [`ConstrainedBlockHashSizes`].
pub struct BlockHashSizes<const S1: usize, const S2: usize> {}

mod private {
    use super::{BlockHash, BlockHashSize, BlockHashSizes};

    /// A trait to constrain block hash size.
    ///
    /// This type is implemented for [`BlockHashSize`] with following sizes:
    ///
    /// *   [`BlockHash::FULL_SIZE`]
    /// *   [`BlockHash::HALF_SIZE`]
    ///
    /// This is a sealed trait.
    pub trait SealedBlockHashSize {}
    impl SealedBlockHashSize for BlockHashSize<{BlockHash::FULL_SIZE}> {}
    impl SealedBlockHashSize for BlockHashSize<{BlockHash::HALF_SIZE}> {}

    /// A trait to constrain block hash sizes.
    ///
    /// This type is implemented for [`BlockHashSizes`] with following sizes:
    ///
    /// *   [`BlockHash::FULL_SIZE`] and [`BlockHash::FULL_SIZE`]
    /// *   [`BlockHash::FULL_SIZE`] and [`BlockHash::HALF_SIZE`]
    ///
    /// This is a sealed trait.
    pub trait SealedBlockHashSizes {}
    impl SealedBlockHashSizes for BlockHashSizes<{BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}> {}
    impl SealedBlockHashSizes for BlockHashSizes<{BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}> {}
}

/// A trait to constrain block hash size.
///
/// This type is implemented for [`BlockHashSize`] with following sizes:
///
/// *   [`BlockHash::FULL_SIZE`]
/// *   [`BlockHash::HALF_SIZE`]
///
/// Note that this trait is intentionally designed to be non-extensible
/// (using the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html)).
pub trait ConstrainedBlockHashSize: private::SealedBlockHashSize {}
impl<T> ConstrainedBlockHashSize for T where T: private::SealedBlockHashSize {}

/// A trait to constrain block hash sizes.
///
/// This type is implemented for [`BlockHashSizes`] with following sizes:
///
/// *   [`BlockHash::FULL_SIZE`] and [`BlockHash::FULL_SIZE`]
/// *   [`BlockHash::FULL_SIZE`] and [`BlockHash::HALF_SIZE`]
///
/// Note that this trait is intentionally designed to be non-extensible
/// (using the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html)).
pub trait ConstrainedBlockHashSizes: private::SealedBlockHashSizes {}
impl<T> ConstrainedBlockHashSizes for T where T: private::SealedBlockHashSizes {}





/// Constant assertions related to this module.
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::{const_assert, const_assert_eq, const_assert_ne};

    // We must restrict alphabet size to number of Base64 alphabets.
    // It minimizes memory usage of FuzzyHashCompareTarget.
    const_assert_eq!(BlockHash::ALPHABET_SIZE, 64);

    // FULL_SIZE must be even.
    const_assert!(BlockHash::FULL_SIZE % 2 == 0);

    // Compare with original ssdeep constants
    // fuzzy.h: SPAMSUM_LENGTH
    const_assert_eq!(BlockHash::FULL_SIZE, 64);
    // fuzzy.c: MIN_BLOCKSIZE
    const_assert_eq!(BlockSize::MIN, 3);
    // fuzzy.c: NUM_BLOCKHASHES
    const_assert_eq!(BlockSize::NUM_VALID, 31);
    // fuzzy.c: (implementation of memcpy_eliminate_sequences)
    const_assert_eq!(BlockHash::MAX_SEQUENCE_SIZE, 3);

    // MAX_SEQUENCE_SIZE: fits in u32 and safe to add 1 (in either u32 or usize)
    const_assert!(BlockHash::MAX_SEQUENCE_SIZE < 0xffff_ffff);
    const_assert_ne!(BlockHash::MAX_SEQUENCE_SIZE, usize::MAX);

    // BlockSize::NUM_VALID - 1 indicates the largest n so that
    // (BlockSize::MIN << n) fits in 32-bits.
    const_assert!((BlockSize::MIN as u64) << (BlockSize::NUM_VALID - 1) <= u32::MAX as u64);
    const_assert!((BlockSize::MIN as u64) << BlockSize::NUM_VALID > u32::MAX as u64);
}

// grcov-excl-br-start
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    #[test]
    fn test_block_size_log_valid() {
        for i in 0..BlockSize::NUM_VALID as u8 {
            // log(exp(i)) == i.
            assert_eq!(
                i,
                BlockSize::log_from_valid(
                    BlockSize::from_log(i).unwrap()
                )
            );
            #[cfg(feature = "unsafe")]
            unsafe {
                assert_eq!(
                    i,
                    BlockSize::log_from_valid_unchecked(
                        BlockSize::from_log(i).unwrap()
                    )
                );
            }
        }
    }

    #[test]
    fn test_block_size_log_invalid() {
        for i in BlockSize::NUM_VALID as u8..=u8::MAX {
            assert_eq!(BlockSize::from_log(i), None);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_block_size_strings() {
        for i in 0..BlockSize::NUM_VALID as u8 {
            // BLOCK_SIZES_STR must match to converted strings from the block size.
            let block_size = BlockSize::from_log(i).unwrap();
            assert_eq!(BlockSize::BLOCK_SIZES_STR[i as usize], block_size.to_string());
            assert!(BlockSize::BLOCK_SIZES_STR[i as usize].len() <= BlockSize::MAX_BLOCK_SIZE_LEN_IN_CHARS);
        }
    }


    #[cfg(feature = "alloc")]
    #[test]
    fn test_block_size_relation_debug() {
        crate::test_utils::test_auto_debug_for_enum!(
            BlockSizeRelation, [Far, NearEq, NearGt, NearLt]
        );
    }

    #[test]
    fn test_block_size_relation_consistency() {
        for bs1 in 0..BlockSize::NUM_VALID as u8 {
            for bs2 in 0..BlockSize::NUM_VALID as u8 {
                // Use cmp.
                let ord = BlockSize::cmp(bs1, bs2);
                match ord {
                    Ordering::Equal   => assert!(bs1 == bs2),
                    Ordering::Less    => assert!(bs1 < bs2),
                    Ordering::Greater => assert!(bs1 > bs2),
                }
                // Use compare_sizes.
                let rel = BlockSize::compare_sizes(bs1, bs2);
                // Test consistency between logical expressions and the BlockSizeRelation value.
                // TODO: Replace plain subtraction with abs_diff when MSRV 1.60 is acceptable.
                assert_eq!(bs1 == bs2, rel == BlockSizeRelation::NearEq);
                assert_eq!(bs1 == bs2 + 1, rel == BlockSizeRelation::NearGt);
                assert_eq!(bs1 + 1 == bs2, rel == BlockSizeRelation::NearLt);
                assert_eq!(((bs1 as i32) - (bs2 as i32)).abs() > 1, rel == BlockSizeRelation::Far);
                // Test consistency between the result of other functions and the BlockSizeRelation value.
                #[allow(clippy::bool_assert_comparison)]
                match rel.clone() {
                    BlockSizeRelation::Far => {
                        assert_eq!(rel.is_near(), false);
                        assert_eq!(BlockSize::is_near(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_lt(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_eq(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_gt(bs1, bs2), false);
                        assert_ne!(ord, Ordering::Equal);
                    }
                    BlockSizeRelation::NearLt => {
                        assert_eq!(rel.is_near(), true);
                        assert_eq!(BlockSize::is_near(bs1, bs2), true);
                        assert_eq!(BlockSize::is_near_lt(bs1, bs2), true);
                        assert_eq!(BlockSize::is_near_eq(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_gt(bs1, bs2), false);
                        assert_eq!(ord, Ordering::Less);
                    }
                    BlockSizeRelation::NearEq => {
                        assert_eq!(rel.is_near(), true);
                        assert_eq!(BlockSize::is_near(bs1, bs2), true);
                        assert_eq!(BlockSize::is_near_lt(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_eq(bs1, bs2), true);
                        assert_eq!(BlockSize::is_near_gt(bs1, bs2), false);
                        assert_eq!(ord, Ordering::Equal);
                    }
                    BlockSizeRelation::NearGt => {
                        assert_eq!(rel.is_near(), true);
                        assert_eq!(BlockSize::is_near(bs1, bs2), true);
                        assert_eq!(BlockSize::is_near_lt(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_eq(bs1, bs2), false);
                        assert_eq!(BlockSize::is_near_gt(bs1, bs2), true);
                        assert_eq!(ord, Ordering::Greater);
                    }
                }
            }
        }
    }
}
// grcov-excl-br-stop
