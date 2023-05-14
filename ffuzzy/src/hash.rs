// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::base64::BASE64_TABLE_U8;
use crate::hash::block::{
    BlockSize, BlockSizeRelation, BlockHash,
    BlockHashSize, ConstrainedBlockHashSize,
    BlockHashSizes, ConstrainedBlockHashSizes
};
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin, BlockHashParseState
};
use crate::macros::{optionally_unsafe, invariant};


mod algorithms;
pub mod block;
pub mod parser_state;
#[cfg(test)]
mod tests;
#[cfg(any(test, doc))]
pub(crate) mod test_utils;


/// An efficient fixed size fuzzy hash representation.
///
/// # Fuzzy Hash Internals
///
/// A fuzzy hash consists of four parts:
///
/// 1.  Block size (reciprocal of average piece-splitting probability per byte)
///
/// 2.  Block hash 1.  6-bit hash per "piece", variable-length up to
///     [`BlockHash::FULL_SIZE`].
///
///     The average piece-splitting probability is given as `1/block_size`.
/// 3.  Block hash 2.  6-bit hash per "piece", variable-length up to either
///     *   [`BlockHash::HALF_SIZE`] (truncated / short / regular) or
///     *   [`BlockHash::FULL_SIZE`] (non-truncated / long).
///
///     The average piece-splitting probability is given as `1/block_size/2`).
///
/// 4.  (optional) The input file name, which is ignored by the parser
///     on this type.
///
/// This struct stores first three parts of a fuzzy hash.
///
/// You can see the following figure for an example:
///
/// ```text
/// 196608:DfiQF5UWAC2qctjBemsqz7yHlHr4bMCE2J8Y:jBp/Fqz7mlHZCE2J8Y,"/usr/local/bin/rustc"
/// \____/|\__________________________________/|\________________/|\____________________/
///  |    |            Block hash 1            |   Block hash 2   | File name (optional)
///  |    |                                    |                  |
///  |    +-- (sep:colon)                      +-- (sep:colon)    +-- (sep,comma (optional))
///  |
///  +-- Block size
/// ```
///
/// # Block Size
///
/// In the example above, 1 / 196 608 is the average probability for
/// piece-splitting per byte on the block hash 1.  On the block hash 2, the
/// probability is 1 / 393 216 per byte, half of the probability on the
/// block hash 1.
///
/// Since ssdeep uses [a 32-bit hash function](crate::generate::RollingHash)
/// to decide whether to perform a piece-splitting, this probability will get
/// inaccurate as the block size gets larger.
///
/// There is an important property of the block size: all valid block sizes
/// can be represented as [`BlockSize::MIN`] * 2<sup>n</sup> (`n` ≧ 0).
///
/// In this crate, the block size is stored as `n` (the **base-2 logarithm**
/// form of the block size) for higher efficiency.
/// [`log_block_size()`](Self::log_block_size()) method returns this raw
/// representation.  If you need an actual block size as used in the string
/// representation, [`block_size()`](Self::block_size) can be used instead.
///
/// # Block Hashes
///
/// A fuzzy hash has two block hashes (1 and 2).
///
/// They are variable-length fields that store an array of 6-bit "piece" hash
/// values (represented as Base64 characters in the string representation and
/// internally stored as Base64 indices).
///
/// ## Relations with Block Size
///
/// The reason a fuzzy hash having two block hashes is, to enable comparing
/// fuzzy hashes with similar block sizes (but not too far).
///
/// In principle, we can only compare block hashes with the same block size
/// directly.  Think following fuzzy hash for example:
///
/// ```text
/// 6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+
///      \____________________________________________________/ \_______________________/
///       Block hash 1                                                      Block hash 2
///       (effective block size: 6144)                      (effective block size: 12288)
///                                                                [*] 12288 == 6144 * 2
/// ```
///
/// You can easily compare it with another fuzzy hash with the same block size
/// ([but actual block hash similarity scoring only occurs after checking common substring](BlockHash::MIN_LCS_FOR_COMPARISON)).
///
/// ```text
/// Unaligned:
/// [A] 6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+
/// [B] 6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:H5d+X36WnL5d+X3v5d+X315d+X3+
///
/// Aligned:
/// [A] 6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ   :Z5d+X395d+X3X5d+X315d+X3+
/// [B] 6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:H5d+X36WnL5d+X3v5d+X315d+X3+
///          \_______________________________________________________/ \__________________________/
///                                Comparison 1                                Comparison 2
///                       (score([A1], [B1], 6144) = 94)            (score([A2], [B2], 12288) = 85)
///
/// score_final([A], [B], 6144) = max(94, 85) = 94
/// ```
///
/// The final similarity score is the maximum of two block hash comparisons
/// (note that [the `score` function on small block sizes will cap the score to
/// prevent exaggeration of matches](crate::compare::FuzzyHashCompareTarget::score_cap_on_block_hash_comparison())).
///
/// If you have two fuzzy hashes with different block sizes but they are *near*
/// enough, we can still perform a block hash comparison.
///
/// ```text
/// Unaligned:
/// [A] 3072:S+IiyfkMY+BES09JXAnyrZalI+YuyfkMY+BES09JXAnyrZalI+YQ:S+InsMYod+X3oI+YLsMYod+X3oI+YQ
/// [B] 6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+
/// [C] 12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:1+Jr+d++H+5+e
///
/// Aligned:
/// [A] 3072 :S+IiyfkMY+BES09JXAnyrZalI+YuyfkMY+BES09JXAnyrZalI+YQ:S+InsMYod+X3oI+YLsMYod+X3oI+YQ
/// [B] 6144 :                                                     SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+
/// [C] 12288:                                                                                                            Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:1+Jr+d++H+5+e
///           \__________________________________________________/ \____________________________________________________/ \_______________________________/ \___________/
///            Eff.B.S.=3072                                        Eff.B.S.=6144                                          Eff.B.S.=12288                    Eff.B.S.=24576
///                                                                 Comparison between [A2] and [B1]                       Comparison between [B2] and [C1]
///                                                                 (score([A2], [B1], 6144) = 72)                         (score([B2], [C1], 12288) = 88)
///
/// score_final([A], [B], 3072) = score([A2], [B1],  6144) = 72
/// score_final([B], [C], 6144) = score([B2], [C1], 12288) = 88
/// score_final([A], [C], 3072) = 0 (since there's no block hashes to compare)
/// ```
///
/// Such cases are handled with [`BlockSizeRelation`] and [`BlockSize`]
/// utility functions.  We can outline the relation in the table below.
/// Note that each block size is denoted as
/// "Actual block size ([block size in *base-2 logarithm*](Self#block-size))".
///
/// | Left (`lhs`) | Right (`rhs`) | Relation                              |
/// | ------------:| -------------:|:------------------------------------- |
/// |    3072 (10) |     6144 (11) | [`NearLt`](BlockSizeRelation::NearLt) |
/// |    6144 (11) |     3072 (10) | [`NearGt`](BlockSizeRelation::NearGt) |
/// |    6144 (11) |     6144 (11) | [`NearEq`](BlockSizeRelation::NearEq) |
/// |    6144 (11) |    12288 (12) | [`NearLt`](BlockSizeRelation::NearLt) |
/// |   12288 (12) |     6144 (11) | [`NearGt`](BlockSizeRelation::NearGt) |
/// |    3072 (10) |    12288 (12) | [`Far`](BlockSizeRelation::Far)       |
///
/// On highly optimized clustering applications, being aware of the block size
/// relation will be crucial.
///
/// See also: [`BlockSizeRelation`]
///
/// ## Normalization
///
/// To prevent exaggerating the comparison score from repeating patterns,
/// ssdeep processes each block hash before comparison so that a sequence
/// consisting of the same character longer than
/// [`BlockHash::MAX_SEQUENCE_SIZE`] cannot exist.
///
/// For instance, after processing a block hash `122333444455555`, it is
/// converted to `122333444555` (four `4`s and five `5`s are shortened into
/// three `4`s and three `5`s because [`BlockHash::MAX_SEQUENCE_SIZE`] is
/// defined to be three (`3`)).
///
/// In this crate, this process is called *normalization*.
///
/// ssdeep normally generates (as well as [`Generator`](crate::generate::Generator))
/// not normalized, raw fuzzy hashes.  So, making a distinction between normalized
/// and raw forms are important.
///
/// ## Truncation
///
/// ssdeep normally generates (as well as [`Generator`](crate::generate::Generator))
/// *truncated* fuzzy hashes.  In the truncated fuzzy hash, length of block hash
/// 2 is limited to [`BlockHash::HALF_SIZE`], half of the maximum length of
/// block hash 1 ([`BlockHash::FULL_SIZE`]).
///
/// While libfuzzy allows generating non-truncated, long fuzzy hashes, they are
/// typically useless.  So, most operations are performed in short, truncated
/// fuzzy hashes by default.  Short variants of [`FuzzyHashData`] is smaller
/// than longer variants so it can be used to reduce memory footprint.
///
/// # Fuzzy Hash Comparison
///
/// For the basic concept of the comparison, see the
/// ["Relations with Block Size" section](FuzzyHashData#relations-with-block-size)
/// section.
///
/// In this section, we describe the full comparison algorithm.
///
/// 1.  If two normalized hashes `A` and `B` are completely the same,
///     the similarity score is `100` (a perfect match) no matter what.
///
///     This case is not subject to the edit distance-based scoring
///     For instance, [`FuzzyHashCompareTarget::is_comparison_candidate()`](crate::compare::FuzzyHashCompareTarget::is_comparison_candidate())
///     may return `false` on such cases.
///
///     So, this case must be handled separately.
///
/// 2.  For each block hash pair (in which the effective block size match),
///     compute the sub-similarity score as follows:
///
///     1.  Search for a common substring of the length of
///         [`BlockHash::MIN_LCS_FOR_COMPARISON`] or longer.
///
///         If we could not find one, the sub-similarity score is `0` and no
///         edit distance-based scoring is performed.
///
///     2.  Compute the edit distance between two block hashes and scale it
///         *   from `0..=(A.len()+B.len())` (`0` is the perfect match)
///         *   to `0..=100` (`100` is the perfect match).
///
///     3.  For small block sizes,
///         [cap the score to prevent exaggregating the matches](crate::compare::FuzzyHashCompareTarget::score_cap_on_block_hash_comparison())).
///
/// 3.  Take the maximum of sub-similarity scores
///     (`0` if there's no sub-similarity scores
///     i.e. [block sizes are far](BlockSizeRelation::Far)).
///
/// For actual comparison, a
/// [`FuzzyHashCompareTarget`](crate::compare::FuzzyHashCompareTarget) object is used.
/// See this struct for details.
#[repr(align(8))]
#[derive(Copy, Clone)]
pub struct FuzzyHashData<const S1: usize, const S2: usize, const NORM: bool>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Block hash 1.
    ///
    /// Each element contains a 6-bit value which can be easily
    /// converted to a Base64 alphabet.
    /// Elements `[len_blockhash1..]` are always filled with zeroes.
    pub(crate) blockhash1: [u8; S1],

    /// Block hash 2.
    ///
    /// Each element contains a 6-bit value which can be easily
    /// converted to a Base64 alphabet.
    /// Elements `[len_blockhash2..]` are always filled with zeroes.
    pub(crate) blockhash2: [u8; S2],

    /// Length of the block hash 1 (up to [`BlockHash::FULL_SIZE`]).
    pub(crate) len_blockhash1: u8,

    /// Length of the block hash 2 (up to `S2`, either
    /// [`BlockHash::FULL_SIZE`] or [`BlockHash::HALF_SIZE`]).
    pub(crate) len_blockhash2: u8,

    /// *Base-2 logarithm* form of the actual block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](Self#block-size)
    pub(crate) log_blocksize: u8,
}


/// An enumeration representing a cause of a generic fuzzy hash error.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzyHashOperationError {
    /// When converting between two fuzzy hash types, copying block hash
    /// would cause a buffer overflow.
    BlockHashOverflow,
    /// When converting a fuzzy hash to a string, a buffer overflow would occur.
    StringizationOverflow,
}

impl core::fmt::Display for FuzzyHashOperationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            FuzzyHashOperationError::BlockHashOverflow     => "overflow will occur while copying the block hash",
            FuzzyHashOperationError::StringizationOverflow => "overflow will occur while converting to the string representation",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FuzzyHashOperationError {}


/// Implementation for all variants of fuzzy hashes.
///
/// Constants and methods below are available on all variants of fuzzy hashes.
impl<const S1: usize, const S2: usize, const NORM: bool> FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// The maximum size of the block hash 1.
    ///
    /// This value is always [`BlockHash::FULL_SIZE`].
    pub const MAX_BLOCK_HASH_SIZE_1: usize = S1;

    /// The maximum size of the block hash 2.
    ///
    /// This value is either
    /// [`BlockHash::HALF_SIZE`] or [`BlockHash::FULL_SIZE`].
    pub const MAX_BLOCK_HASH_SIZE_2: usize = S2;

    /// Denotes whether the fuzzy type only contains a normalized form.
    pub const IS_NORMALIZED_FORM: bool = NORM;

    /// Denotes whether the fuzzy type can contain a non-truncated fuzzy hash.
    ///
    /// It directly corresponds to
    /// [`MAX_BLOCK_HASH_SIZE_2`](Self::MAX_BLOCK_HASH_SIZE_2).
    pub const IS_LONG_FORM: bool = Self::MAX_BLOCK_HASH_SIZE_2 == BlockHash::FULL_SIZE;

    /// Creates a new fuzzy hash object with empty contents.
    ///
    /// This is equivalent to the fuzzy hash string `3::`.
    pub fn new() -> Self {
        Self {
            blockhash1: [0; S1],
            blockhash2: [0; S2],
            len_blockhash1: 0,
            len_blockhash2: 0,
            log_blocksize: 0,
        }
    }

    /// The internal implementation of [`Self::init_from_internals_raw_unchecked()`].
    fn init_from_internals_raw_internal(
        &mut self,
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) {
        debug_assert!(BlockSize::is_log_valid(log_block_size));
        debug_assert!(block_hash_1_len as usize <= S1);
        debug_assert!(block_hash_2_len as usize <= S2);
        debug_assert!(block_hash_1[..block_hash_1_len as usize].iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        debug_assert!(block_hash_2[..block_hash_2_len as usize].iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        debug_assert!(block_hash_1[block_hash_1_len as usize..].iter().all(|&x| x == 0));
        debug_assert!(block_hash_2[block_hash_2_len as usize..].iter().all(|&x| x == 0));
        if NORM { // grcov-excl-br-line:STATIC_NORM_BRANCH
            debug_assert!(algorithms::is_normalized(block_hash_1, block_hash_1_len));
            debug_assert!(algorithms::is_normalized(block_hash_2, block_hash_2_len));
        }
        self.blockhash1 = *block_hash_1;
        self.blockhash2 = *block_hash_2;
        self.len_blockhash1 = block_hash_1_len;
        self.len_blockhash2 = block_hash_2_len;
        self.log_blocksize = log_block_size;
    }

    /// Initialize the fuzzy hash object with internal contents (raw).
    ///
    /// # Safety
    ///
    /// *   Valid range of `block_hash_1` and `block_hash_2` must consist of
    ///     valid Base64 indices.
    /// *   Invalid ranges of `block_hash_1` and `block_hash_2` must be
    ///     filled with zeroes.
    /// *   `block_hash_1_len` and `block_hash_2_len` must be valid.
    /// *   `log_block_size` must hold a valid *base-2 logarithm* form
    ///     of a block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    ///
    /// If they are not satisfied, the resulting object is corrupted.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn init_from_internals_raw_unchecked(
        &mut self,
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) {
        self.init_from_internals_raw_internal(log_block_size, block_hash_1, block_hash_2, block_hash_1_len, block_hash_2_len)
    }

    /// Initialize the fuzzy hash object with internal contents (raw).
    ///
    /// Because this function assumes that you know the fuzzy hash internals,
    /// it panics when you fail to satisfy fuzzy hash constraints.
    ///
    /// # Usage Constraints
    ///
    /// *   Valid range of `block_hash_1` and `block_hash_2` must consist of
    ///     valid Base64 indices.
    /// *   Invalid ranges of `block_hash_1` and `block_hash_2` must be
    ///     filled with zeroes.
    /// *   `block_hash_1_len` and `block_hash_2_len` must be valid.
    /// *   `log_block_size` must hold a valid *base-2 logarithm* form
    ///     of a block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    #[inline]
    pub fn init_from_internals_raw(
        &mut self,
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) {
        assert!(BlockSize::is_log_valid(log_block_size));
        assert!(block_hash_1_len as usize <= S1);
        assert!(block_hash_2_len as usize <= S2);
        assert!(block_hash_1[..block_hash_1_len as usize].iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        assert!(block_hash_2[..block_hash_2_len as usize].iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        assert!(block_hash_1[block_hash_1_len as usize..].iter().all(|&x| x == 0));
        assert!(block_hash_2[block_hash_2_len as usize..].iter().all(|&x| x == 0));
        if NORM { // grcov-excl-br-line:STATIC_NORM_BRANCH
            assert!(algorithms::is_normalized(block_hash_1, block_hash_1_len));
            assert!(algorithms::is_normalized(block_hash_2, block_hash_2_len));
        }
        self.init_from_internals_raw_internal(
            log_block_size,
            block_hash_1,
            block_hash_2,
            block_hash_1_len,
            block_hash_2_len
        );
    }

    /// The internal implementation of [`Self::new_from_internals_raw_unchecked()`].
    #[allow(dead_code)]
    fn new_from_internals_raw_internal(
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) -> Self
    {
        let mut hash = Self::new();
        hash.init_from_internals_raw_internal(log_block_size, block_hash_1, block_hash_2, block_hash_1_len, block_hash_2_len);
        hash
    }

    /// Creates a new fuzzy hash object with internal contents (raw).
    ///
    /// # Safety
    ///
    /// *   Valid range of `block_hash_1` and `block_hash_2` must consist of
    ///     valid Base64 indices.
    /// *   Invalid ranges of `block_hash_1` and `block_hash_2` must be
    ///     filled with zeroes.
    /// *   `block_hash_1_len` and `block_hash_2_len` must be valid.
    /// *   `log_block_size` must hold a valid *base-2 logarithm* form
    ///     of a block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    ///
    /// If they are not satisfied, the resulting object is corrupted.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn new_from_internals_raw_unchecked(
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) -> Self
    {
        Self::new_from_internals_raw_internal(log_block_size, block_hash_1, block_hash_2, block_hash_1_len, block_hash_2_len)
    }

    /// Creates a new fuzzy hash object with internal contents (raw).
    ///
    /// Because this function assumes that you know the fuzzy hash internals,
    /// it panics when you fail to satisfy fuzzy hash constraints.
    ///
    /// # Usage Constraints
    ///
    /// *   Valid range of `block_hash_1` and `block_hash_2` must consist of
    ///     valid Base64 indices.
    /// *   Invalid ranges of `block_hash_1` and `block_hash_2` must be
    ///     filled with zeroes.
    /// *   `block_hash_1_len` and `block_hash_2_len` must be valid.
    /// *   `log_block_size` must hold a valid *base-2 logarithm* form
    ///     of a block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    #[inline]
    pub fn new_from_internals_raw(
        log_block_size: u8,
        block_hash_1: &[u8; S1],
        block_hash_2: &[u8; S2],
        block_hash_1_len: u8,
        block_hash_2_len: u8
    ) -> Self
    {
        let mut hash = Self::new();
        hash.init_from_internals_raw(log_block_size, block_hash_1, block_hash_2, block_hash_1_len, block_hash_2_len);
        hash
    }

    /// The internal implementation of [`Self::new_from_internals_unchecked()`].
    fn new_from_internals_internal(
        block_size: u32,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        let mut hash = Self::new();
        debug_assert!(BlockSize::is_valid(block_size));
        debug_assert!(block_hash_1.iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        debug_assert!(block_hash_2.iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        optionally_unsafe! {
            invariant!(block_hash_1.len() <= S1);
            invariant!(block_hash_2.len() <= S2);
        }
        hash.blockhash1[..block_hash_1.len()].clone_from_slice(block_hash_1); // grcov-excl-br-line:ARRAY
        hash.blockhash2[..block_hash_2.len()].clone_from_slice(block_hash_2); // grcov-excl-br-line:ARRAY
        hash.len_blockhash1 = block_hash_1.len() as u8;
        hash.len_blockhash2 = block_hash_2.len() as u8;
        hash.log_blocksize = BlockSize::log_from_valid_internal(block_size);
        if NORM { // grcov-excl-br-line:STATIC_NORM_BRANCH
            debug_assert!(algorithms::is_normalized(&hash.blockhash1, hash.len_blockhash1));
            debug_assert!(algorithms::is_normalized(&hash.blockhash2, hash.len_blockhash2));
        }
        hash
    }

    /// Creates a new fuzzy hash object with internal contents.
    ///
    /// # Safety
    ///
    /// *   `block_hash_1` and `block_hash_2` must have valid lengths.
    /// *   Elements of `block_hash_1` and `block_hash_2` must consist of valid
    ///     Base64 indices.
    /// *   `block_size` must hold a valid block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    ///
    /// If they are not satisfied, the resulting object will be corrupted.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn new_from_internals_unchecked(
        block_size: u32,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        Self::new_from_internals_internal(block_size, block_hash_1, block_hash_2)
    }

    /// Creates a new fuzzy hash object with internal contents.
    ///
    /// Because this function assumes that you know the fuzzy hash internals,
    /// it panics when you fail to satisfy fuzzy hash constraints.
    ///
    /// # Usage Constraints
    ///
    /// *   `block_hash_1` and `block_hash_2` must have valid lengths.
    /// *   Elements of `block_hash_1` and `block_hash_2` must consist of valid
    ///     Base64 indices.
    /// *   `block_size` must hold a valid block size.
    /// *   On the normalized variant, contents of `block_hash_1` and
    ///     `block_hash_2` must be normalized.
    #[inline]
    pub fn new_from_internals(
        block_size: u32,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        assert!(BlockSize::is_valid(block_size));
        assert!(block_hash_1.len() <= S1);
        assert!(block_hash_2.len() <= S2);
        assert!(block_hash_1.iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        assert!(block_hash_2.iter().all(|&x| x < BlockHash::ALPHABET_SIZE as u8));
        let hash = Self::new_from_internals_internal(
            block_size,
            block_hash_1,
            block_hash_2
        );
        if NORM { // grcov-excl-br-line:STATIC_NORM_BRANCH
            assert!(algorithms::is_normalized(&hash.blockhash1, hash.len_blockhash1));
            assert!(algorithms::is_normalized(&hash.blockhash2, hash.len_blockhash2));
        }
        hash
    }

    /// The *base-2 logarithm* form of the block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](Self#block-size)
    #[inline(always)]
    pub fn log_block_size(&self) -> u8 { self.log_blocksize }

    /// The block size of the fuzzy hash.
    #[inline]
    pub fn block_size(&self) -> u32 {
        BlockSize::from_log_internal(self.log_blocksize)
    }

    /// A reference to the block hash 1.
    ///
    /// # Safety
    ///
    /// You cannot modify a fuzzy hash while block hashes are borrowed through
    /// [`block_hash_1()`](Self::block_hash_1()) or
    /// [`block_hash_2()`](Self::block_hash_2()).
    ///
    /// ```compile_fail
    /// let mut hash: ssdeep::FuzzyHash = str::parse("3:aaaa:bbbb").unwrap();
    /// let bh1 = hash.block_hash_1();
    /// hash.normalize_in_place(); // <- ERROR: because the block hash 1 is borrowed.
    /// // If normalize_in_place succeeds, bh1 will hold an invalid slice
    /// // because the block hash 1 is going to be length 3 after the normalization.
    /// assert_eq!(bh1.len(), 4);
    /// ```
    #[inline]
    pub fn block_hash_1(&self) -> &[u8] {
        optionally_unsafe! {
            invariant!((self.len_blockhash1 as usize) <= S1);
        }
        &self.blockhash1[..self.len_blockhash1 as usize] // grcov-excl-br-line:ARRAY
    }

    /// A reference to the block hash 1 (in fixed-size array).
    ///
    /// Elements that are not a part of the block hash are filled with zeroes.
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    #[inline]
    pub fn block_hash_1_as_array(&self) -> &[u8; S1] {
        &self.blockhash1
    }

    /// The length of the block hash 1.
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    #[inline]
    pub fn block_hash_1_len(&self) -> usize {
        self.len_blockhash1 as usize
    }

    /// A reference to the block hash 2.
    ///
    /// # Safety
    ///
    /// You cannot modify a fuzzy hash while block hashes are borrowed through
    /// [`block_hash_1()`](Self::block_hash_1()) or
    /// [`block_hash_2()`](Self::block_hash_2()).
    ///
    /// ```compile_fail
    /// let mut hash: ssdeep::FuzzyHash = str::parse("3:aaaa:bbbb").unwrap();
    /// let bh2 = hash.block_hash_2();
    /// hash.normalize_in_place(); // <- ERROR: because the block hash 2 is borrowed.
    /// // If normalize_in_place succeeds, bh2 will hold an invalid slice
    /// // because the block hash 2 is going to be length 3 after the normalization.
    /// assert_eq!(bh2.len(), 4);
    /// ```
    #[inline]
    pub fn block_hash_2(&self) -> &[u8] {
        optionally_unsafe! {
            invariant!((self.len_blockhash2 as usize) <= S2);
        }
        &self.blockhash2[..self.len_blockhash2 as usize] // grcov-excl-br-line:ARRAY
    }

    /// A reference to the block hash 2 (in fixed-size array).
    ///
    /// Elements that are not a part of the block hash are filled with zeroes.
    ///
    /// See also: [`block_hash_2()`](Self::block_hash_2())
    #[inline]
    pub fn block_hash_2_as_array(&self) -> &[u8; S2] {
        &self.blockhash2
    }

    /// The length of the block hash 2.
    ///
    /// See also: [`block_hash_2()`](Self::block_hash_2())
    #[inline]
    pub fn block_hash_2_len(&self) -> usize {
        self.len_blockhash2 as usize
    }

    /// The length of this fuzzy hash in the string representation.
    ///
    /// This is the exact size (bytes and characters) required to store the
    /// string representation corresponding this fuzzy hash object.
    #[inline]
    pub fn len_in_str(&self) -> usize {
        debug_assert!(BlockSize::is_log_valid(self.log_blocksize));
        optionally_unsafe! {
            invariant!((self.log_blocksize as usize) < BlockSize::NUM_VALID);
            BlockSize::BLOCK_SIZES_STR[self.log_blocksize as usize].len() // grcov-excl-br-line:ARRAY
                + self.len_blockhash1 as usize
                + self.len_blockhash2 as usize
                + 2
        }
    }

    /// The maximum length in the string representation.
    ///
    /// This is the maximum possible value of
    /// the [`len_in_str()`](Self::len_in_str()) method.
    pub const MAX_LEN_IN_STR: usize = BlockSize::MAX_BLOCK_SIZE_LEN_IN_CHARS
        + Self::MAX_BLOCK_HASH_SIZE_1
        + Self::MAX_BLOCK_HASH_SIZE_2
        + 2;

    /*
        #[allow(clippy::inherent_to_string_shadow_display)] BELOW IS INTENTIONAL.
        Display trait and to_string method below are equivalent and shadowing
        default to_string helps improving the performance.
    */
    /// Converts the fuzzy hash to the string.
    #[cfg(feature = "alloc")]
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        debug_assert!((self.len_blockhash1 as usize) <= BlockHash::FULL_SIZE);
        debug_assert!((self.len_blockhash2 as usize) <= BlockHash::FULL_SIZE);
        debug_assert!(BlockSize::is_log_valid(self.log_blocksize));
        let mut buf = String::with_capacity(self.len_in_str());
        optionally_unsafe! {
            invariant!((self.log_blocksize as usize) < BlockSize::NUM_VALID);
        }
        buf.push_str(BlockSize::BLOCK_SIZES_STR[self.log_blocksize as usize]); // grcov-excl-br-line:ARRAY
        buf.push(':');
        algorithms::insert_block_hash_into_str(
            &mut buf,
            &self.blockhash1,
            self.len_blockhash1
        );
        buf.push(':');
        algorithms::insert_block_hash_into_str(
            &mut buf,
            &self.blockhash2,
            self.len_blockhash2
        );
        buf
    }

    /// Store the string representation of the fuzzy hash into the bytes.
    /// Returns whether the operation has succeeded.
    ///
    /// The only case this function will fail (returns an [`Err`]) is,
    /// when `buffer` does not have enough size to store string representation
    /// of the fuzzy hash.
    ///
    /// Required size of the `buffer` is
    /// [`len_in_str()`](Self::len_in_str()) bytes.  This size is exact.
    ///
    /// # Incompatibility Notice
    ///
    /// On the version 0.3.0, the result type will be changed to
    /// `Result<usize, FuzzyHashOperationError>` in which the non-error
    /// result is equivalent to [`len_in_str()`](Self::len_in_str()).
    ///
    /// It will simplify handling the result.
    pub fn store_into_bytes(&self, buffer: &mut [u8])
        -> Result<(), FuzzyHashOperationError>
    {
        if buffer.len() < self.len_in_str() {
            return Err(FuzzyHashOperationError::StringizationOverflow);
        }
        optionally_unsafe! {
            invariant!((self.log_blocksize as usize) < BlockSize::NUM_VALID);
            let block_size_str =
                BlockSize::BLOCK_SIZES_STR[self.log_blocksize as usize].as_bytes(); // grcov-excl-br-line:ARRAY
            invariant!(block_size_str.len() <= buffer.len());
            buffer[..block_size_str.len()].copy_from_slice(block_size_str); // grcov-excl-br-line:ARRAY
            let mut i: usize = block_size_str.len();
            invariant!(i < buffer.len());
            buffer[i] = b':'; // grcov-excl-br-line:ARRAY
            i += 1;
            algorithms::insert_block_hash_into_bytes(
                &mut buffer[i..],
                &self.blockhash1,
                self.len_blockhash1
            );
            i += self.len_blockhash1 as usize;
            invariant!(i < buffer.len());
            buffer[i] = b':'; // grcov-excl-br-line:ARRAY
            i += 1;
            algorithms::insert_block_hash_into_bytes(
                &mut buffer[i..],
                &self.blockhash2,
                self.len_blockhash2
            );
        }
        Ok(())
    }

    /// Parse a fuzzy hash from given bytes (a slice of [`u8`])
    /// of a string representation.
    pub fn from_bytes(str: &[u8])
        -> Result<Self, ParseError>
    {
        let mut fuzzy = Self::new();
        // Parse fuzzy hash
        let mut i = 0; // ignored
        match algorithms::parse_block_size_from_bytes(str, &mut i) {
            Ok(bs) => {
                fuzzy.log_blocksize = BlockSize::log_from_valid_internal(bs);
            }
            Err(err) => { return Err(err); }
        }
        match algorithms::parse_block_hash_from_bytes::<S1, NORM>(
            &mut fuzzy.blockhash1,
            &mut fuzzy.len_blockhash1,
            str, &mut i
        ) {
            // End of BH1: Only colon is acceptable as the separator between BH1:BH2.
            BlockHashParseState::MetColon => { }
            BlockHashParseState::MetComma => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockHash1, i - 1
                ));
            }
            BlockHashParseState::Base64Error => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockHash1, i
                ));
            }
            BlockHashParseState::MetEndOfString => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedEndOfString,
                    ParseErrorOrigin::BlockHash1, i
                ));
            }
            BlockHashParseState::OverflowError => {
                return Err(ParseError(
                    ParseErrorKind::BlockHashIsTooLong,
                    ParseErrorOrigin::BlockHash1, i
                ));
            }
        }
        match algorithms::parse_block_hash_from_bytes::<S2, NORM>(
            &mut fuzzy.blockhash2,
            &mut fuzzy.len_blockhash2,
            str, &mut i
        ) {
            // End of BH2: Optional comma or end-of-string is expected.
            BlockHashParseState::MetComma | BlockHashParseState::MetEndOfString => { }
            BlockHashParseState::MetColon => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockHash2, i - 1
                ));
            }
            BlockHashParseState::Base64Error => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockHash2, i
                ));
            }
            BlockHashParseState::OverflowError => {
                return Err(ParseError(
                    ParseErrorKind::BlockHashIsTooLong,
                    ParseErrorOrigin::BlockHash2, i
                ));
            }
        }
        Ok(fuzzy)
    }

    /// Normalize the fuzzy hash in place.
    ///
    /// After calling this method, `self` will be normalized.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](Self#normalization)
    pub fn normalize_in_place(&mut self) {
        algorithms::normalize_block_hash_in_place(
            &mut self.blockhash1,
            &mut self.len_blockhash1
        );
        algorithms::normalize_block_hash_in_place(
            &mut self.blockhash2,
            &mut self.len_blockhash2
        );
    }

    /// Performs full validity checking of the internal structure.
    ///
    /// The primary purpose of this is debugging and it should always
    /// return [`true`] unless...
    ///
    /// 1.  There is a bug in this crate, corrupting this structure or
    /// 2.  A memory corruption is occurred somewhere else.
    ///
    /// Because of its purpose, this method is not designed to be fast.
    ///
    /// Note that, despite that it is only relevant to users when the `unsafe`
    /// feature is enabled but made public without any features because this
    /// method is not *unsafe*.
    pub fn is_valid(&self) -> bool {
        BlockSize::is_log_valid(self.log_blocksize)
            && (self.len_blockhash1 as usize) <= S1
            && (self.len_blockhash2 as usize) <= S2
            && self.blockhash1[..self.len_blockhash1 as usize]
                .iter().all(|&x| { x < BlockHash::ALPHABET_SIZE as u8 })
            && self.blockhash1[self.len_blockhash1 as usize..]
                .iter().all(|&x| { x == 0 })
            && self.blockhash2[..self.len_blockhash2 as usize]
                .iter().all(|&x| { x < BlockHash::ALPHABET_SIZE as u8 })
            && self.blockhash2[self.len_blockhash2 as usize..]
                .iter().all(|&x| { x == 0 })
            && (!NORM || (
                algorithms::is_normalized(
                    &self.blockhash1,
                    self.len_blockhash1
                ) &&
                algorithms::is_normalized(
                    &self.blockhash2,
                    self.len_blockhash2
                )
            ))
    }

    /// Performs full equality checking of the internal structure.
    ///
    /// While [`PartialEq::eq()`] for this type is designed to be fast by
    /// ignoring non-block hash bytes, this method performs full equality
    /// checking, *not* ignoring "non-block hash" bytes.
    ///
    /// The primary purpose of this is debugging and it should always
    /// return the same value as [`PartialEq::eq()`] result unless...
    ///
    /// 1.  There is a bug in this crate, corrupting this structure or
    /// 2.  A memory corruption is occurred somewhere else.
    ///
    /// Because of its purpose, this method is not designed to be fast.
    ///
    /// Note that, despite that it is only relevant to users when the `unsafe`
    /// feature is enabled but made public without any features because this
    /// method is not *unsafe*.
    pub fn full_eq(&self, other: &Self) -> bool {
        // This is the auto-generated code by rust-analyzer as the default
        // PartialEq implementation of FuzzyHashData struct.
        self.blockhash1 == other.blockhash1 &&
        self.blockhash2 == other.blockhash2 &&
        self.len_blockhash1 == other.len_blockhash1 &&
        self.len_blockhash2 == other.len_blockhash2 &&
        self.log_blocksize == other.log_blocksize
    }

    /// Compare two *base-2 logarithm* forms of the block size values from
    /// given two fuzzy hashes to determine their block size relation.
    #[inline]
    pub fn compare_block_sizes(
        lhs: impl AsRef<Self>,
        rhs: impl AsRef<Self>
    ) -> BlockSizeRelation
    {
        BlockSize::compare_sizes(
            lhs.as_ref().log_blocksize,
            rhs.as_ref().log_blocksize
        )
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// from given two fuzzy hashes form a near relation.
    #[inline]
    pub fn is_block_sizes_near(
        lhs: impl AsRef<Self>,
        rhs: impl AsRef<Self>
    ) -> bool
    {
        BlockSize::is_near(
            lhs.as_ref().log_blocksize,
            rhs.as_ref().log_blocksize
        )
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// from given two fuzzy hashes form a [`BlockSizeRelation::NearEq`]
    /// relation.
    #[inline]
    pub fn is_block_sizes_near_eq(
        lhs: impl AsRef<Self>,
        rhs: impl AsRef<Self>
    ) -> bool
    {
        BlockSize::is_near_eq(
            lhs.as_ref().log_blocksize,
            rhs.as_ref().log_blocksize
        )
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// from given two fuzzy hashes form a [`BlockSizeRelation::NearLt`]
    /// relation.
    #[inline]
    pub fn is_block_sizes_near_lt(
        lhs: impl AsRef<Self>,
        rhs: impl AsRef<Self>
    ) -> bool
    {
        BlockSize::is_near_lt(
            lhs.as_ref().log_blocksize,
            rhs.as_ref().log_blocksize
        )
    }

    /// Checks whether two *base-2 logarithm* forms of the block size values
    /// from given two fuzzy hashes form a [`BlockSizeRelation::NearGt`]
    /// relation.
    #[inline]
    pub fn is_block_sizes_near_gt(
        lhs: impl AsRef<Self>,
        rhs: impl AsRef<Self>
    ) -> bool
    {
        BlockSize::is_near_gt(
            lhs.as_ref().log_blocksize,
            rhs.as_ref().log_blocksize
        )
    }

    /// Compare two fuzzy hashes only by their block sizes.
    #[inline]
    pub fn cmp_by_block_size(&self, other: &Self) -> core::cmp::Ordering {
        u8::cmp(
            &self.log_blocksize,
            &other.log_blocksize)
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    AsRef<FuzzyHashData<S1, S2, NORM>> for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline(always)]
    fn as_ref(&self) -> &FuzzyHashData<S1, S2, NORM> {
        self
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    Default for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    PartialEq for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        if !(self.len_blockhash1 == other.len_blockhash1
            && self.len_blockhash2 == other.len_blockhash2
            && self.log_blocksize == other.log_blocksize)
        {
            return false;
        }
        optionally_unsafe! {
            invariant!((self.len_blockhash1 as usize) <= self.blockhash1.len());
            invariant!((self.len_blockhash2 as usize) <= self.blockhash2.len());
            invariant!((other.len_blockhash1 as usize) <= other.blockhash1.len());
            invariant!((other.len_blockhash2 as usize) <= other.blockhash2.len());
        }
        // grcov-excl-br-start:ARRAY
        self.blockhash1[0..self.len_blockhash1 as usize] == other.blockhash1[0..other.len_blockhash1 as usize] &&
        self.blockhash2[0..self.len_blockhash2 as usize] == other.blockhash2[0..other.len_blockhash2 as usize]
        // grcov-excl-br-stop
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    Eq for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{}

impl<const S1: usize, const S2: usize, const NORM: bool>
    core::hash::Hash for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // As this implementation does its own length prefixing,
        // don't worry about prefix collisions (if hasher doesn't implement it).
        state.write_u8(self.log_blocksize);
        state.write_u8(self.len_blockhash1);
        state.write_u8(self.len_blockhash2);
        optionally_unsafe! {
            invariant!((self.len_blockhash1 as usize) <= self.blockhash1.len());
            invariant!((self.len_blockhash2 as usize) <= self.blockhash2.len());
        }
        state.write(&self.blockhash1[0..self.len_blockhash1 as usize]); // grcov-excl-br-line:ARRAY
        state.write(&self.blockhash2[0..self.len_blockhash2 as usize]); // grcov-excl-br-line:ARRAY
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    Ord for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (
            self.log_blocksize,
            &self.blockhash1,
            self.len_blockhash1,
            &self.blockhash2,
            self.len_blockhash2
        ).cmp(&(
            other.log_blocksize,
            &other.blockhash1,
            other.len_blockhash1,
            &other.blockhash2,
            other.len_blockhash2
        ))
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    PartialOrd for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "alloc")]
impl<const S1: usize, const S2: usize, const NORM: bool>
    core::convert::From<FuzzyHashData<S1, S2, NORM>> for String
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    fn from(value: FuzzyHashData<S1, S2, NORM>) -> Self {
        value.to_string()
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    core::fmt::Display for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Formats the value using a given formatter.
    ///
    /// # Safety
    ///
    /// This method assumes that the fuzzy hash data is not broken.
    ///
    /// Unlike this method, [`Debug`](core::fmt::Debug::fmt) implementation
    /// does not cause problems if a given fuzzy hash is broken.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buffer = [0u8; crate::MAX_LEN_IN_STR];
        self.store_into_bytes(&mut buffer).unwrap();
        cfg_if::cfg_if! {
            if #[cfg(feature = "unsafe")] {
                unsafe {
                    f.write_str(core::str::from_utf8_unchecked(&buffer[..self.len_in_str()]))
                }
            }
            else {
                f.write_str(core::str::from_utf8(&buffer[..self.len_in_str()]).unwrap())
            }
        }
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    core::fmt::Debug for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // It's for debug purposes and do the full checking.
        if self.is_valid() {
            // Table lookup is safe.  All entries are `0 <= x < 64`.
            let buffer1 = self.blockhash1.map(|x| { BASE64_TABLE_U8[x as usize] }); // grcov-excl-br-line:ARRAY
            let buffer2 = self.blockhash2.map(|x| { BASE64_TABLE_U8[x as usize] }); // grcov-excl-br-line:ARRAY
            f.debug_struct("FuzzyHashData")
                .field("LONG", &Self::IS_LONG_FORM)
                .field("NORM", &Self::IS_NORMALIZED_FORM)
                .field("block_size", &BlockSize::from_log_internal(self.log_blocksize))
                .field("blockhash1", &core::str::from_utf8(&buffer1[..self.len_blockhash1 as usize]).unwrap()) // grcov-excl-br-line:ARRAY
                .field("blockhash2", &core::str::from_utf8(&buffer2[..self.len_blockhash2 as usize]).unwrap()) // grcov-excl-br-line:ARRAY
                .finish()
        }
        else {
            f.debug_struct("FuzzyHashData")
                .field("ILL_FORMED", &true)
                .field("LONG", &Self::IS_LONG_FORM)
                .field("NORM", &Self::IS_NORMALIZED_FORM)
                .field("log_blocksize", &self.log_blocksize)
                .field("len_blockhash1", &self.len_blockhash1)
                .field("len_blockhash2", &self.len_blockhash2)
                .field("blockhash1", &self.blockhash1)
                .field("blockhash2", &self.blockhash2)
                .finish()
        }
    }
}

impl<const S1: usize, const S2: usize, const NORM: bool>
    core::str::FromStr for FuzzyHashData<S1, S2, NORM>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    type Err = ParseError;
    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_bytes(s.as_bytes()) }
}


/// Type macro for a normalized fuzzy hash type.
macro_rules!  norm_type {($s1: expr, $s2: expr) => { FuzzyHashData<$s1, $s2, true> }}
/// Type macro for a non-normalized (raw) fuzzy hash type.
macro_rules!   raw_type {($s1: expr, $s2: expr) => { FuzzyHashData<$s1, $s2, false> }}
/// Type macro for a short fuzzy hash type.
macro_rules! short_type {($norm: expr) => {FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}, $norm> }}
/// Type macro for a long fuzzy hash type.
macro_rules!  long_type {($norm: expr) => {FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}, $norm> }}


/// Implementation of normalized fuzzy hashes.
///
/// Methods below are available on normalized fuzzy hashes
/// ([`FuzzyHash`] or [`LongFuzzyHash`]).
impl<const S1: usize, const S2: usize> norm_type!(S1, S2)
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Windows representing normalized substrings
    /// suitable for filtering block hashes to match (block hash 1).
    ///
    /// To compare two normalized block hashes with the same effective block
    /// size, the scoring function requires that two strings contain a common
    /// substring with a length of [`BlockHash::MIN_LCS_FOR_COMPARISON`].
    ///
    /// This method provides an access to substrings of that length, allowing
    /// the specialized clustering application to filter fuzzy hashes to compare
    /// prior to actual comparison.
    ///
    /// For instance, you may store fuzzy hashes indexed by the elements of
    /// this window.
    ///
    /// # Example (pseudocode)
    ///
    /// ```
    /// use ssdeep::FuzzyHash;
    ///
    /// // It stores a fuzzy hash with keys (with duplicates) like this:
    /// //     db_entries(log_block_size, substring).add(hash)
    /// // ... to enable later filtering.
    /// fn insert_to_database(key: (u8, &[u8]), value: &FuzzyHash) { /* ... */ }
    ///
    /// # let hash_str = "196608:DfiQF5UWAC2qctjBemsqz7yHlHr4bMCE2J8Y:jBp/Fqz7mlHZCE2J8Y";
    /// // let hash_str = ...;
    /// let hash: FuzzyHash = str::parse(hash_str).unwrap();
    /// for window in hash.block_hash_1_windows() {
    ///     insert_to_database(
    ///         (hash.log_block_size(), window),
    ///         &hash
    ///     );
    /// }
    /// for window in hash.block_hash_2_windows() {
    ///     insert_to_database(
    ///         (hash.log_block_size() + 1, window),
    ///         &hash
    ///     );
    /// }
    /// ```
    #[inline]
    pub fn block_hash_1_windows(&self) -> core::slice::Windows<'_, u8> {
        self.block_hash_1().windows(BlockHash::MIN_LCS_FOR_COMPARISON)
    }

    /// Windows representing substrings
    /// suitable for filtering block hashes to match (block hash 2).
    ///
    /// See also: [`block_hash_1_windows()`](Self::block_hash_1_windows()).
    #[inline]
    pub fn block_hash_2_windows(&self) -> core::slice::Windows<'_, u8> {
        self.block_hash_2().windows(BlockHash::MIN_LCS_FOR_COMPARISON)
    }

    /// Converts the fuzzy hash from a raw form, normalizing it.
    #[inline]
    pub fn from_raw_form(source: &raw_type!(S1, S2)) -> Self { source.normalize() }

    /// Converts the fuzzy hash to a raw form.
    #[inline]
    pub fn to_raw_form(&self) -> raw_type!(S1, S2) {
        FuzzyHashData {
            blockhash1: self.blockhash1,
            blockhash2: self.blockhash2,
            len_blockhash1: self.len_blockhash1,
            len_blockhash2: self.len_blockhash2,
            log_blocksize: self.log_blocksize
        }
    }

    /// Copy the fuzzy hash to another (output is a raw form).
    #[inline]
    pub fn into_mut_raw_form(&self, dest: &mut raw_type!(S1, S2)) {
        dest.blockhash1 = self.blockhash1;
        dest.blockhash2 = self.blockhash2;
        dest.len_blockhash1 = self.len_blockhash1;
        dest.len_blockhash2 = self.len_blockhash2;
        dest.log_blocksize = self.log_blocksize;
    }

    /// Converts the fuzzy hash to a normalized form (with normalization).
    ///
    /// In this normalized variant, this normalization is just a clone.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](Self#normalization)
    #[inline]
    pub fn normalize(&self) -> norm_type!(S1, S2) { *self }

    /// Clones the fuzzy hash with normalization but without changing a type.
    ///
    /// For a normalized fuzzy hash type, it always clones itself.
    #[inline]
    pub fn clone_normalized(&self) -> Self { *self }

    /// Returns whether the fuzzy hash is normalized.
    ///
    /// For a normalized fuzzy hash type, it always returns [`true`].
    ///
    /// Note that this method is only for convenience purposes and checking
    /// whether a fuzzy hash is normalized does not usually improve the performance.
    #[inline(always)]
    pub fn is_normalized(&self) -> bool { true }
}


/// Implementation of non-normalized fuzzy hashes (in raw form).
///
/// Methods below are available on non-normalized fuzzy hashes
/// ([`RawFuzzyHash`] or [`LongRawFuzzyHash`]).
impl<const S1: usize, const S2: usize> raw_type!(S1, S2)
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Converts the fuzzy hash from a normalized form.
    #[inline]
    pub fn from_normalized(source: &norm_type!(S1, S2)) -> Self { source.to_raw_form() }

    /// Converts the fuzzy hash to a normalized form (with normalization).
    ///
    /// In this raw form variant, it performs a normalization operation.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](Self#normalization)
    #[inline]
    pub fn normalize(&self) -> norm_type!(S1, S2) {
        let mut dest = FuzzyHashData {
            blockhash1: self.blockhash1,
            blockhash2: self.blockhash2,
            len_blockhash1: self.len_blockhash1,
            len_blockhash2: self.len_blockhash2,
            log_blocksize: self.log_blocksize
        };
        dest.normalize_in_place();
        dest
    }

    /// Clones the fuzzy hash with normalization but without changing a type.
    #[inline]
    pub fn clone_normalized(&self) -> Self {
        let mut new = *self;
        new.normalize_in_place();
        new
    }

    /// Returns whether the fuzzy hash is normalized.
    ///
    /// For a non-normalized fuzzy hash type (in raw form), it checks whether
    /// the fuzzy hash is already normalized.
    ///
    /// Note that this method is only for convenience purposes and checking
    /// whether a fuzzy hash is normalized does not usually improve the performance.
    pub fn is_normalized(&self) -> bool {
        algorithms::is_normalized(
            &self.blockhash1,
            self.len_blockhash1
        ) &&
        algorithms::is_normalized(
            &self.blockhash2,
            self.len_blockhash2
        )
    }
}


/// Implementation of short fuzzy hashes.
///
/// Methods below are available on short (truncated) fuzzy hashes
/// ([`FuzzyHash`] or [`RawFuzzyHash`]).
impl <const NORM: bool> short_type!(NORM) {
    /// Converts the fuzzy hash to a long form.
    #[inline]
    pub fn to_long_form(&self) -> long_type!(NORM) {
        let mut dest =
            FuzzyHashData {
                blockhash1: self.blockhash1,
                blockhash2: [0; BlockHash::FULL_SIZE],
                len_blockhash1: self.len_blockhash1,
                len_blockhash2: self.len_blockhash2,
                log_blocksize: self.log_blocksize
            };
        dest.blockhash2[0..BlockHash::HALF_SIZE].copy_from_slice(&self.blockhash2);
        dest
    }

    /// Copy the fuzzy hash to another (output is a long form).
    #[inline]
    pub fn into_mut_long_form(&self, dest: &mut long_type!(NORM)) {
        dest.blockhash1 = self.blockhash1;
        dest.blockhash2[0..BlockHash::HALF_SIZE].copy_from_slice(&self.blockhash2);
        dest.blockhash2[BlockHash::HALF_SIZE..BlockHash::FULL_SIZE].fill(0);
        dest.len_blockhash1 = self.len_blockhash1;
        dest.len_blockhash2 = self.len_blockhash2;
        dest.log_blocksize = self.log_blocksize;
    }
}


/// Implementation of long fuzzy hashes.
///
/// Methods below are available on long (non-truncated) fuzzy hashes
/// ([`LongFuzzyHash`] or [`LongRawFuzzyHash`]).
impl <const NORM: bool> long_type!(NORM) {
    /// Converts the fuzzy hash from a short, truncated form.
    #[inline]
    pub fn from_short_form(source: &short_type!(NORM)) -> Self { source.to_long_form() }

    /// Tries to copy the fuzzy hash to another (output is a short form).
    #[inline]
    pub fn try_into_mut_short(&self, dest: &mut short_type!(NORM))
        -> Result<(), FuzzyHashOperationError>
    {
        if self.len_blockhash2 as usize > BlockHash::HALF_SIZE {
            return Err(FuzzyHashOperationError::BlockHashOverflow);
        }
        dest.blockhash1 = self.blockhash1;
        dest.blockhash2.copy_from_slice(&self.blockhash2[0..BlockHash::HALF_SIZE]);
        dest.len_blockhash1 = self.len_blockhash1;
        dest.len_blockhash2 = self.len_blockhash2;
        dest.log_blocksize = self.log_blocksize;
        Ok(())
    }
}


impl<const S1: usize, const S2: usize>
    core::convert::From<norm_type!(S1, S2)> for raw_type!(S1, S2)
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn from(value: norm_type!(S1, S2)) -> Self { value.to_raw_form() }
}

impl<const S1: usize, const S2: usize>
    core::convert::From<raw_type!(S1, S2)> for norm_type!(S1, S2)
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn from(value: raw_type!(S1, S2)) -> Self { value.normalize() }
}

impl<const NORM: bool>
    core::convert::From<short_type!(NORM)> for long_type!(NORM)
{
    #[inline]
    fn from(value: short_type!(NORM)) -> Self { value.to_long_form() }
}

impl core::convert::From<short_type!(true)> for long_type!(false) {
    #[inline]
    fn from(value: short_type!(true)) -> Self {
        // Reimplement plain copy to avoid two-step copy.
        let mut dest: Self = Self::new();
        dest.blockhash1 = value.blockhash1;
        dest.blockhash2[0..BlockHash::HALF_SIZE].copy_from_slice(&value.blockhash2);
        dest.len_blockhash1 = value.len_blockhash1;
        dest.len_blockhash2 = value.len_blockhash2;
        dest.log_blocksize = value.log_blocksize;
        dest
    }
}

impl<const NORM: bool>
    core::convert::TryFrom<long_type!(NORM)> for short_type!(NORM)
{
    type Error = FuzzyHashOperationError;
    fn try_from(value: long_type!(NORM)) -> Result<Self, Self::Error> {
        let mut dest: Self = Self::new();
        value.try_into_mut_short(&mut dest)?;
        Ok(dest)
    }
}


/// Regular (truncated) normalized fuzzy hash type.
///
/// This type has a short (truncated) and normalized form so this type is
/// the best fit for fuzzy hash comparison.
///
/// See also: [`FuzzyHashData`]
///
/// # Alternative Types
///
/// This type does not preserve the original contents of the input fuzzy hash.
/// If you want to...
///
/// 1.  Preserve the original string representation of the fuzzy hash
///     (when parsing existing fuzzy hashes) or
/// 2.  Retrieve a fuzzy hash generated by [`Generator`](crate::generate::Generator)
///     (not normalized by default ssdeep),
///
/// use a raw form, [`RawFuzzyHash`].
///
/// Usually, all fuzzy hashes you would handle are truncated, meaning the second
/// half of two block hashes are truncated to the half size of the maximum size
/// of the first half.  But if you pass the `FUZZY_FLAG_NOTRUNC` flag to the
/// `fuzzy_digest` function (libfuzzy), the result will be a non-truncated,
/// long form.  If you want to handle such fuzzy hashes, use [`LongFuzzyHash`]
/// (instead of [`FuzzyHash`]) and/or [`LongRawFuzzyHash`] (instead of [`RawFuzzyHash`]).
pub type FuzzyHash =
    FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}, true>;


/// Regular (truncated) raw fuzzy hash type.
///
/// This type has a short (truncated) and non-normalized raw form so this
/// type is the best fit to preserve the original string representation of a
/// fuzzy hash.
///
/// This is also the default type of the fuzzy hash generator output because
/// (by default) the generator does not normalize the resulting fuzzy hash.
///
/// See also: [`FuzzyHashData`]
///
/// # Alternative Types
///
/// Comparison functions/methods require that the input is normalized.
/// To prevent excess normalization, [`FuzzyHash`] is recommended for comparison.
///
/// Usually, all fuzzy hashes you would handle are truncated, meaning the second
/// half of two block hashes are truncated to the half size of the maximum size
/// of the first half.  But if you pass the `FUZZY_FLAG_NOTRUNC` flag to the
/// `fuzzy_digest` function (libfuzzy), the result will be a non-truncated,
/// long form.  If you want to handle such fuzzy hashes, use [`LongFuzzyHash`]
/// (instead of [`FuzzyHash`]) and/or [`LongRawFuzzyHash`] (instead of [`RawFuzzyHash`]).
pub type RawFuzzyHash =
    FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}, false>;


/// Long (non-truncated) normalized fuzzy hash type.
///
/// This type has a long (non-truncated) and normalized form.
///
/// You don't usually handle non-truncated fuzzy hashes.
/// Use [`FuzzyHash`] where applicable.
///
/// See also: [`FuzzyHashData`]
pub type LongFuzzyHash =
    FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}, true>;


/// Long (non-truncated) raw fuzzy hash type.
///
/// This type has a long (non-truncated) and non-normalized raw form.
///
/// You don't usually handle non-truncated fuzzy hashes.
/// Use [`RawFuzzyHash`] where applicable.
///
/// See also: [`FuzzyHashData`]
pub type LongRawFuzzyHash =
    FuzzyHashData<{BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}, false>;





/// Constant assertions related to the parent module.
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::{const_assert, const_assert_eq};

    // Validate Configurations of Four Variants
    // FuzzyHash
    const_assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_1, BlockHash::FULL_SIZE);
    const_assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_2, BlockHash::HALF_SIZE);
    const_assert_eq!(FuzzyHash::IS_NORMALIZED_FORM, true);
    const_assert_eq!(FuzzyHash::IS_LONG_FORM, false);
    // RawFuzzyHash
    const_assert_eq!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_1, BlockHash::FULL_SIZE);
    const_assert_eq!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_2, BlockHash::HALF_SIZE);
    const_assert_eq!(RawFuzzyHash::IS_NORMALIZED_FORM, false);
    const_assert_eq!(RawFuzzyHash::IS_LONG_FORM, false);
    // LongFuzzyHash
    const_assert_eq!(LongFuzzyHash::MAX_BLOCK_HASH_SIZE_1, BlockHash::FULL_SIZE);
    const_assert_eq!(LongFuzzyHash::MAX_BLOCK_HASH_SIZE_2, BlockHash::FULL_SIZE);
    const_assert_eq!(LongFuzzyHash::IS_NORMALIZED_FORM, true);
    const_assert_eq!(LongFuzzyHash::IS_LONG_FORM, true);
    // LongRawFuzzyHash
    const_assert_eq!(LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_1, BlockHash::FULL_SIZE);
    const_assert_eq!(LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_2, BlockHash::FULL_SIZE);
    const_assert_eq!(LongRawFuzzyHash::IS_NORMALIZED_FORM, false);
    const_assert_eq!(LongRawFuzzyHash::IS_LONG_FORM, true);

    // Test for Relative Sizes
    // Short forms (sizes should match)
    const_assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_1, RawFuzzyHash::MAX_BLOCK_HASH_SIZE_1);
    const_assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_2, RawFuzzyHash::MAX_BLOCK_HASH_SIZE_2);
    const_assert_eq!(FuzzyHash::MAX_LEN_IN_STR, RawFuzzyHash::MAX_LEN_IN_STR);
    const_assert_eq!(core::mem::size_of::<FuzzyHash>(), core::mem::size_of::<RawFuzzyHash>());
    // Long forms (sizes should match)
    const_assert_eq!(LongFuzzyHash::MAX_BLOCK_HASH_SIZE_1, LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_1);
    const_assert_eq!(LongFuzzyHash::MAX_BLOCK_HASH_SIZE_2, LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_2);
    const_assert_eq!(LongFuzzyHash::MAX_LEN_IN_STR, LongRawFuzzyHash::MAX_LEN_IN_STR);
    const_assert_eq!(core::mem::size_of::<LongFuzzyHash>(), core::mem::size_of::<LongRawFuzzyHash>());
    // Short-long forms: Block hash 1 (sizes should match)
    const_assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_1, LongFuzzyHash::MAX_BLOCK_HASH_SIZE_1);
    const_assert_eq!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_1, LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_1);
    // Short-long forms: Others (long form should be larger)
    const_assert!(FuzzyHash::MAX_BLOCK_HASH_SIZE_2 < LongFuzzyHash::MAX_BLOCK_HASH_SIZE_2);
    const_assert!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_2 < LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_2);
    const_assert!(FuzzyHash::MAX_LEN_IN_STR < LongFuzzyHash::MAX_LEN_IN_STR);
    const_assert!(RawFuzzyHash::MAX_LEN_IN_STR < LongRawFuzzyHash::MAX_LEN_IN_STR);
}
