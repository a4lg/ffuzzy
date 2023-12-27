// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

use crate::hash::{FuzzyHashData, fuzzy_norm_type};
use crate::hash::block::{
    block_size, block_hash,
    BlockSizeRelation,
    BlockHashSize, ConstrainedBlockHashSize,
    BlockHashSizes, ConstrainedBlockHashSizes
};
use crate::hash_dual::{
    FuzzyHashDualData,
    ReconstructionBlockSize, ConstrainedReconstructionBlockSize
};
use crate::macros::{optionally_unsafe, invariant};


/// Module that contains position array-related traits and implementations.
pub mod position_array;
/// Test-only utilities.
#[cfg(any(test, doc))]
mod test_utils;
#[cfg(test)]
mod tests;

use position_array::{
    BlockHashPositionArrayData,
    BlockHashPositionArrayImpl,
    BlockHashPositionArrayImplInternal,
    BlockHashPositionArrayImplMutInternal,
    BlockHashPositionArrayRef,
    BlockHashPositionArrayMutRef,
};
#[cfg(feature = "unchecked")]
use position_array::BlockHashPositionArrayImplUnchecked;


/// An efficient position array-based fuzzy hash comparison target.
///
/// It can be built from a normalized [`FuzzyHashData`] object and represents
/// the normalized contents of two block hashes as two position arrays.
///
/// Although that this structure is large, it is particularly useful if
/// you compare many of fuzzy hashes and you can fix one of the operands
/// (this is usually over 10 times faster than batched `fuzzy_compare` calls
/// in ssdeep 2.13).  Even if we generate this object each time we compare
/// two fuzzy hashes, it's usually faster than `fuzzy_compare` in ssdeep 2.13.
///
/// In fact, if you just compare two fuzzy hashes in this crate, a temporary
/// [`FuzzyHashCompareTarget`] object is created from either side
/// of the comparison.
///
/// See also: ["Fuzzy Hash Comparison" section of `FuzzyHashData`](FuzzyHashData#fuzzy-hash-comparison)
///
/// # Examples
///
/// ```rust
/// // Requires the global allocator to use `Vec` (default on std).
/// # #[cfg(feature = "alloc")]
/// # {
/// use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
///
/// // Brute force comparison
/// let hashes: Vec<FuzzyHash> = Vec::new();
/// /* ... add fuzzy hashes to `hashes` ... */
///
/// let mut target: FuzzyHashCompareTarget = FuzzyHashCompareTarget::new();
/// for hash1 in &hashes {
///     target.init_from(hash1);
///     for hash2 in &hashes {
///         let score = target.compare(hash2);
///         /* ... */
///     }
/// }
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct FuzzyHashCompareTarget {
    /// The position array representation of block hash 1.
    ///
    /// See also:
    /// 1.  [`BlockHashPositionArrayData`]
    /// 2.  [`BlockHashPositionArrayImpl`]
    /// 3.  [`block_hash_1()`](Self::block_hash_1())
    blockhash1: [u64; block_hash::ALPHABET_SIZE],

    /// The position array representation of block hash 2.
    ///
    /// See also:
    /// 1.  [`BlockHashPositionArrayData`]
    /// 2.  [`BlockHashPositionArrayImpl`]
    /// 3.  [`block_hash_2()`](Self::block_hash_2())
    blockhash2: [u64; block_hash::ALPHABET_SIZE],

    /// Length of the block hash 1 (up to [`block_hash::FULL_SIZE`]).
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    len_blockhash1: u8,

    /// Length of the block hash 2 (up to [`block_hash::FULL_SIZE`]).
    ///
    /// See also: [`block_hash_2()`](Self::block_hash_2())
    len_blockhash2: u8,

    /// *Base-2 logarithm* form of the actual block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](FuzzyHashData#block-size)
    log_blocksize: u8,
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "unchecked"))] {
        /// The return type of [`FuzzyHashCompareTarget::block_hash_1()`] and
        /// [`FuzzyHashCompareTarget::block_hash_2()`].
        macro_rules! compare_target_block_hash_pub_impl {
            ($a:lifetime) => {
                impl $a + BlockHashPositionArrayImpl
            };
        }
        /// The return type of [`FuzzyHashCompareTarget::block_hash_1_internal()`]
        /// and [`FuzzyHashCompareTarget::block_hash_2_internal()`].
        macro_rules! compare_target_block_hash_priv_impl {
            ($a:lifetime) => {
                impl $a + BlockHashPositionArrayImpl + BlockHashPositionArrayImplInternal
            };
        }
    }
    else {
        /// The return type of [`FuzzyHashCompareTarget::block_hash_1()`] and
        /// [`FuzzyHashCompareTarget::block_hash_2()`].
        macro_rules! compare_target_block_hash_pub_impl {
            ($a:lifetime) => {
                impl $a + BlockHashPositionArrayImpl + BlockHashPositionArrayImplUnchecked
            };
        }
        /// The return type of [`FuzzyHashCompareTarget::block_hash_1_internal()`]
        /// and [`FuzzyHashCompareTarget::block_hash_2_internal()`].
        macro_rules! compare_target_block_hash_priv_impl {
            ($a:lifetime) => {
                impl $a + BlockHashPositionArrayImpl + BlockHashPositionArrayImplUnchecked + BlockHashPositionArrayImplInternal
            };
        }
    }
}

impl FuzzyHashCompareTarget {
    /// The minimum length of the common substring to compute edit distance
    /// between two block hashes.
    ///
    /// Use [`block_hash::MIN_LCS_FOR_COMPARISON`] instead.
    ///
    /// # Incompatibility Notice
    ///
    /// This constant will be removed on the version 0.3.0.
    #[deprecated]
    pub const MIN_LCS_FOR_BLOCKHASH: usize = block_hash::MIN_LCS_FOR_COMPARISON;

    /// The lower bound (inclusive) of the *base-2 logarithm* form of
    /// the block size in which the score capping is no longer required.
    ///
    /// If `log_block_size` is equal to or larger than this value and `len1` and
    /// `len2` are at least [`block_hash::MIN_LCS_FOR_COMPARISON`] in size,
    /// [`Self::score_cap_on_block_hash_comparison`]`(log_block_size, len1, len2)`
    /// is guaranteed to be `100` or greater.
    ///
    /// The score "cap" is computed as
    /// `(1 << log_block_size) * min(len1, len2)`.
    /// If this always guaranteed to be `100` or greater,
    /// capping the score is not longer required.
    ///
    /// See also: ["Fuzzy Hash Comparison" section of `FuzzyHashData`](FuzzyHashData#fuzzy-hash-comparison)
    ///
    /// # Backgrounds
    ///
    /// ## Theorem
    ///
    /// For all positive integers `a`, `b` and `c`, `a <= b * c` iff
    /// `(a + b - 1) / b <= c` (where `ceil(a/b) == (a + b - 1) / b`).
    ///
    /// This is proven by Z3 and (partially) Coq in the source code:
    /// *   Z3 + Python:  
    ///     `dev/prover/compare/blocksize_capping_theorem.py`
    /// *   Coq (uses existing ceiling function instead of `(a + b - 1) / b`):  
    ///     `dev/prover/compare/blocksize_capping_theorem.v`
    ///
    /// ## The Minimum Score Cap
    ///
    /// This is expressed as `(1 << log_block_size) * MIN_LCS_FOR_COMPARISON`
    /// because both block hashes must at least as long as
    /// [`block_hash::MIN_LCS_FOR_COMPARISON`] to perform edit distance-based
    /// scoring.
    ///
    /// ## Computing the Constant
    ///
    /// Applying the theorem above,
    /// `100 <= (1 << log_block_size) * MIN_LCS_FOR_COMPARISON`
    /// is equivalent to
    /// `(100 + MIN_LCS_FOR_COMPARISON - 1) / MIN_LCS_FOR_COMPARISON <= (1 << log_block_size)`.
    ///
    /// This leads to the expression to define this constant.
    pub const LOG_BLOCK_SIZE_CAPPING_BORDER: u8 =
        ((100 + block_hash::MIN_LCS_FOR_COMPARISON as u64 - 1) / block_hash::MIN_LCS_FOR_COMPARISON as u64)
        .next_power_of_two().trailing_zeros() as u8;

    /// Creates a new [`FuzzyHashCompareTarget`] object with empty contents.
    ///
    /// This is equivalent to the fuzzy hash string `3::`.
    #[inline]
    pub fn new() -> Self {
        FuzzyHashCompareTarget {
            blockhash1: [0u64; block_hash::ALPHABET_SIZE],
            blockhash2: [0u64; block_hash::ALPHABET_SIZE],
            len_blockhash1: 0,
            len_blockhash2: 0,
            log_blocksize: 0,
        }
    }

    /// The *base-2 logarithm* form of the comparison target's block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](FuzzyHashData#block-size)
    #[inline(always)]
    pub fn log_block_size(&self) -> u8 { self.log_blocksize }

    /// The block size of the comparison target.
    #[inline]
    pub fn block_size(&self) -> u32 {
        block_size::from_log_internal(self.log_blocksize)
    }

    /// Position array-based representation of the block hash 1.
    ///
    /// This is the same as [`block_hash_1()`](Self::block_hash_1()) except that
    /// it exposes some internals.
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    ///
    /// # Examples (Public part)
    ///
    /// Because this documentation test is not suitable for a part of the public
    /// documentation, it is listed here.
    ///
    /// ```
    /// use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    ///
    /// let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// let base_bh1:     &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let base_bh1_mod: &[u8] = &[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]; // [0] is replaced
    /// let bh1 = target.block_hash_1();
    ///
    /// assert!(bh1.is_valid());                // Should be always true
    /// assert!(bh1.is_valid_and_normalized()); // Should be always true
    /// assert_eq!(bh1.len(), base_bh1.len() as u8);
    /// assert!( bh1.is_equiv(base_bh1));
    /// assert!(!bh1.is_equiv(base_bh1_mod));
    /// assert!(!bh1.is_equiv(&[0, 1, 2, 3, 4, 5, 6, 7])); // "ABCDEFGH" (subset)
    /// assert!( bh1.has_common_substring(&[ 0,  1,  2,  3,  4,  5,  6,  7])); // 0..=6 or 1..=7 matches (enough length)
    /// assert!(!bh1.has_common_substring(&[10, 11, 12, 13, 14, 15, 16, 17])); // 10..=15 matches but doesn't have enough length
    /// assert_eq!(bh1.edit_distance(base_bh1), 0);     // edit distance with itself
    /// assert_eq!(bh1.edit_distance(base_bh1_mod), 2); // replace a character: cost 2
    /// assert_eq!(bh1.score_strings_raw(base_bh1), 100); // compare with itself
    /// assert_eq!(bh1.score_strings(base_bh1, 0),   16); // compare with itself, capped (block size 3)
    ///
    /// #[cfg(feature = "unchecked")]
    /// unsafe {
    ///     use ssdeep::internal_comparison::BlockHashPositionArrayImplUnchecked;
    ///     // Test unchecked counterparts
    ///     assert!( bh1.is_equiv_unchecked(base_bh1));
    ///     assert!(!bh1.is_equiv_unchecked(base_bh1_mod));
    ///     assert!(!bh1.is_equiv_unchecked(&[0, 1, 2, 3, 4, 5, 6, 7]));
    ///     assert!( bh1.has_common_substring_unchecked(&[ 0,  1,  2,  3,  4,  5,  6,  7]));
    ///     assert!(!bh1.has_common_substring_unchecked(&[10, 11, 12, 13, 14, 15, 16, 17]));
    ///     assert_eq!(bh1.edit_distance_unchecked(base_bh1), 0);
    ///     assert_eq!(bh1.edit_distance_unchecked(base_bh1_mod), 2);
    ///     assert_eq!(bh1.score_strings_raw_unchecked(base_bh1), 100);
    ///     assert_eq!(bh1.score_strings_unchecked(base_bh1, 0),   16);
    /// }
    /// ```
    ///
    /// # Examples (Private part which should fail)
    ///
    /// It allows access to internal functions of [`BlockHashPositionArrayImplInternal`].
    ///
    /// In the examples below, it makes sure that they are not
    /// accessible from outside.
    ///
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.is_equiv_internal(base_bh1));
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.has_common_substring_internal(&[0, 1, 2, 3, 4, 5, 6, 7]));
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert_eq!(bh1.edit_distance_internal(base_bh1), 0);
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert_eq!(bh1.score_strings_raw_internal(base_bh1), 100);
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let target = FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("3:ABCDEFGHIJKLMNOP:").unwrap());
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert_eq!(bh1.score_strings_internal(base_bh1, 0), 16);
    /// ```
    #[inline(always)]
    fn block_hash_1_internal(&self) -> compare_target_block_hash_priv_impl!('_) {
        BlockHashPositionArrayRef(&self.blockhash1, &self.len_blockhash1)
    }

    /// Position array-based representation of the block hash 1.
    ///
    /// This method provices raw access to the internal efficient block hash
    /// representation and fast bit-parallel string functions.
    ///
    /// You are not recommended to use this unless
    /// you know the internal details deeply.
    ///
    /// The result has the same lifetime as this object and implements
    /// following traits:
    ///
    /// 1.  [`BlockHashPositionArrayData`]
    /// 2.  [`BlockHashPositionArrayImpl`]
    /// 3.  [`BlockHashPositionArrayImplUnchecked`]
    ///     (only if the `unchecked` feature is enabled)
    #[inline(always)]
    pub fn block_hash_1(&self) -> compare_target_block_hash_pub_impl!('_) {
        // Expose a subset of block_hash_1_internal()
        self.block_hash_1_internal()
    }

    /// Position array-based representation of the block hash 1.
    ///
    /// This is internal only *and* mutable.
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    ///
    /// # Examples (That should fail)
    ///
    /// In the examples below, it makes sure that they are not
    /// accessible from outside.
    ///
    /// It allows access to internal functions of
    /// [`BlockHashPositionArrayImplMut`](crate::compare::position_array::BlockHashPositionArrayImplMut)
    /// and [`BlockHashPositionArrayImplMutInternal`].
    ///
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let mut target = FuzzyHashCompareTarget::new();
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.init_from(base_bh1));
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let mut target = FuzzyHashCompareTarget::new();
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.set_len_internal(16));
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let mut target = FuzzyHashCompareTarget::new();
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.clear_representation_only());
    /// ```
    /// ```compile_fail
    /// # use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
    /// # use ssdeep::internal_comparison::{BlockHashPositionArrayData, BlockHashPositionArrayImpl};
    /// # let mut target = FuzzyHashCompareTarget::new();
    /// # let base_bh1: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// let bh1 = target.block_hash_1();
    /// assert!(bh1.init_from_partial(base_bh1));
    /// ```
    #[inline(always)]
    fn block_hash_1_mut(&mut self)
        -> impl '_ + BlockHashPositionArrayImpl + BlockHashPositionArrayImplMutInternal
    {
        BlockHashPositionArrayMutRef(&mut self.blockhash1, &mut self.len_blockhash1)
    }

    /// Position array-based representation of the block hash 2.
    ///
    /// This is the same as [`block_hash_2()`](Self::block_hash_2()) except that
    /// it exposes some internals.
    ///
    /// See also: [`block_hash_1_internal()`](Self::block_hash_1_internal())
    #[inline(always)]
    fn block_hash_2_internal(&self) -> compare_target_block_hash_priv_impl!('_) {
        BlockHashPositionArrayRef(&self.blockhash2, &self.len_blockhash2)
    }

    /// Position array-based representation of the block hash 2.
    ///
    /// See also: [`block_hash_1()`](Self::block_hash_1())
    #[inline(always)]
    pub fn block_hash_2(&self) -> compare_target_block_hash_pub_impl!('_) {
        // Expose a subset of block_hash_2_internal()
        self.block_hash_2_internal()
    }

    /// Position array-based representation of the block hash 2.
    ///
    /// This is internal only *and* mutable.
    ///
    /// See also: [`block_hash_1_mut()`](Self::block_hash_1_mut())
    #[inline(always)]
    fn block_hash_2_mut(&mut self)
        -> impl '_ + BlockHashPositionArrayImpl + BlockHashPositionArrayImplMutInternal
    {
        BlockHashPositionArrayMutRef(&mut self.blockhash2, &mut self.len_blockhash2)
    }

    /// Performs full equality checking of the internal structure.
    ///
    /// This type intentionally lacks the implementation of [`PartialEq`]
    /// because of its large size.  However, there's a case where we need to
    /// compare two comparison targets.
    ///
    /// The primary purpose of this is debugging and it compares all internal
    /// members inside the structure (just like auto-generated
    /// [`PartialEq::eq()`]).
    ///
    /// Note that, despite that it is only relevant to users when the
    /// `unchecked` feature is enabled but made public without any features
    /// because this method is not *unsafe* or *unchecked* in any way.
    pub fn full_eq(&self, other: &Self) -> bool {
        // The contents of this method is auto-generated by rust-analyzer
        // (the only modification is the indentation).
        self.blockhash1 == other.blockhash1 &&
        self.blockhash2 == other.blockhash2 &&
        self.len_blockhash1 == other.len_blockhash1 &&
        self.len_blockhash2 == other.len_blockhash2 &&
        self.log_blocksize == other.log_blocksize
    }

    /// Initialize the object from a given fuzzy hash
    /// (without clearing the position arrays).
    ///
    /// This method is intended to be used just after clearing the position
    /// arrays (i.e. just after the initialization).
    #[inline]
    fn init_from_partial<const S1: usize, const S2: usize>(
        &mut self,
        hash: impl AsRef<fuzzy_norm_type!(S1, S2)>
    )
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let hash = hash.as_ref();
        debug_assert!((hash.len_blockhash1 as usize) <= S1);
        debug_assert!((hash.len_blockhash2 as usize) <= S2);
        debug_assert!(block_size::is_log_valid(hash.log_blocksize));
        self.len_blockhash1 = hash.len_blockhash1;
        self.len_blockhash2 = hash.len_blockhash2;
        self.log_blocksize = hash.log_blocksize;
        // Initialize position arrays based on the original block hashes
        self.block_hash_1_mut().init_from_partial(hash.block_hash_1());
        self.block_hash_2_mut().init_from_partial(hash.block_hash_2());
    }

    /// Initialize the object from a given fuzzy hash.
    #[inline]
    pub fn init_from<const S1: usize, const S2: usize>(
        &mut self,
        hash: impl AsRef<fuzzy_norm_type!(S1, S2)>
    )
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.block_hash_1_mut().clear_representation_only();
        self.block_hash_2_mut().clear_representation_only();
        self.init_from_partial(hash);
    }

    /// Compare whether two fuzzy hashes are equivalent
    /// (except for their block size).
    #[inline]
    fn is_equiv_except_block_size<const S1: usize, const S2: usize>(
        &self,
        hash: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let hash = hash.as_ref();
        self.block_hash_1_internal().is_equiv_internal(hash.block_hash_1()) &&
        self.block_hash_2_internal().is_equiv_internal(hash.block_hash_2())
    }

    /// Compare whether two fuzzy hashes are equivalent.
    #[inline(always)]
    pub fn is_equiv<const S1: usize, const S2: usize>(
        &self,
        hash: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let hash = hash.as_ref();
        if self.log_blocksize != hash.log_blocksize { return false; }
        self.is_equiv_except_block_size(hash)
    }

    /// The internal implementation of [`Self::raw_score_by_edit_distance_unchecked()`].
    #[inline(always)]
    fn raw_score_by_edit_distance_internal(
        len_block_hash_lhs: u32,
        len_block_hash_rhs: u32,
        edit_distance: u32
    ) -> u32
    {
        // Scale the raw edit distance to a 0 to 100 score (familiar to humans).
        debug_assert!(len_block_hash_lhs >= block_hash::MIN_LCS_FOR_COMPARISON as u32);
        debug_assert!(len_block_hash_rhs >= block_hash::MIN_LCS_FOR_COMPARISON as u32);
        debug_assert!(len_block_hash_lhs <= block_hash::FULL_SIZE as u32);
        debug_assert!(len_block_hash_rhs <= block_hash::FULL_SIZE as u32);
        debug_assert!(edit_distance <= len_block_hash_lhs + len_block_hash_rhs - 2 * block_hash::MIN_LCS_FOR_COMPARISON as u32);
        optionally_unsafe! {
            // rustc/LLVM cannot prove that
            // (len_block_hash_lhs + len_block_hash_rhs)
            //     <= block_hash::MIN_LCS_FOR_COMPARISON * 2.
            // Place this invariant to avoid division-by-zero checking.
            invariant!((len_block_hash_lhs + len_block_hash_rhs) > 0);
        }
        /*
            Possible arithmetic operations to check overflow:
            1.  (block_hash::FULL_SIZE * 2) * block_hash::FULL_SIZE
            2.  100 * block_hash::FULL_SIZE
        */
        100 - (100 * (
            (edit_distance * block_hash::FULL_SIZE as u32)
                / (len_block_hash_lhs + len_block_hash_rhs) // grcov-excl-br-line:DIVZERO
        )) / block_hash::FULL_SIZE as u32
    }

    /// Returns the raw score (without capping) based on the lengths of block
    /// hashes and the edit distance between them.
    ///
    /// This method assumes that following constraints are satisfied.
    ///
    /// # Safety
    ///
    /// *   Both `len_block_hash_lhs` and `len_block_hash_rhs` must satisfy:
    ///     *   Equal to or greater than [`MIN_LCS_FOR_COMPARISON`](crate::block_hash::MIN_LCS_FOR_COMPARISON),
    ///     *   Equal to or less than [`FULL_SIZE`](crate::block_hash::FULL_SIZE).
    ///
    /// *   `edit_distance` must be equal to or less than
    ///     `len_block_hash_lhs + len_block_hash_rhs - 2 * MIN_LCS_FOR_COMPARISON`.
    ///
    ///     This constraint comes from the constraints of the lengths and the
    ///     fact that we shall have a common substring of the length
    ///     [`MIN_LCS_FOR_COMPARISON`](crate::block_hash::MIN_LCS_FOR_COMPARISON)
    ///     to perform an edit distance-based comparison (reducing maximum
    ///     possible edit distance by `2 * MIN_LCS_FOR_COMPARISON`).
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn raw_score_by_edit_distance_unchecked(
        len_block_hash_lhs: u32,
        len_block_hash_rhs: u32,
        edit_distance: u32
    ) -> u32
    {
        Self::raw_score_by_edit_distance_internal(
            len_block_hash_lhs,
            len_block_hash_rhs,
            edit_distance
        )
    }

    /// Returns the raw score (without capping) based on the lengths of block
    /// hashes and the edit distance between them.
    ///
    /// This method scales the edit distance to the `0..=100` score familiar to
    /// humans (`100` means a perfect match, smaller the score, lower
    /// the similarity).
    ///
    /// Note that it doesn't perform any [score capping](Self::score_cap_on_block_hash_comparison())
    /// (that should be performed on [smaller block sizes](Self::LOG_BLOCK_SIZE_CAPPING_BORDER)).
    ///
    /// See also: ["Fuzzy Hash Comparison" section of `FuzzyHashData`](FuzzyHashData#fuzzy-hash-comparison)
    ///
    /// # Usage Constraints
    ///
    /// *   Both `len_block_hash_lhs` and `len_block_hash_rhs` must satisfy:
    ///     *   Equal to or greater than [`MIN_LCS_FOR_COMPARISON`](crate::block_hash::MIN_LCS_FOR_COMPARISON),
    ///     *   Equal to or less than [`FULL_SIZE`](crate::block_hash::FULL_SIZE).
    ///
    /// *   `edit_distance` must be equal to or less than
    ///     `len_block_hash_lhs + len_block_hash_rhs - 2 * MIN_LCS_FOR_COMPARISON`.
    ///
    ///     This constraint comes from the constraints of the lengths and the
    ///     fact that we shall have a common substring of the length
    ///     [`MIN_LCS_FOR_COMPARISON`](crate::block_hash::MIN_LCS_FOR_COMPARISON)
    ///     to perform an edit distance-based comparison (reducing maximum
    ///     possible edit distance by `2 * MIN_LCS_FOR_COMPARISON`).
    ///
    /// # Useful Property
    ///
    /// If all arguments are valid, the return value (the raw score) is
    /// guaranteed to be greater than zero.  Along with the property of the
    /// [score capping](Self::score_cap_on_block_hash_comparison()), it means
    /// that we should have a non-zero score if we can perform an edit
    /// distance-based comparison.
    #[inline(always)]
    pub fn raw_score_by_edit_distance(
        len_block_hash_lhs: u32,
        len_block_hash_rhs: u32,
        edit_distance: u32
    ) -> u32
    {
        // Scale the raw edit distance to a 0 to 100 score (familiar to humans).
        assert!(len_block_hash_lhs >= block_hash::MIN_LCS_FOR_COMPARISON as u32);
        assert!(len_block_hash_rhs >= block_hash::MIN_LCS_FOR_COMPARISON as u32);
        assert!(len_block_hash_lhs <= block_hash::FULL_SIZE as u32);
        assert!(len_block_hash_rhs <= block_hash::FULL_SIZE as u32);
        assert!(edit_distance <= len_block_hash_lhs + len_block_hash_rhs - 2 * block_hash::MIN_LCS_FOR_COMPARISON as u32);
        Self::raw_score_by_edit_distance_internal(
            len_block_hash_lhs,
            len_block_hash_rhs,
            edit_distance
        )
    }

    /// The internal implementation of [`Self::score_cap_on_block_hash_comparison_unchecked()`].
    #[inline(always)]
    fn score_cap_on_block_hash_comparison_internal(
        log_block_size: u8,
        len_block_hash_lhs: u8,
        len_block_hash_rhs: u8
    ) -> u32
    {
        optionally_unsafe! {
            invariant!(log_block_size < FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER);
        }
        (1u32 << log_block_size) * u32::min(len_block_hash_lhs as u32, len_block_hash_rhs as u32)
    }

    /// Returns the "score cap" for a given block size and two block hash
    /// lengths, assuming that block size and block hash lengths are small
    /// enough so that no arithmetic overflow will occur.
    ///
    /// # Safety
    ///
    /// *   `log_block_size` must be less than
    ///     [`FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER`](Self::LOG_BLOCK_SIZE_CAPPING_BORDER).
    /// *   Both `len_block_hash_lhs` and `len_block_hash_rhs` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    ///
    /// Otherwise, it may cause an arithmetic overflow and return an
    /// useless value.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn score_cap_on_block_hash_comparison_unchecked(
        log_block_size: u8,
        len_block_hash_lhs: u8,
        len_block_hash_rhs: u8
    ) -> u32
    {
        Self::score_cap_on_block_hash_comparison_internal(
            log_block_size,
            len_block_hash_lhs,
            len_block_hash_rhs
        )
    }

    /// Returns the "score cap" for a given block size and
    /// two block hash lengths.
    ///
    /// The internal block hash comparison method "caps" the score to prevent
    /// exaggregating the matches that are not meaningful enough.  This behavior
    /// depends on the block size (the "cap" gets higher as the block size gets
    /// higher) and the minimum of block hash lengths.
    ///
    /// The result is not always guaranteed to be in `0..=100` but `100` or
    /// higher means that we don't need any score capping.
    ///
    /// If at least one of the arguments `len_block_hash_lhs` and
    /// `len_block_hash_rhs` are less than
    /// [`block_hash::MIN_LCS_FOR_COMPARISON`], the result is
    /// implementation-defined.
    ///
    /// If all arguments are valid and `log_block_size` is
    /// [large enough](Self::LOG_BLOCK_SIZE_CAPPING_BORDER),
    /// `100` or greater will be returned, meaning that the score capping is
    /// no longer required.
    ///
    /// See also: ["Fuzzy Hash Comparison" section of `FuzzyHashData`](FuzzyHashData#fuzzy-hash-comparison)
    ///
    /// # Compatibility Note
    ///
    /// While this method is completely safe even if semantically-invalid
    /// parameters are specified (due to arithmetic properties of internal
    /// computation and a safety measure in this method), following semantic
    /// constraints may be added on the future versions:
    ///
    /// *   `log_block_size` [must be valid](block_size::is_log_valid)
    ///     or must be equal to [`block_size::NUM_VALID`] (this value itself is
    ///     not valid as a block size for a fuzzy hash object but will be valid
    ///     on this method).
    /// *   Both `len_block_hash_lhs` and `len_block_hash_rhs` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    ///
    /// If at least one of the arguments `len_block_hash_lhs` and
    /// `len_block_hash_rhs` are less than
    /// [`block_hash::MIN_LCS_FOR_COMPARISON`], this is semantically-invalid.
    /// We haven't determined whether we need to reject those cases but at
    /// least implementation-defined.
    ///
    /// # Useful Property
    ///
    /// If all arguments are valid and both `len_block_hash_lhs` and
    /// `len_block_hash_rhs` are non-zero, the return value (the score cap) is
    /// guaranteed to be greater than zero.  Along with the property of the
    /// [raw scoring](Self::raw_score_by_edit_distance()), it means that we
    /// should have a non-zero score if we can perform an edit distance-based
    /// comparison.
    #[inline(always)]
    pub fn score_cap_on_block_hash_comparison(
        log_block_size: u8,
        len_block_hash_lhs: u8,
        len_block_hash_rhs: u8
    ) -> u32
    {
        // assert!((log_block_size as usize) <= block_size::NUM_VALID);
        // assert!((len_block_hash_lhs as usize) <= block_hash::FULL_SIZE);
        // assert!((len_block_hash_rhs as usize) <= block_hash::FULL_SIZE);
        if log_block_size >= FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER {
            100
        }
        else {
            Self::score_cap_on_block_hash_comparison_internal(
                log_block_size,
                len_block_hash_lhs,
                len_block_hash_rhs
            )
        }
    }
}

impl Default for FuzzyHashCompareTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzyHashCompareTarget {
    /// Performs full validity checking of the internal structure.
    ///
    /// The primary purpose of this is debugging and it should always
    /// return [`true`] unless...
    ///
    /// 1.  There is a bug in this crate, corrupting this structure or
    /// 2.  A memory corruption is occurred somewhere else.
    ///
    /// Because of its purpose, this method is not designed to be fast.
    pub fn is_valid(&self) -> bool {
        block_size::is_log_valid(self.log_blocksize)
            && self.block_hash_1_internal().is_valid_and_normalized()
            && self.block_hash_2_internal().is_valid_and_normalized()
    }

    /// The internal implementation of [`Self::compare_unequal_near_eq_unchecked()`].
    #[inline]
    fn compare_unequal_near_eq_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(!self.is_equiv(other));
        debug_assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        u32::max(
            self.block_hash_1_internal().score_strings_internal(
                other.block_hash_1(),
                self.log_blocksize
            ),
            self.block_hash_2_internal().score_strings_internal(
                other.block_hash_2(),
                self.log_blocksize + 1
            )
        )
    }

    /// Compare two fuzzy hashes assuming both are different and their
    /// block sizes have a relation of [`BlockSizeRelation::NearEq`].
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes must be different.
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_eq_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_near_eq_internal(other)
    }

    /// *Slow*: Compare two fuzzy hashes assuming both are different and
    /// their block sizes have a relation of [`BlockSizeRelation::NearEq`].
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes must be different.
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    ///
    /// # Performance Consideration
    ///
    /// This method's performance is not good enough (because of constraint
    /// checking).
    ///
    /// Use those instead:
    /// *   [`compare_near_eq()`](Self::compare_near_eq()) (checked)
    /// *   [`compare_unequal_near_eq_unchecked()`](Self::compare_unequal_near_eq_unchecked())
    ///     (unchecked)
    #[inline(always)]
    pub fn compare_unequal_near_eq<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(!self.is_equiv(other));
        assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_eq_internal(other)
    }

    /// The internal implementation of [`Self::compare_near_eq_unchecked()`].
    #[inline]
    fn compare_near_eq_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        if self.is_equiv_except_block_size(other) { return 100; }
        self.compare_unequal_near_eq_internal(other)
    }

    /// Compare two fuzzy hashes assuming their block sizes have
    /// a relation of [`BlockSizeRelation::NearEq`].
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_near_eq_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_near_eq_internal(other)
    }

    /// Compare two fuzzy hashes assuming their block sizes have
    /// a relation of [`BlockSizeRelation::NearEq`].
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    #[inline(always)]
    pub fn compare_near_eq<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.compare_near_eq_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_near_lt_unchecked()`].
    #[inline(always)]
    fn compare_unequal_near_lt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.block_hash_2_internal().score_strings_internal(
            other.block_hash_1(),
            other.log_blocksize
        )
    }

    /// Compare two fuzzy hashes assuming both are different and their
    /// block sizes have a relation of [`BlockSizeRelation::NearLt`].
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearLt`].
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_lt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_near_lt_internal(other)
    }

    /// Compare two fuzzy hashes assuming both are different and their
    /// block sizes have a relation of [`BlockSizeRelation::NearLt`].
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearLt`].
    #[inline(always)]
    pub fn compare_unequal_near_lt<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_lt_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_near_gt_unchecked()`].
    #[inline(always)]
    fn compare_unequal_near_gt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.block_hash_1_internal().score_strings_internal(
            other.block_hash_2(),
            self.log_blocksize
        )
    }

    /// Compare two fuzzy hashes assuming both are different and their
    /// block sizes have a relation of [`BlockSizeRelation::NearGt`].
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearGt`].
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_gt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_near_gt_internal(other)
    }

    /// Compare two fuzzy hashes assuming both are different and their
    /// block sizes have a relation of [`BlockSizeRelation::NearGt`].
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearGt`].
    #[inline(always)]
    pub fn compare_unequal_near_gt<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_gt_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_unchecked()`].
    #[inline]
    fn compare_unequal_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(!self.is_equiv(other));
        match block_size::compare_sizes(self.log_blocksize, other.log_blocksize) {
            BlockSizeRelation::Far => 0,
            BlockSizeRelation::NearEq => self.compare_unequal_near_eq_internal(other),
            BlockSizeRelation::NearLt => self.compare_unequal_near_lt_internal(other),
            BlockSizeRelation::NearGt => self.compare_unequal_near_gt_internal(other),
        }
    }

    /// Compare two normalized fuzzy hashes assuming both are different.
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must be different.
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_unequal_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_internal(other)
    }

    /// *Slow*: Compare two normalized fuzzy hashes assuming
    /// both are different.
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must be different.
    ///
    /// # Performance Consideration
    ///
    /// This method's performance is not good enough (because of the constraint
    /// checking).
    ///
    /// Use those instead:
    /// *   [`compare()`](Self::compare()) (checked)
    /// *   [`compare_unequal_unchecked()`](Self::compare_unequal_unchecked())
    ///     (unchecked)
    #[inline(always)]
    pub fn compare_unequal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(!self.is_equiv(other));
        self.compare_unequal_internal(other)
    }

    /// Compares two normalized fuzzy hashes.
    #[inline]
    pub fn compare<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        match block_size::compare_sizes(self.log_blocksize, other.log_blocksize) {
            BlockSizeRelation::Far => 0,
            BlockSizeRelation::NearEq => self.compare_near_eq_internal(other),
            BlockSizeRelation::NearLt => self.compare_unequal_near_lt_internal(other),
            BlockSizeRelation::NearGt => self.compare_unequal_near_gt_internal(other),
        }
    }

    /// The internal implementation of [`Self::is_comparison_candidate_near_eq_unchecked()`].
    #[inline]
    fn is_comparison_candidate_near_eq_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.block_hash_1_internal().has_common_substring_internal(other.block_hash_1()) ||
        self.block_hash_2_internal().has_common_substring_internal(other.block_hash_2())
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearEq`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless value.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn is_comparison_candidate_near_eq_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.is_comparison_candidate_near_eq_internal(other)
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearEq`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearEq`].
    #[inline(always)]
    pub fn is_comparison_candidate_near_eq<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.is_comparison_candidate_near_eq_internal(other)
    }

    /// The internal implementation of [`Self::is_comparison_candidate_near_lt_unchecked()`].
    #[inline]
    fn is_comparison_candidate_near_lt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.block_hash_2_internal().has_common_substring_internal(other.block_hash_1())
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearLt`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearLt`].
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless value.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn is_comparison_candidate_near_lt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.is_comparison_candidate_near_lt_internal(other)
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearLt`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearLt`].
    #[inline(always)]
    pub fn is_comparison_candidate_near_lt<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.is_comparison_candidate_near_lt_internal(other)
    }

    /// The internal implementation of [`Self::is_comparison_candidate_near_gt_unchecked()`].
    #[inline]
    fn is_comparison_candidate_near_gt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(block_size::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.block_hash_1_internal().has_common_substring_internal(other.block_hash_2())
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearGt`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Safety
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearGt`].
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless value.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn is_comparison_candidate_near_gt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.is_comparison_candidate_near_gt_internal(other)
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison
    /// assuming that their block sizes have a relation of
    /// [`BlockSizeRelation::NearGt`].
    ///
    /// See also: [`is_comparison_candidate()`](Self::is_comparison_candidate())
    ///
    /// # Usage Constraints
    ///
    /// *   Both fuzzy hashes (`self` and `other`) must have
    ///     block size relation of [`BlockSizeRelation::NearGt`].
    #[inline(always)]
    pub fn is_comparison_candidate_near_gt<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(block_size::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.is_comparison_candidate_near_gt_internal(other)
    }

    /// Tests whether `other` is a candidate for edit distance-based comparison.
    ///
    /// If this function returns [`false`] **and** `self` and `other` are not
    /// [equivalent](Self::is_equiv()), their similarity will be
    /// calculated to 0.
    ///
    /// # Use Case (Example)
    ///
    /// This operation is useful to divide a set of *unique* (normalized)
    /// fuzzy hashes into smaller distinct sets.  The similarity score can be
    /// non-zero if and only if two fuzzy hashes belong to the same set.
    ///
    /// # Safety (Warning)
    ///
    /// This function (and its variants) can return [`false`] if `self` and
    /// `other` are equivalent (the base fuzzy hash object of `self` and `other`
    /// are the same and their similarity score is 100).
    ///
    /// Because of this, we have to use a set of *unique* fuzzy hash values
    /// on the use case above to prevent false-negative matches.
    ///
    /// See ["Fuzzy Hash Comparison" section of `FuzzyHashData`](FuzzyHashData#fuzzy-hash-comparison)
    /// for the reason why we need to care about those cases.
    ///
    /// # Useful Property
    ///
    /// If two fuzzy hashes are correctly provided and this method (or its
    /// family) returns [`true`], the similarity score is guaranteed to be
    /// greater than zero.
    ///
    /// This property can be used to simplify clustering since we are able to
    /// prove that the similarity score of two *different* fuzzy hashes is
    /// non-zero if this method (or its family) returns [`true`] (i.e. no actual
    /// comparison is required to split clusters on single-linkage clustering).
    ///
    /// # Advanced Topic: Implementing Equivalents
    ///
    /// While this method family can be important to preprocessing on
    /// single-linkage clustering, it can be inefficient as the number of fuzzy
    /// hash increases.
    /// On such cases, precomputing useful information to compute "comparison
    /// candidate" relations will help.
    ///
    /// [`FuzzyHashData::block_hash_1_windows()`] and family methods provide
    /// window access to block hash windows to enable implementing functionality
    /// equivalent to this method family.
    #[inline]
    pub fn is_comparison_candidate<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<fuzzy_norm_type!(S1, S2)>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        match block_size::compare_sizes(self.log_blocksize, other.log_blocksize) {
            BlockSizeRelation::Far => false,
            BlockSizeRelation::NearEq => self.is_comparison_candidate_near_eq_internal(other),
            BlockSizeRelation::NearLt => self.is_comparison_candidate_near_lt_internal(other),
            BlockSizeRelation::NearGt => self.is_comparison_candidate_near_gt_internal(other),
        }
    }
}

impl<const S1: usize, const S2: usize>
    core::convert::From<fuzzy_norm_type!(S1, S2)> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    // This "allow(unknown_lints)" is a workaround for Rust -1.62.
    // Remove this once MSRV 1.63 is acceptable.
    #[allow(unknown_lints)]
    #[allow(clippy::needless_borrow)]
    #[allow(clippy::needless_borrows_for_generic_args)]
    #[inline]
    fn from(value: fuzzy_norm_type!(S1, S2)) -> Self {
        let mut dest: Self = Self::new();
        dest.init_from_partial(&value);
        dest
    }
}

impl<const S1: usize, const S2: usize>
    core::convert::From<&fuzzy_norm_type!(S1, S2)> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn from(value: &fuzzy_norm_type!(S1, S2)) -> Self {
        let mut dest: Self = Self::new();
        dest.init_from_partial(value);
        dest
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::convert::From<FuzzyHashDualData<S1, S2, C1, C2>> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[allow(clippy::needless_borrow)]
    #[inline]
    fn from(value: FuzzyHashDualData<S1, S2, C1, C2>) -> Self {
        Self::from(value.as_ref())
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::convert::From<&FuzzyHashDualData<S1, S2, C1, C2>> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[allow(clippy::needless_borrow)]
    #[inline]
    fn from(value: &FuzzyHashDualData<S1, S2, C1, C2>) -> Self {
        Self::from(value.as_ref())
    }
}


/// Additional implementation for normalized fuzzy hashes,
/// enabling comparison between two fuzzy hashes directly.
impl<const S1: usize, const S2: usize> fuzzy_norm_type!(S1, S2)
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Internal function for [`compare()`](Self::compare()) and
    /// [`compare_unequal_internal()`](Self::compare_unequal_internal()) methods.
    ///
    /// `check_equality` parameter determines whether to perform
    /// an equality test (`100` if `self` and `other` are the same).
    #[inline(always)]
    fn compare_inlined_internal(&self, other: &Self, check_equality: bool) -> u32 {
        let rel = block_size::compare_sizes(self.log_blocksize, other.log_blocksize);
        if !rel.is_near() {
            return 0;
        }
        if check_equality && rel == BlockSizeRelation::NearEq && self == other {
            return 100;
        }
        let target = FuzzyHashCompareTarget::from(self);
        match rel {
            BlockSizeRelation::NearEq => { target.compare_unequal_near_eq_internal(other) },
            BlockSizeRelation::NearLt => { target.compare_unequal_near_lt_internal(other) },
            BlockSizeRelation::NearGt => { target.compare_unequal_near_gt_internal(other) },
            BlockSizeRelation::Far => unreachable!(), // grcov-excl-line:UNREACHABLE
        }
    }

    /// Compare two fuzzy hashes and retrieves the similarity score.
    #[inline]
    pub fn compare(&self, other: impl AsRef<Self>) -> u32 {
        let other = other.as_ref();
        self.compare_inlined_internal(other, true)
    }

    /// The internal implementation of [`Self::compare_unequal_unchecked()`].
    #[inline]
    fn compare_unequal_internal(&self, other: impl AsRef<Self>) -> u32 {
        let other = other.as_ref();
        debug_assert!(self != other);
        self.compare_inlined_internal(other, false)
    }

    /// Compare two fuzzy hashes assuming both are different.
    ///
    /// # Safety
    ///
    /// *   `self` and `other` must be different.
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless score.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn compare_unequal_unchecked(&self, other: impl AsRef<Self>) -> u32 {
        self.compare_unequal_internal(other)
    }

    /// *Slow*: Compare two fuzzy hashes assuming both are different.
    ///
    /// # Usage Constraints
    ///
    /// *   `self` and `other` must be different.
    ///
    /// # Performance Consideration
    ///
    /// This method's performance is not good enough (because of constraint
    /// checking).
    ///
    /// Use those instead:
    /// *   [`compare()`](Self::compare()) (checked)
    /// *   [`compare_unequal_unchecked()`](Self::compare_unequal_unchecked())
    ///     (unchecked)
    #[inline(always)]
    pub fn compare_unequal(&self, other: impl AsRef<Self>) -> u32 {
        let other = other.as_ref();
        assert!(self != other);
        self.compare_unequal_internal(other)
    }
}





/// Constant assertions related to this module
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::{const_assert, const_assert_eq};

    /// Check whether a given block size requires no score capping.
    #[allow(dead_code)] // to avoid false error
    const fn is_log_block_size_needs_no_capping(log_block_size: u8) -> bool {
        // Test whether score_cap in score_strings method is equal to
        // or greater than 100 (meaning, no capping is required).
        (100 + block_hash::MIN_LCS_FOR_COMPARISON as u64 - 1) /
            block_hash::MIN_LCS_FOR_COMPARISON as u64
                <= block_size::from_log_internal(log_block_size) as u64 / block_size::MIN as u64
    }

    // Compare with the precomputed value
    // (block_size / block_size::MIN >= 15, log_block_size >= 4 [2^log_block_size >= 16])
    const_assert_eq!(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER, 4);

    // Regular tests.
    const_assert!(block_size::is_log_valid(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));
    const_assert!(!is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER - 1));
    const_assert!( is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));

    // Regular tests (dynamic)
    // grcov-excl-br-start
    #[cfg(test)]
    #[test]
    fn log_block_size_capping_border_is_correct() {
        assert!(!is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER - 1));
        assert!( is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));
    }
    // grcov-excl-br-end

    // Test whether no arithmetic overflow occurs on
    // the similarity score computation.
    // grcov-excl-br-start
    #[cfg(test)]
    #[test]
    fn score_arithmetic_causes_no_overflow() {
        /*
            Possible arithmetic operations to check overflow:
            1.  (block_hash::FULL_SIZE * 2) * block_hash::FULL_SIZE
            2.  100 * block_hash::FULL_SIZE
        */
        assert!(
            u32::try_from(block_hash::FULL_SIZE).ok()
                .and_then(|x| x.checked_mul(2))
                .and_then(|x| x.checked_mul(u32::try_from(block_hash::FULL_SIZE).unwrap()))
                .is_some()
        );
        assert!(
            u32::try_from(block_hash::FULL_SIZE).ok()
                .and_then(|x| x.checked_mul(100))
                .is_some()
        );
    }
    // grcov-excl-br-end
}
