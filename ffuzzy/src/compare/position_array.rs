// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

use crate::compare::FuzzyHashCompareTarget;
use crate::hash::block::{block_size, block_hash};
use crate::macros::{optionally_unsafe, invariant};
use crate::utils::u64_lsb_ones;


#[cfg(test)]
pub(crate) mod tests;


/// A module containing utilities for an element of block hash position array.
///
/// # Incompatibility Notice
///
/// This module is renamed from `BlockHashPositionArrayElement` to
/// `block_hash_position_array_element` in the version 0.2.2.  The old name
/// `BlockHashPositionArrayElement` will be removed on the version 0.3.0.
pub mod block_hash_position_array_element {
    /// Checks whether a given position array entry has a sequence of the given
    /// length (or longer).
    ///
    /// # Performance Analysis
    ///
    /// This function expects many constant foldings assuming constant `len`.
    /// [`has_sequences_const()`] forces to do that.
    #[inline(always)]
    pub const fn has_sequences(pa_elem: u64, len: u32) -> bool {
        if len == 0 { return true; }
        if len == 1 { return pa_elem != 0; }
        if len == u64::BITS { return pa_elem == u64::MAX; }
        if len >  u64::BITS { return false; }
        let cont_01 = pa_elem;
        let cont_02 = cont_01 & (cont_01 >>  1);
        let cont_04 = cont_02 & (cont_02 >>  2);
        let cont_08 = cont_04 & (cont_04 >>  4);
        let cont_16 = cont_08 & (cont_08 >>  8);
        let cont_32 = cont_16 & (cont_16 >> 16);
        let mut len = len;
        let mut shift;
        let mut mask =
            if len < 4 {
                // MSB == 2
                len &= !2;
                shift = 2;
                cont_02
            }
            else if len < 8 {
                // MSB == 4
                len &= !4;
                shift = 4;
                cont_04
            }
            else if len < 16 {
                // MSB == 8
                len &= !8;
                shift = 8;
                cont_08
            }
            else if len < 32 {
                // MSB == 16
                len &= !16;
                shift = 16;
                cont_16
            }
            else /* if len < 64 */ {
                // MSB == 32
                len &= !32;
                shift = 32;
                cont_32
            };
        if (len & 16) != 0 { mask &= cont_16 >> shift; shift += 16; }
        if (len &  8) != 0 { mask &= cont_08 >> shift; shift +=  8; }
        if (len &  4) != 0 { mask &= cont_04 >> shift; shift +=  4; }
        if (len &  2) != 0 { mask &= cont_02 >> shift; shift +=  2; }
        if (len &  1) != 0 { mask &= cont_01 >> shift; }
        mask != 0
    }

    /// The generic variant of [`has_sequences()`](has_sequences()).
    ///
    /// It improves the performance by intensive constant foldings.
    #[inline(always)]
    pub const fn has_sequences_const<const LEN: u32>(pa_elem: u64) -> bool {
        has_sequences(pa_elem, LEN)
    }
}


/// Represents abstract representation of the block hash position array.
///
/// Each element of the position array indicates which positions in
/// the corresponding block hash has the given alphabet
/// (note that the array index is of the alphabet).
///
/// For instance, if `representation()[5] == 0x81`, it means the block hash
/// contains the alphabet index `5` in the positions `0` and `7`
/// (block hash glob: `E??????E*`).
///
/// This is because the bit 0 (`0x01`) at the index 5 means that position 0 has
/// the alphabet with index `5` (`E`).  Likewise, the bit 7 (`0x80`) at the
/// index 5 corresponds to the fact that position 7 has the alphabet with
/// index `5` (`E`).
///
/// This representation makes it possible to make some dynamic programming
/// algorithms bit-parallel.  In other words, some table updates of
/// certain top-down dynamic programming algorithms can be
/// represented as logical expressions (with some arithmetic ones
/// to enable, for instance, horizontal propagation).  This is particularly
/// effective on ssdeep because each block hash has a maximum size of
/// [`block_hash::FULL_SIZE`] (64; many 64-bit machines would handle that
/// efficiently and even 32-bit machines can benefit from).
///
/// This is *so* fast that the bit-parallel approach is still faster
/// even if we don't use any batching.
///
/// For an example of such algorithms, see
/// [Bitap algorithm](https://en.wikipedia.org/wiki/Bitap_algorithm).
///
/// # Alphabet / Character Sets
///
/// Despite that the algorithm itself is independent from the number of
/// alphabets in the string, this trait is defined for ssdeep and requires
/// that the all elements inside the string is less than
/// [`block_hash::ALPHABET_SIZE`] (64).
///
/// In other words, a string must be an array of Base64 indices
/// (not a Base64 string itself).
pub trait BlockHashPositionArrayData {
    /// Returns the raw representation of the block hash position array.
    fn representation(&self) -> &[u64; block_hash::ALPHABET_SIZE];
    /// Returns the length of the block hash.
    fn len(&self) -> u8;
    /// Returns whether the block hash is empty.
    #[inline(always)]
    fn is_empty(&self) -> bool { self.len() == 0 }

    /// Performs full validity checking of a position array object.
    ///
    /// # Compatibility Note
    ///
    /// Note that, since version 0.2, this method does not check whether
    /// the object contains a normalized string.  For this purpose, use
    /// [`is_valid_and_normalized()`](Self::is_valid_and_normalized()) instead.
    fn is_valid(&self) -> bool {
        let len = self.len();
        if len > 64 { return false; }
        let expected_total: u64 = u64_lsb_ones(len as u32);
        let mut total: u64 = 0;
        for &pos in self.representation() {
            if (total & pos) != 0 {
                // Two or more alphabets are placed in the same position.
                return false;
            }
            total |= pos;
        }
        if total != expected_total {
            // Not all characters are placed in the position array
            // or a character is placed outside "the string".
            return false;
        }
        true
    }

    /// Performs full validity checking and the normalization test
    /// of a position array object.
    ///
    /// If it returns [`true`], the position array representation is valid *and*
    /// the corresponding string is already normalized.
    ///
    /// To pass this validity test, the string cannot contain a sequence
    /// consisting of the same character longer than
    /// [`block_hash::MAX_SEQUENCE_SIZE`].
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](crate::hash::FuzzyHashData#normalization)
    fn is_valid_and_normalized(&self) -> bool {
        if !self.is_valid() { return false; }
        for &pos in self.representation() {
            if block_hash_position_array_element::has_sequences_const::<
                { block_hash::MAX_SEQUENCE_SIZE as u32 + 1 }
            >(pos)
            {
                // A long repeating character sequence is found.
                return false;
            }
        }
        true
    }
}


/// Represents abstract representation of the block hash position array
/// (mutable portions).
pub(crate) trait BlockHashPositionArrayDataMut: BlockHashPositionArrayData {
    /// Returns the raw mutable representation of the block hash position array.
    ///
    /// This method must return the same reference to the
    /// [`BlockHashPositionArrayData::representation`].
    fn representation_mut(&mut self) -> &mut [u64; block_hash::ALPHABET_SIZE];

    /// Returne the raw mutable representation of the block hash position array.
    fn len_mut(&mut self) -> &mut u8;
}


/// The implementation of the block hash position array (unchecked; immutable).
///
/// # Examples
///
/// This trait should not be accessible from outside.
///
/// ```compile_fail
/// use ssdeep::internal_comparison::BlockHashPositionArrayImplInternal;
/// ```
/// ```compile_fail
/// use ssdeep::compare::position_array::BlockHashPositionArrayImplInternal;
/// ```
pub trait BlockHashPositionArrayImplInternal: BlockHashPositionArrayData {
    /// The internal implementation of [`BlockHashPositionArrayImplUnchecked::is_equiv_unchecked()`].
    #[inline]
    fn is_equiv_internal(&self, other: &[u8]) -> bool {
        debug_assert!(self.is_valid());
        debug_assert!(other.len() <= 64);
        let len = self.len();
        let representation = self.representation();
        if (len as usize) != other.len() { return false; }
        optionally_unsafe! {
            for (i, &ch) in other.iter().enumerate() {
                invariant!((ch as usize) < block_hash::ALPHABET_SIZE);
                let value = representation[ch as usize]; // grcov-excl-br-line:ARRAY
                if value & (1u64 << i) == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// The internal implementation of [`BlockHashPositionArrayImplUnchecked::has_common_substring_unchecked()`].
    #[inline(always)]
    fn has_common_substring_internal(&self, other: &[u8]) -> bool {
        debug_assert!(self.is_valid());
        let len = self.len();
        let representation = self.representation();
        if (len as usize)  < block_hash::MIN_LCS_FOR_COMPARISON
            || other.len() < block_hash::MIN_LCS_FOR_COMPARISON
        {
            return false;
        }
        optionally_unsafe! {
            let mut d: u64;
            let mut r: usize = block_hash::MIN_LCS_FOR_COMPARISON - 1;
            let mut l: usize;
            while r < other.len() {
                l = r - (block_hash::MIN_LCS_FOR_COMPARISON - 1);
                let mut i: usize = other.len() - 1 - r;
                invariant!(i < other.len());
                invariant!((other[i] as usize) < block_hash::ALPHABET_SIZE);
                d = representation[other[i] as usize]; // grcov-excl-br-line:ARRAY
                while d != 0 {
                    r -= 1;
                    i += 1;
                    invariant!(i < other.len());
                    invariant!((other[i] as usize) < block_hash::ALPHABET_SIZE);
                    d = (d << 1) & representation[other[i] as usize]; // grcov-excl-br-line:ARRAY
                    if r == l && d != 0 {
                        return true;
                    }
                }
                // Boyer–Moore-like skipping
                r += block_hash::MIN_LCS_FOR_COMPARISON;
            }
        }
        false
    }

    /// The internal implementation of [`BlockHashPositionArrayImplUnchecked::edit_distance_unchecked()`].
    #[inline(always)]
    fn edit_distance_internal(&self, other: &[u8]) -> u32 {
        let len = self.len();
        let representation = self.representation();
        debug_assert!(self.is_valid());
        debug_assert!((len as usize) <= block_hash::FULL_SIZE);
        debug_assert!(other.len() <= block_hash::FULL_SIZE);
        if len == 0 { return other.len() as u32; }
        let mut cur = len as u32;
        optionally_unsafe! {
            let msb: u64 = 1u64 << (len - 1);
            let mut pv: u64 = 0xffff_ffff_ffff_ffff_u64;
            let mut nv: u64 = 0;
            for &ch in other.iter() {
                invariant!((ch as usize) < block_hash::ALPHABET_SIZE);
                let mt: u64 = representation[ch as usize]; // grcov-excl-br-line:ARRAY
                let zd: u64 = ((mt & pv).wrapping_add(pv) ^ pv) | mt | nv;
                let nh: u64 = pv & zd;
                cur -= u32::from((nh & msb) != 0);
                let x: u64 = nv | !(pv | zd) | (pv & !mt & 1u64);
                let y: u64 = u64::wrapping_sub(pv, nh) >> 1;
                /*
                    i-th bit of ph does not depend on i-th bit of y
                    (only upper bits of ph are affected).
                    So, ph does not depend on invalid bit in y.
                */
                let ph: u64 = u64::wrapping_add(x, y) ^ y;
                cur += u32::from((ph & msb) != 0);
                let t: u64 = (ph << 1).wrapping_add(1);
                nv = t & zd;
                pv = (nh << 1) | !(t | zd) | (t & u64::wrapping_sub(pv, nh));
            }
        }
        cur
    }

    /// The internal implementation of [`BlockHashPositionArrayImplUnchecked::score_strings_raw_unchecked()`].
    #[inline(always)]
    fn score_strings_raw_internal(&self, other: &[u8]) -> u32 {
        let len = self.len();
        debug_assert!(self.is_valid_and_normalized());
        debug_assert!((len as usize) <= block_hash::FULL_SIZE);
        debug_assert!(other.len() <= block_hash::FULL_SIZE);
        if !self.has_common_substring_internal(other) {
            return 0;
        }
        let dist = self.edit_distance_internal(other);
        // Scale the raw edit distance to a 0 to 100 score (familiar to humans).
        optionally_unsafe! {
            // rustc/LLVM cannot prove that
            // (len as u32 + other.len() as u32)
            //     <= block_hash::MIN_LCS_FOR_COMPARISON * 2 .
            // Place this invariant to avoid division-by-zero checking.
            invariant!((len as u32 + other.len() as u32) > 0);
        }
        /*
            Possible arithmetic operations to check overflow:
            1.  (block_hash::FULL_SIZE * 2) * block_hash::FULL_SIZE
            2.  100 * block_hash::FULL_SIZE
        */
        100 - (100 * (
            (dist * block_hash::FULL_SIZE as u32) / (len as u32 + other.len() as u32) // grcov-excl-br-line:DIVZERO
        )) / block_hash::FULL_SIZE as u32
    }

    /// The internal implementation of [`BlockHashPositionArrayImplUnchecked::score_strings_unchecked()`].
    #[inline(never)]
    fn score_strings_internal(&self, other: &[u8], log_block_size: u8) -> u32 {
        /*
            WARNING: Don't be confused!
            This is one of the very few functions so that log_block_size can be
            equal to block_size::NUM_VALID (which is normally invalid).
        */
        let len = self.len();
        debug_assert!(self.is_valid_and_normalized());
        debug_assert!((len as usize) <= block_hash::FULL_SIZE);
        debug_assert!(other.len() <= block_hash::FULL_SIZE);
        debug_assert!((log_block_size as usize) <= block_size::NUM_VALID);
        let score = self.score_strings_raw_internal(other);
        // Cap the score to prevent exaggregating the match size if block size is small enough.
        if log_block_size >= FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER {
            return score;
        }
        let score_cap = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison_internal(
            log_block_size,
            len,
            other.len() as u8
        );
        u32::min(score, score_cap)
    }
}


/// The implementation of the block hash position array (unchecked; immutable).
///
/// # Safety
///
/// This trait contains `unsafe` methods and need to comply with constraints
/// described in each method.
///
/// # Incompatibility Notice
///
/// This trait is renamed from `BlockHashPositionArrayImplUnsafe` to
/// `BlockHashPositionArrayImplUnchecked` in the version 0.2.3.  The old name
/// `BlockHashPositionArrayImplUnsafe` will be removed on the version 0.3.0.
#[cfg(feature = "unchecked")]
#[allow(unsafe_code)]
pub unsafe trait BlockHashPositionArrayImplUnchecked: BlockHashPositionArrayData {
    /// Compare whether two block hashes are equivalent.
    ///
    /// # Safety
    ///
    /// *   The length of `other` must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless value.
    unsafe fn is_equiv_unchecked(&self, other: &[u8]) -> bool;

    /// Checks whether two given strings have common substrings with a length
    /// of [`block_hash::MIN_LCS_FOR_COMPARISON`].
    ///
    /// # Algorithm Implemented (By Default)
    ///
    /// This function implements a Boyer–Moore-like bit-parallel algorithm to
    /// find a fixed-length common substring.  The original algorithm is the
    /// Backward Shift-Add algorithm for the *k*-LCF problem
    /// [[Hirvola, 2016]](https://aaltodoc.aalto.fi/bitstream/handle/123456789/21625/master_Hirvola_Tommi_2016.pdf)
    /// (which searches the longest common substring with
    /// up to *k* errors under the Hamming distance).
    ///
    /// This algorithm is modified:
    /// *   to search only perfect matches (up to 0 errors; *k* = 0),
    /// *   to return as soon as possible if it finds a common substring and
    /// *   to share the position array representation with
    ///     [`BlockHashPositionArrayImpl::edit_distance()`] by reversing
    ///     a pattern from the original paper
    ///     (the original algorithm used reverse "incidence matrix").
    ///
    /// # Safety
    ///
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless value.
    unsafe fn has_common_substring_unchecked(&self, other: &[u8]) -> bool;

    /// Computes the edit distance between two given strings.
    ///
    /// Specifically, it computes the Longest Common Subsequence (LCS)
    /// distance, allowing character insertion and deletion as two primitive
    /// operations (in cost 1).
    ///
    /// # Algorithm Implemented (By Default)
    ///
    /// [[Hyyrö et al., 2005] (doi:10.1007/11427186_33)](https://doi.org/10.1007/11427186_33)
    /// presented a way to compute so called Indel-Distance using a
    /// bit-parallel approach and this method is based on it.
    ///
    /// This algorithm is needed to be modified for our purpose because the
    /// purpose of the original algorithm is to find a "substring"
    /// similar to a pattern string.
    ///
    /// # Safety
    ///
    /// *   The length of `other` must be short enough
    ///     (up to [`block_hash::FULL_SIZE`] is guaranteed to be safe).
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless distance.
    unsafe fn edit_distance_unchecked(&self, other: &[u8]) -> u32;

    /// Compare two block hashes and computes the similarity score
    /// without capping.
    ///
    /// This method does not "cap" the score to prevent exaggregating the
    /// matches that are not meaningful enough, making this function block size
    /// independent.
    ///
    /// # Safety
    ///
    /// *   The lengths of both `self` and `other` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless score.
    unsafe fn score_strings_raw_unchecked(&self, other: &[u8]) -> u32;

    /// Compare two block hashes and computes the similarity score.
    ///
    /// This method "caps" the score to prevent exaggregating the matches that
    /// are not meaningful enough.  This behavior depends on the block size
    /// (score cap gets higher when block size gets higher).
    ///
    /// # Safety
    ///
    /// *   The lengths of both `self` and `other` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    /// *   `log_block_size` [must be valid](block_size::is_log_valid)
    ///     or must be equal to [`block_size::NUM_VALID`] (this value itself is
    ///     not valid as a block size for a fuzzy hash object but valid on this
    ///     method).
    ///
    /// If they are not satisfied, it will return a meaningless score.
    unsafe fn score_strings_unchecked(&self, other: &[u8], log_block_size: u8) -> u32;
}

#[cfg(feature = "unchecked")]
#[allow(unsafe_code)]
unsafe impl<T> BlockHashPositionArrayImplUnchecked for T
where
    T: BlockHashPositionArrayImplInternal
{
    #[inline(always)]
    unsafe fn is_equiv_unchecked(&self, other: &[u8]) -> bool {
        self.is_equiv_internal(other)
    }

    #[inline(always)]
    unsafe fn has_common_substring_unchecked(&self, other: &[u8]) -> bool {
        self.has_common_substring_internal(other)
    }

    #[inline(always)]
    unsafe fn edit_distance_unchecked(&self, other: &[u8]) -> u32 {
        self.edit_distance_internal(other)
    }

    #[inline(always)]
    unsafe fn score_strings_raw_unchecked(&self, other: &[u8]) -> u32 {
        self.score_strings_raw_internal(other)
    }

    #[inline(always)]
    unsafe fn score_strings_unchecked(&self, other: &[u8], log_block_size: u8) -> u32 {
        self.score_strings_internal(other, log_block_size)
    }
}


/// The implementation of the block hash position array (safe; immutable).
pub trait BlockHashPositionArrayImpl: BlockHashPositionArrayData {
    /// Compare whether two block hashes are equivalent.
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `other` must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn is_equiv(&self, other: &[u8]) -> bool;

    /// Checks whether two given strings have common substrings with a length
    /// of [`block_hash::MIN_LCS_FOR_COMPARISON`].
    ///
    /// # Algorithm Implemented (By Default)
    ///
    /// This function implements a Boyer–Moore-like bit-parallel algorithm to
    /// find a fixed-length common substring.  The original algorithm is the
    /// Backward Shift-Add algorithm for the *k*-LCF problem
    /// [[Hirvola, 2016]](https://aaltodoc.aalto.fi/bitstream/handle/123456789/21625/master_Hirvola_Tommi_2016.pdf)
    /// (which searches the longest common substring with
    /// up to *k* errors under the Hamming distance).
    ///
    /// This algorithm is modified:
    /// *   to search only perfect matches (up to 0 errors; *k* = 0),
    /// *   to return as soon as possible if it finds a common substring and
    /// *   to share the position array representation with
    ///     [`edit_distance()`](Self::edit_distance()) by reversing
    ///     a pattern from the original paper
    ///     (the original algorithm used reverse "incidence matrix").
    ///
    /// # Usage Constraints
    ///
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn has_common_substring(&self, other: &[u8]) -> bool;

    /// Computes the edit distance between two given strings.
    ///
    /// Specifically, it computes the Longest Common Subsequence (LCS)
    /// distance, allowing character insertion and deletion as two primitive
    /// operations (in cost 1).
    ///
    /// # Algorithm Implemented (By Default)
    ///
    /// [[Hyyrö et al., 2005] (doi:10.1007/11427186_33)](https://doi.org/10.1007/11427186_33)
    /// presented a way to compute so called Indel-Distance using a
    /// bit-parallel approach and this method is based on it.
    ///
    /// This algorithm is needed to be modified for our purpose because the
    /// purpose of the original algorithm is to find a "substring"
    /// similar to a pattern string.
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `other` must be short enough
    ///     (up to [`block_hash::FULL_SIZE`] is guaranteed to be safe).
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn edit_distance(&self, other: &[u8]) -> u32;

    /// Compare two block hashes and computes the similarity score
    /// without capping.
    ///
    /// This method does not "cap" the score to prevent exaggregating the
    /// matches that are not meaningful enough, making this function block size
    /// independent.
    ///
    /// # Usage Constraints
    ///
    /// *   The lengths of both `self` and `other` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn score_strings_raw(&self, other: &[u8]) -> u32;

    /// Compare two block hashes and computes the similarity score.
    ///
    /// This method "caps" the score to prevent exaggregating the matches that
    /// are not meaningful enough.  This behavior depends on the block size
    /// (score cap gets higher when block size gets higher).
    ///
    /// # Usage Constraints
    ///
    /// *   The lengths of both `self` and `other` must not exceed
    ///     [`block_hash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    /// *   `log_block_size` [must be valid](block_size::is_log_valid)
    ///     or must be equal to [`block_size::NUM_VALID`] (this value itself is
    ///     not valid as a block size for a fuzzy hash object but valid on this
    ///     method).
    fn score_strings(&self, other: &[u8], log_block_size: u8) -> u32;
}

impl<T> BlockHashPositionArrayImpl for T
where
    T: BlockHashPositionArrayImplInternal
{
    fn is_equiv(&self, other: &[u8]) -> bool {
        assert!(self.is_valid());
        assert!(other.len() <= 64);
        assert!(other.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        self.is_equiv_internal(other)
    }

    fn has_common_substring(&self, other: &[u8]) -> bool {
        assert!(self.is_valid());
        assert!(other.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        self.has_common_substring_internal(other)
    }

    fn edit_distance(&self, other: &[u8]) -> u32 {
        assert!(self.is_valid());
        assert!((self.len() as usize) <= block_hash::FULL_SIZE);
        assert!(other.len() <= block_hash::FULL_SIZE);
        assert!(other.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        self.edit_distance_internal(other)
    }

    fn score_strings_raw(&self, other: &[u8]) -> u32 {
        assert!(self.is_valid_and_normalized());
        assert!((self.len() as usize) <= block_hash::FULL_SIZE);
        assert!(other.len() <= block_hash::FULL_SIZE);
        assert!(other.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        self.score_strings_raw_internal(other)
    }

    fn score_strings(&self, other: &[u8], log_block_size: u8) -> u32 {
        assert!(self.is_valid_and_normalized());
        assert!((self.len() as usize) <= block_hash::FULL_SIZE);
        assert!(other.len() <= block_hash::FULL_SIZE);
        assert!(other.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        assert!((log_block_size as usize) <= block_size::NUM_VALID);
        self.score_strings_internal(other, log_block_size)
    }
}


/// The implementation of the block hash position array (unchecked; mutable).
pub(crate) trait BlockHashPositionArrayImplMutInternal: BlockHashPositionArrayDataMut {
    /// Clears the current representation of the block hash
    /// without resetting the length.
    #[inline(always)]
    fn clear_representation_only(&mut self) {
        self.representation_mut().fill(0);
    }

    /// Clears the current representation of the block hash.
    #[inline(always)]
    fn clear(&mut self) {
        self.clear_representation_only();
        *self.len_mut() = 0;
    }

    /// Sets the length of the block hash.
    fn set_len_internal(&mut self, len: u8);

    /// Initialize (encode) the object from a given byte array and length
    /// without clearing or checking validity.
    ///
    /// This method is intended to be used just after clearing the position
    /// array (i.e. just after the initialization).
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `blockhash` must not exceed 64.
    /// *   All elements in `blockhash` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn init_from_partial(&mut self, blockhash: &[u8]) {
        debug_assert!(blockhash.len() <= 64);
        let representation = self.representation_mut();
        optionally_unsafe! {
            for (i, &ch) in blockhash.iter().enumerate() {
                invariant!((ch as usize) < block_hash::ALPHABET_SIZE);
                representation[ch as usize] |= 1u64 << i; // grcov-excl-br-line:ARRAY
            }
        }
        self.set_len_internal(blockhash.len() as u8);
    }
}


/// The implementation of the block hash position array (safe; mutable).
pub(crate) trait BlockHashPositionArrayImplMut: BlockHashPositionArrayDataMut {
    /// Clear and initialize (encode) the object from a given slice.
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `blockhash` must not exceed 64.
    /// *   All elements in `blockhash` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    fn init_from(&mut self, blockhash: &[u8]);
}

impl<T> BlockHashPositionArrayImplMut for T
where
    T: BlockHashPositionArrayImplMutInternal
{
    fn init_from(&mut self, blockhash: &[u8]) {
        assert!(blockhash.len() <= 64);
        assert!(blockhash.iter().all(|&x| (x as usize) < block_hash::ALPHABET_SIZE));
        self.clear_representation_only();
        self.init_from_partial(blockhash);
    }
}


/// A position array based on existing immutable references.
pub struct BlockHashPositionArrayRef<'a>(pub &'a [u64; block_hash::ALPHABET_SIZE], pub &'a u8);
/// A position array based on existing mutable references.
pub(crate) struct BlockHashPositionArrayMutRef<'a>(pub(crate) &'a mut [u64; block_hash::ALPHABET_SIZE], pub(crate) &'a mut u8);

impl<'a> BlockHashPositionArrayData for BlockHashPositionArrayRef<'a> {
    #[inline(always)]
    fn representation(&self) -> &[u64; block_hash::ALPHABET_SIZE] {
        self.0
    }

    #[inline(always)]
    fn len(&self) -> u8 {
        *self.1
    }
}

impl<'a> BlockHashPositionArrayData for BlockHashPositionArrayMutRef<'a> {
    #[inline(always)]
    fn representation(&self) -> &[u64; block_hash::ALPHABET_SIZE] {
        self.0
    }

    #[inline(always)]
    fn len(&self) -> u8 {
        *self.1
    }
}

impl<'a> BlockHashPositionArrayDataMut for BlockHashPositionArrayMutRef<'a> {
    #[inline(always)]
    fn representation_mut(&mut self) -> &mut [u64; block_hash::ALPHABET_SIZE] {
        self.0
    }

    #[inline(always)]
    fn len_mut(&mut self) -> &mut u8 {
        self.1
    }
}

impl<'a> BlockHashPositionArrayImplInternal for BlockHashPositionArrayRef<'a> {}

impl<'a> BlockHashPositionArrayImplInternal for BlockHashPositionArrayMutRef<'a> {}
impl<'a> BlockHashPositionArrayImplMutInternal
    for BlockHashPositionArrayMutRef<'a>
{
    #[inline(always)]
    fn set_len_internal(&mut self, len: u8) {
        debug_assert!(len <= 64);
        *self.1 = len;
    }
}


/// An example of position array-related traits.
///
/// This type is not used by [`FuzzyHashCompareTarget`] but can be a good
/// example to use internal efficient implementation.
///
/// See also:
/// 1.  [`BlockHashPositionArrayData`]
/// 2.  [`BlockHashPositionArrayImpl`]
#[derive(Debug, PartialEq, Eq)]
pub struct BlockHashPositionArray {
    /// The block hash position array representation.
    representation: [u64; block_hash::ALPHABET_SIZE],
    /// The length of this block hash.
    len: u8,
}

impl BlockHashPositionArray {
    /// Creates a new position array object with empty contents.
    pub fn new() -> Self {
        BlockHashPositionArray {
            representation: [0u64; block_hash::ALPHABET_SIZE],
            len: 0
        }
    }

    // Because mutable interface for the block hash position array is private,
    // safe functions are exported separately.

    /// Clears the current representation of the block hash.
    pub fn clear(&mut self) {
        BlockHashPositionArrayImplMutInternal::clear(self);
    }

    /// Clear and initialize (encode) the object from a given slice.
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `blockhash` must not exceed 64.
    /// *   All elements in `blockhash` must be less than
    ///     [`block_hash::ALPHABET_SIZE`].
    pub fn init_from(&mut self, blockhash: &[u8]) {
        BlockHashPositionArrayImplMut::init_from(self, blockhash);
    }
}

impl BlockHashPositionArrayData for BlockHashPositionArray {
    fn representation(&self) -> &[u64; block_hash::ALPHABET_SIZE] {
        &self.representation
    }

    fn len(&self) -> u8 {
        self.len
    }
}

impl BlockHashPositionArrayDataMut for BlockHashPositionArray {
    fn representation_mut(&mut self) -> &mut [u64; block_hash::ALPHABET_SIZE] {
        &mut self.representation
    }

    fn len_mut(&mut self) -> &mut u8 {
        &mut self.len
    }
}

impl BlockHashPositionArrayImplInternal for BlockHashPositionArray {}
impl BlockHashPositionArrayImplMutInternal for BlockHashPositionArray {
    fn set_len_internal(&mut self, len: u8) {
        debug_assert!(len <= 64);
        self.len = len;
    }
}

impl Default for BlockHashPositionArray {
    fn default() -> Self {
        Self::new()
    }
}





/// Constant assertions related to this module
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::const_assert;

    // Prerequisite for 64-bit position array
    // grcov-excl-br-start
    #[cfg(test)]
    #[test]
    fn position_array_fits_in_64_bits() {
        assert!(
            u32::try_from(block_hash::FULL_SIZE)
                .map(|x| x <= u64::BITS)
                .unwrap_or(false)
        );
    }
    // grcov-excl-br-end

    // Prerequisite for 64-bit position array
    const_assert!(block_hash::FULL_SIZE <= 64);

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
