// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

use crate::hash::FuzzyHashData;
use crate::hash::block::{
    BlockSize, BlockSizeRelation, BlockHash,
    BlockHashSize, ConstrainedBlockHashSize,
    BlockHashSizes, ConstrainedBlockHashSizes
};
use crate::macros::{optionally_unsafe, invariant};


/// Test-only utilities.
#[cfg(any(test, doc))]
mod test_utils;
#[cfg(test)]
mod tests;


/// A position array-based block hash except its length.
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
/// [`BlockHash::FULL_SIZE`] (64; many 64-bit machines would handle that
/// efficiently and even 32-bit machines can benefit from).
///
/// This is *so* fast that the bit-parallel approach is still faster
/// even if we don't use any batching.
///
/// For an example of such algorithms, see
/// [Bitap algorithm](https://en.wikipedia.org/wiki/Bitap_algorithm).
///
/// # Important Note: Length not included
///
/// Note that this struct does not contain its length inside.  The length must
/// be given from outside each time you call the methods.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BlockHashPositionArray {
    pub(crate) representation: [u64; BlockHash::ALPHABET_SIZE]
}

impl BlockHashPositionArray {
    /// Creates empty position array-based block hash object without length.
    ///
    /// Because the resulting object doesn't contain any characters, it is
    /// only valid on length zero.
    pub fn new() -> Self {
        BlockHashPositionArray {
            representation: [0u64; BlockHash::ALPHABET_SIZE]
        }
    }

    /// Returns the raw representation of the block hash position array.
    pub fn representation(&self) -> [u64; BlockHash::ALPHABET_SIZE] {
        self.representation
    }

    /// Clears the current representation of the block hash.
    pub fn clear(&mut self) {
        self.representation.fill(0);
    }

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
    ///     [`BlockHash::ALPHABET_SIZE`].
    #[inline]
    pub(crate) fn init_from_partial(&mut self, blockhash: &[u8]) {
        debug_assert!(blockhash.len() <= 64);
        optionally_unsafe! {
            for (i, &ch) in blockhash.iter().enumerate() {
                invariant!((ch as usize) < BlockHash::ALPHABET_SIZE);
                self.representation[ch as usize] |= 1u64 << i; // grcov-excl-br-line:ARRAY
            }
        }
    }

    /// Clear and initialize (encode) the object from a given slice.
    ///
    /// # Usage Constraints
    ///
    /// *   The length of `blockhash` must not exceed 64.
    /// *   All elements in `blockhash` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    pub fn init_from(&mut self, blockhash: &[u8]) {
        assert!(blockhash.len() <= 64);
        assert!(blockhash.iter().all(|&x| (x as usize) < BlockHash::ALPHABET_SIZE));
        self.clear();
        self.init_from_partial(blockhash);
    }

    /// The internal implementation of [`Self::is_equiv_unchecked`].
    #[inline]
    pub(crate) fn is_equiv_internal(&self, len: u8, other: &[u8]) -> bool {
        debug_assert!(other.len() <= 64);
        debug_assert!(self.is_valid(len));
        if (len as usize) != other.len() { return false; }
        optionally_unsafe! {
            for (i, &ch) in other.iter().enumerate() {
                invariant!((ch as usize) < BlockHash::ALPHABET_SIZE);
                let value = self.representation[ch as usize]; // grcov-excl-br-line:ARRAY
                if value & (1u64 << i) == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Compare whether two block hashes are equivalent.
    ///
    /// # Safety
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   The length of `other` must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless value.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn is_equiv_unchecked(&self, len: u8, other: &[u8]) -> bool {
        self.is_equiv_internal(len, other)
    }

    /// Compare whether two block hashes are equivalent.
    ///
    /// # Usage Constraints
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   The length of `other` must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    pub fn is_equiv(&self, len: u8, other: &[u8]) -> bool {
        assert!(other.len() <= 64);
        assert!(self.is_valid(len));
        assert!(other.iter().all(|&x| (x as usize) < BlockHash::ALPHABET_SIZE));
        self.is_equiv_internal(len, other)
    }

    /// Performs full validity checking of a position array
    /// considering a given length.
    ///
    /// # Incompatibility Notice
    ///
    /// From v0.2.0, the new argument `test_norm` will be
    /// added, making this method incompatible with v0.1.x series.
    pub fn is_valid(&self, len: u8) -> bool {
        if len > 64 { return false; }
        let expected_total: u64 =
            (if len == 64 { 0 } else { 1u64 << len as u32 })
            .wrapping_sub(1);
        let mut total: u64 = 0;
        for pos in self.representation {
            if Self::element_has_sequences_const::<{BlockHash::MAX_SEQUENCE_SIZE as u32 + 1}>(pos) {
                // Long repeating character sequence is found.
                return false;
            }
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

    /// The internal implementation of [`Self::has_common_substring_unchecked`].
    #[inline(always)]
    pub(crate) fn has_common_substring_internal(&self, len: u8, other: &[u8]) -> bool {
        debug_assert!((len as u32) <= 64);
        debug_assert!(self.is_valid(len));
        if (len as usize) < FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH
            || other.len() < FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH
        {
            return false;
        }
        optionally_unsafe! {
            let mut d: u64;
            let mut r: usize = FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH - 1;
            let mut l: usize;
            while r < other.len() {
                l = r - (FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH - 1);
                let mut i: usize = other.len() - 1 - r;
                invariant!(i < other.len());
                invariant!((other[i] as usize) < BlockHash::ALPHABET_SIZE);
                d = self.representation[other[i] as usize]; // grcov-excl-br-line:ARRAY
                while d != 0 {
                    r -= 1;
                    i += 1;
                    invariant!(i < other.len());
                    invariant!((other[i] as usize) < BlockHash::ALPHABET_SIZE);
                    d = (d << 1) & self.representation[other[i] as usize]; // grcov-excl-br-line:ARRAY
                    if r == l && d != 0 {
                        return true;
                    }
                }
                // Boyer–Moore-like skipping
                r += FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH;
            }
        }
        false
    }

    /// Checks whether two given strings have common substrings with a length
    /// of [`MIN_LCS_FOR_BLOCKHASH`](FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH).
    ///
    /// # Algorithm Implemented
    ///
    /// This function implements a Boyer–Moore-like bit-parallel algorithm to
    /// find a fixed-length common substring.  The original algorithm is the
    /// Backward Shift-Add algorithm for the k-LCF problem
    /// [[Hirvola, 2016]](https://aaltodoc.aalto.fi/bitstream/handle/123456789/21625/master_Hirvola_Tommi_2016.pdf)
    /// (which searches the longest common substring with
    /// up to k errors under the Hamming distance).
    ///
    /// This algorithm is modified:
    /// *   to search only perfect matches (up to 0 errors),
    /// *   to return as soon as possible if it finds a common substring and
    /// *   to share the position array representation with
    ///     [`edit_distance`](Self::edit_distance)
    ///     (the original algorithm used reverse "incidence matrix").
    ///
    /// # Safety
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless value.
    ///
    /// # Incompatibility Notice
    ///
    /// From v0.2.0, the new argument `expect_norm` will be
    /// added, making this method incompatible with v0.1.x series.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn has_common_substring_unchecked(&self, len: u8, other: &[u8]) -> bool {
        self.has_common_substring_internal(len, other)
    }

    /// Checks whether two given strings have common substrings with a length
    /// of [`MIN_LCS_FOR_BLOCKHASH`](FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH).
    ///
    /// # Algorithm Implemented
    ///
    /// This function implements a Boyer–Moore-like bit-parallel algorithm to
    /// find a fixed-length common substring.  The original algorithm is the
    /// Backward Shift-Add algorithm for the k-LCF problem
    /// [[Hirvola, 2016]](https://aaltodoc.aalto.fi/bitstream/handle/123456789/21625/master_Hirvola_Tommi_2016.pdf)
    /// (which searches the longest common substring with
    /// up to k errors under the Hamming distance).
    ///
    /// This algorithm is modified:
    /// *   to search only perfect matches (up to 0 errors),
    /// *   to return as soon as possible if it finds a common substring and
    /// *   to share the position array representation with
    ///     [`edit_distance`](Self::edit_distance)
    ///     (the original algorithm used reverse "incidence matrix").
    ///
    /// # Usage Constraints
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// # Incompatibility Notice
    ///
    /// From v0.2.0, the new argument `expect_norm` will be
    /// added, making this method incompatible with v0.1.x series.
    pub fn has_common_substring(&self, len: u8, other: &[u8]) -> bool {
        assert!((len as u32) <= 64);
        assert!(self.is_valid(len));
        self.has_common_substring_internal(len, other)
    }

    /// The internal implementation of [`Self::edit_distance_unchecked`].
    #[inline(always)]
    pub(crate) fn edit_distance_internal(&self, len: u8, other: &[u8]) -> u32 {
        debug_assert!((len as u32) <= 64);
        debug_assert!(u32::try_from(other.len()).is_ok());
        debug_assert!(self.is_valid(len));
        if len == 0 { return other.len() as u32; }
        let mut cur = len as u32;
        optionally_unsafe! {
            let msb: u64 = 1u64 << (len - 1);
            let mut pv: u64 = 0xffff_ffff_ffff_ffff_u64;
            let mut nv: u64 = 0;
            for &ch in other.iter() {
                invariant!((ch as usize) < BlockHash::ALPHABET_SIZE);
                let mt: u64 = self.representation[ch as usize]; // grcov-excl-br-line:ARRAY
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

    /// Computes the edit distance between two given strings
    ///
    /// Specifically, it computes the Longest Common Subsequence (LCS)
    /// distance, allowing character insertion and deletion as two primitive
    /// operations (in cost 1).
    ///
    /// # Algorithm Implemented
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
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless distance.
    ///
    /// # Incompatibility Notice
    ///
    /// From v0.2.0, the new argument `expect_norm` will be
    /// added, making this method incompatible with v0.1.x series.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn edit_distance_unchecked(&self, len: u8, other: &[u8]) -> u32 {
        self.edit_distance_internal(len, other)
    }

    /// Computes the edit distance between two given strings
    ///
    /// Specifically, it computes the Longest Common Subsequence (LCS)
    /// distance, allowing character insertion and deletion as two primitive
    /// operations (in cost 1).
    ///
    /// # Algorithm Implemented
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
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed 64.
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// # Incompatibility Notice
    ///
    /// From v0.2.0, the new argument `expect_norm` will be
    /// added, making this method incompatible with v0.1.x series.
    pub fn edit_distance(&self, len: u8, other: &[u8]) -> u32 {
        assert!((len as u32) <= 64);
        assert!(u32::try_from(other.len()).is_ok());
        assert!(self.is_valid(len));
        assert!(other.iter().all(|&x| (x as usize) < BlockHash::ALPHABET_SIZE));
        self.edit_distance_internal(len, other)
    }

    /// The internal implementation of [`Self::score_strings_raw_unchecked`].
    #[inline(always)]
    pub(crate) fn score_strings_raw_internal(&self, len: u8, other: &[u8]) -> u32 {
        debug_assert!(other.len() <= BlockHash::FULL_SIZE);
        debug_assert!((len as usize) <= BlockHash::FULL_SIZE);
        debug_assert!(self.is_valid(len));
        if !self.has_common_substring_internal(len, other) {
            return 0;
        }
        let dist = self.edit_distance_internal(len, other);
        // Scale the raw edit distance to a 0 to 100 score (familiar to humans).
        optionally_unsafe! {
            // rustc/LLVM cannot prove that
            // (len as u32 + other.len() as u32)
            //     <= FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH * 2 .
            // Place this invariant to avoid division-by-zero checking.
            invariant!((len as u32 + other.len() as u32) > 0);
        }
        100 - (100 * (
            (dist * BlockHash::FULL_SIZE as u32) / (len as u32 + other.len() as u32) // grcov-excl-br-line:DIVZERO
        )) / BlockHash::FULL_SIZE as u32
    }

    /// Compare two block hashes and computes the similarity score
    /// without capping.
    ///
    /// This method does not "cap" the score to prevent exaggregating the
    /// matches that are not meaningful enough, making this function block size
    /// independent.
    ///
    /// # Safety
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed
    ///     [`BlockHash::FULL_SIZE`].
    /// *   The length of `other` must not exceed [`BlockHash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn score_strings_raw_unchecked(&self, len: u8, other: &[u8]) -> u32 {
        self.score_strings_raw_internal(len, other)
    }

    /// Compare two block hashes and computes the similarity score
    /// without capping.
    ///
    /// This method does not "cap" the score to prevent exaggregating the
    /// matches that are not meaningful enough, making this function block size
    /// independent.
    ///
    /// # Usage Constraints
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed
    ///     [`BlockHash::FULL_SIZE`].
    /// *   The length of `other` must not exceed [`BlockHash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    pub fn score_strings_raw(&self, len: u8, other: &[u8]) -> u32 {
        assert!((len as usize) <= BlockHash::FULL_SIZE);
        assert!(other.len() <= BlockHash::FULL_SIZE);
        assert!(self.is_valid(len));
        assert!(other.iter().all(|&x| (x as usize) < BlockHash::ALPHABET_SIZE));
        self.score_strings_raw_internal(len, other)
    }

    /// The internal implementation of [`Self::score_strings_unchecked`].
    #[inline(never)]
    pub(crate) fn score_strings_internal(&self, len: u8, other: &[u8], log_block_size: u8) -> u32 {
        /*
            WARNING: Don't be confused!
            This is one of the very few functions so that log_block_size can be
            equal to BlockSize::NUM_VALID (which is normally invalid).
        */
        debug_assert!((len as usize) <= BlockHash::FULL_SIZE);
        debug_assert!(other.len() <= BlockHash::FULL_SIZE);
        debug_assert!((log_block_size as usize) <= BlockSize::NUM_VALID);
        debug_assert!(self.is_valid(len));
        let score = self.score_strings_raw_internal(len, other);
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

    /// Compare two block hashes and computes the similarity score.
    ///
    /// This method "caps" the score to prevent exaggregating the matches that
    /// are not meaningful enough.  This behavior depends on the block size
    /// (score cap gets higher when block size gets higher).
    ///
    /// # Safety
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed
    ///     [`BlockHash::FULL_SIZE`].
    /// *   The length of `other` must not exceed [`BlockHash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    /// *   `log_block_size` [must be valid](crate::hash::block::BlockSize::is_log_valid).
    ///
    /// If they are not satisfied, it will return a meaningless score.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn score_strings_unchecked(&self, len: u8, other: &[u8], log_block_size: u8) -> u32 {
        self.score_strings_internal(len, other, log_block_size)
    }

    /// Compare two block hashes and computes the similarity score.
    ///
    /// This method "caps" the score to prevent exaggregating the matches that
    /// are not meaningful enough.  This behavior depends on the block size
    /// (score cap gets higher when block size gets higher).
    ///
    /// # Usage Constraints
    ///
    /// *   This object must be valid on a given length `len`.
    /// *   `len` (the length of this object) must not exceed
    ///     [`BlockHash::FULL_SIZE`].
    /// *   The length of `other` must not exceed [`BlockHash::FULL_SIZE`].
    /// *   All elements in `other` must be less than
    ///     [`BlockHash::ALPHABET_SIZE`].
    /// *   `log_block_size` [must be valid](crate::hash::block::BlockSize::is_log_valid).
    #[inline(never)]
    pub fn score_strings(&self, len: u8, other: &[u8], log_block_size: u8) -> u32 {
        assert!((len as usize) <= BlockHash::FULL_SIZE);
        assert!(other.len() <= BlockHash::FULL_SIZE);
        assert!(other.iter().all(|&x| (x as usize) < BlockHash::ALPHABET_SIZE));
        assert!((log_block_size as usize) <= BlockSize::NUM_VALID);
        assert!(self.is_valid(len));
        self.score_strings_internal(len, other, log_block_size)
    }

    /// Checks whether a given position array entry has a sequence of the given
    /// length (or longer).
    ///
    /// # Performance Analysis
    ///
    /// This function expects many constant foldings assuming constant `len`.
    /// [`has_sequences_const`](Self::element_has_sequences_const) forces
    /// to do that.
    #[inline(always)]
    pub const fn element_has_sequences(pa_elem: u64, len: u32) -> bool {
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

    /// The generic variant of [`element_has_sequences`](Self::element_has_sequences).
    ///
    /// It improves the performance by intensive constant foldings.
    #[inline(always)]
    pub const fn element_has_sequences_const<const LEN: u32>(pa_elem: u64) -> bool {
        Self::element_has_sequences(pa_elem, LEN)
    }
}

impl Default for BlockHashPositionArray {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for BlockHashPositionArray {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", &self.representation))
    }
}


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
#[derive(Debug)]
pub struct FuzzyHashCompareTarget {
    /// The position array representation of block hash 1.
    ///
    /// See [`BlockHashPositionArray`] for details.
    pub(crate) blockhash1: BlockHashPositionArray,

    /// The position array representation of block hash 2.
    ///
    /// See [`BlockHashPositionArray`] for details.
    pub(crate) blockhash2: BlockHashPositionArray,

    /// Length of the block hash 1 (up to [`BlockHash::FULL_SIZE`]).
    pub(crate) len_blockhash1: u8,
    /// Length of the block hash 2 (up to [`BlockHash::FULL_SIZE`]).
    pub(crate) len_blockhash2: u8,

    /// Base-2 logarithm form of the actual block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](Self#block-size)
    pub(crate) log_blocksize: u8,
}

impl FuzzyHashCompareTarget {
    /// The minimum length of the common substring to compute edit distance
    /// between two block hashes.
    ///
    /// To score similarity between two block hashes, ssdeep expects that
    /// two block hashes are similar enough.  In other words, ssdeep expects
    /// that they have a common substring of a length
    /// [`MIN_LCS_FOR_BLOCKHASH`](Self::MIN_LCS_FOR_BLOCKHASH) or longer
    /// to reduce the possibility of false matches by chance.
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
    /// (≧ [`MIN_LCS_FOR_BLOCKHASH`](Self::MIN_LCS_FOR_BLOCKHASH))
    /// to compute the edit distance to compute the similarity score.
    ///
    /// Specifically, ssdeep requires a common substring of a length 7 to
    /// compute a similarity score.  Otherwise, the block hash comparison
    /// method returns zero (meaning, not similar).
    pub const MIN_LCS_FOR_BLOCKHASH: usize = 7;

    /// The lower bound (inclusive) of the *base-2 logarithm* form of
    /// the block size in which the score capping is no longer required.
    ///
    /// If `log_block_size` is equal to or larger than this value and
    /// `len1` and `len2` are at least
    /// [`MIN_LCS_FOR_BLOCKHASH`](Self::MIN_LCS_FOR_BLOCKHASH) in size,
    /// [`Self::score_cap_on_block_hash_comparison`]`(log_block_size, len1, len2)`
    /// is guaranteed to be `100` or greater.
    ///
    /// The score "cap" is computed as
    /// `(1 << log_block_size) * min(len1, len2)`.
    /// If this always guaranteed to be `100` or greater,
    /// capping the score is not longer required.
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
    /// This is expressed as `(1 << log_block_size) * MIN_LCS_FOR_BLOCKHASH`
    /// because both block hashes must at least as long as
    /// [`MIN_LCS_FOR_BLOCKHASH`](Self::MIN_LCS_FOR_BLOCKHASH) to perform
    /// edit distance-based scoring.
    ///
    /// ## Computing the Constant
    ///
    /// Applying the theorem above,
    /// `100 <= (1 << log_block_size) * MIN_LCS_FOR_BLOCKHASH`
    /// is equivalent to
    /// `(100 + MIN_LCS_FOR_BLOCKHASH - 1) / MIN_LCS_FOR_BLOCKHASH <= (1 << log_block_size)`.
    ///
    /// This leads to the expression to define this constant.
    pub const LOG_BLOCK_SIZE_CAPPING_BORDER: u8 =
        ((100 + Self::MIN_LCS_FOR_BLOCKHASH as u64 - 1) / Self::MIN_LCS_FOR_BLOCKHASH as u64)
        .next_power_of_two().trailing_zeros() as u8;

    /// Creates a new [`FuzzyHashCompareTarget`] object with empty contents.
    ///
    /// This is equivalent to the fuzzy hash string `3::`.
    #[inline]
    pub fn new() -> Self {
        FuzzyHashCompareTarget {
            blockhash1: BlockHashPositionArray::new(),
            blockhash2: BlockHashPositionArray::new(),
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
        BlockSize::from_log_unchecked(self.log_blocksize)
    }

    /// Initialize the object from a given fuzzy hash
    /// (without clearing the position arrays).
    ///
    /// This method is intended to be used just after clearing the position
    /// arrays (i.e. just after the initialization).
    #[inline]
    fn init_from_partial<const S1: usize, const S2: usize>(
        &mut self,
        hash: impl AsRef<FuzzyHashData<S1, S2, true>>
    )
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let hash = hash.as_ref();
        debug_assert!((hash.len_blockhash1 as usize) <= S1);
        debug_assert!((hash.len_blockhash2 as usize) <= S2);
        debug_assert!(BlockSize::is_log_valid(hash.log_blocksize));
        self.len_blockhash1 = hash.len_blockhash1;
        self.len_blockhash2 = hash.len_blockhash2;
        self.log_blocksize = hash.log_blocksize;
        // Initialize position arrays based on the original block hashes
        self.blockhash1.init_from_partial(hash.block_hash_1());
        self.blockhash2.init_from_partial(hash.block_hash_2());
    }

    /// Initialize the object from a given fuzzy hash.
    #[inline]
    pub fn init_from<const S1: usize, const S2: usize>(
        &mut self,
        hash: impl AsRef<FuzzyHashData<S1, S2, true>>
    )
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.blockhash1.clear();
        self.blockhash2.clear();
        self.init_from_partial(hash);
    }

    /// Compare whether two fuzzy hashes are equivalent
    /// (except for their block size).
    #[inline]
    fn is_equiv_except_block_size<const S1: usize, const S2: usize>(
        &self,
        hash: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> bool
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let hash = hash.as_ref();
        self.blockhash1.is_equiv_internal(self.len_blockhash1, hash.block_hash_1()) &&
        self.blockhash2.is_equiv_internal(self.len_blockhash2, hash.block_hash_2())
    }

    /// Compare whether two fuzzy hashes are equivalent.
    #[inline(always)]
    pub fn is_equiv<const S1: usize, const S2: usize>(
        &self,
        hash: impl AsRef<FuzzyHashData<S1, S2, true>>
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

    /// The internal implementation of [`Self::score_cap_on_block_hash_comparison_unchecked`].
    #[inline(always)]
    pub(crate) fn score_cap_on_block_hash_comparison_internal(
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
    /// lengths, assuming that block size is small enough so that an arithmetic
    /// overflow will not occur.
    ///
    /// # Safety
    ///
    /// If `log_block_size` is equal to or larger than
    /// [`FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER`](Self::LOG_BLOCK_SIZE_CAPPING_BORDER),
    /// and/or both lengths are too large, it may cause an
    /// arithmetic overflow and return an useless value.
    #[cfg(feature = "unsafe")]
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
    #[inline(always)]
    pub fn score_cap_on_block_hash_comparison(
        log_block_size: u8,
        len_block_hash_lhs: u8,
        len_block_hash_rhs: u8
    ) -> u32
    {
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
        BlockSize::is_log_valid(self.log_blocksize)
            && self.blockhash1.is_valid(self.len_blockhash1)
            && self.blockhash2.is_valid(self.len_blockhash2)
    }

    /// The internal implementation of [`Self::compare_unequal_near_eq_unchecked`].
    #[inline]
    fn compare_unequal_near_eq_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(!self.is_equiv(other));
        debug_assert!(BlockSize::is_near_eq(self.log_blocksize, other.log_blocksize));
        u32::max(
            self.blockhash1.score_strings_internal(
                self.len_blockhash1,
                other.block_hash_1(),
                self.log_blocksize
            ),
            self.blockhash2.score_strings_internal(
                self.len_blockhash2,
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
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_eq_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_near_eq_internal(other)
    }

    /// **SLOW:** Compare two fuzzy hashes assuming both are different and
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
    /// *   [`compare_near_eq`](Self::compare_near_eq) (safe Rust)
    /// *   [`compare_unequal_near_eq_unchecked`](Self::compare_unequal_near_eq_unchecked)
    ///     (unsafe Rust)
    #[inline(always)]
    pub fn compare_unequal_near_eq<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(!self.is_equiv(other));
        assert!(BlockSize::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_eq_internal(other)
    }

    /// The internal implementation of [`Self::compare_near_eq_unchecked`].
    #[inline]
    fn compare_near_eq_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(BlockSize::is_near_eq(self.log_blocksize, other.log_blocksize));
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
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_near_eq_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
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
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(BlockSize::is_near_eq(self.log_blocksize, other.log_blocksize));
        self.compare_near_eq_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_near_lt_unchecked`].
    #[inline(always)]
    fn compare_unequal_near_lt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(BlockSize::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.blockhash2.score_strings_internal(
            self.len_blockhash2,
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
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_lt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
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
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(BlockSize::is_near_lt(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_lt_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_near_gt_unchecked`].
    #[inline(always)]
    fn compare_unequal_near_gt_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(BlockSize::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.blockhash1.score_strings_internal(
            self.len_blockhash1,
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
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_unequal_near_gt_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
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
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        assert!(BlockSize::is_near_gt(self.log_blocksize, other.log_blocksize));
        self.compare_unequal_near_gt_internal(other)
    }

    /// The internal implementation of [`Self::compare_unequal_unchecked`].
    #[inline]
    pub(crate) fn compare_unequal_internal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        debug_assert!(!self.is_equiv(other));
        match BlockSize::compare_sizes(self.log_blocksize, other.log_blocksize) {
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
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_unequal_unchecked<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        self.compare_unequal_internal(other)
    }

    /// **SLOW:** Compare two normalized fuzzy hashes assuming
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
    /// *   [`compare`](Self::compare) (safe Rust)
    /// *   [`compare_unequal_unchecked`](Self::compare_unequal_unchecked)
    ///     (unsafe Rust)
    #[inline(always)]
    pub fn compare_unequal<const S1: usize, const S2: usize>(
        &self,
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
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
        other: impl AsRef<FuzzyHashData<S1, S2, true>>
    ) -> u32
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
    {
        let other = other.as_ref();
        match BlockSize::compare_sizes(self.log_blocksize, other.log_blocksize) {
            BlockSizeRelation::Far => 0,
            BlockSizeRelation::NearEq => self.compare_near_eq_internal(other),
            BlockSizeRelation::NearLt => self.compare_unequal_near_lt_internal(other),
            BlockSizeRelation::NearGt => self.compare_unequal_near_gt_internal(other),
        }
    }
}

impl<const S1: usize, const S2: usize>
    core::convert::From<FuzzyHashData<S1, S2, true>> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[allow(clippy::needless_borrow)]
    #[inline]
    fn from(value: FuzzyHashData<S1, S2, true>) -> Self {
        let mut dest: Self = Self::new();
        dest.init_from_partial(&value);
        dest
    }
}

impl<const S1: usize, const S2: usize>
    core::convert::From<&FuzzyHashData<S1, S2, true>> for FuzzyHashCompareTarget
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    #[inline]
    fn from(value: &FuzzyHashData<S1, S2, true>) -> Self {
        let mut dest: Self = Self::new();
        dest.init_from_partial(value);
        dest
    }
}


/// Additional implementation for normalized fuzzy hashes,
/// enabling comparison between two fuzzy hashes directly.
impl<const S1: usize, const S2: usize> FuzzyHashData<S1, S2, true>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes
{
    /// Compare two fuzzy hashes and retrieves the similarity score.
    #[inline]
    pub fn compare(&self, other: impl AsRef<Self>) -> u32 {
        let target = FuzzyHashCompareTarget::from(self);
        target.compare(other.as_ref())
    }

    /// The internal implementation of [`Self::compare_unequal_unchecked`].
    #[inline]
    pub(crate) fn compare_unequal_internal(&self, other: impl AsRef<Self>) -> u32 {
        let other = other.as_ref();
        debug_assert!(self != other);
        let target = FuzzyHashCompareTarget::from(self);
        target.compare_unequal_internal(other)
    }

    /// Compare two fuzzy hashes assuming both are different.
    ///
    /// # Safety
    ///
    /// *   `self` and `other` must be different.
    ///
    /// If the condition above is not satisfied, it will return
    /// a meaningless score.
    #[cfg(feature = "unsafe")]
    #[inline(always)]
    pub unsafe fn compare_unequal_unchecked(&self, other: impl AsRef<Self>) -> u32 {
        self.compare_unequal_internal(other)
    }

    /// **SLOW:** Compare two fuzzy hashes assuming both are different.
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
    /// *   [`compare`](Self::compare) (safe Rust)
    /// *   [`compare_unequal_unchecked`](Self::compare_unequal_unchecked)
    ///     (unsafe Rust)
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
        (100 + FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH as u64 - 1) /
            FuzzyHashCompareTarget::MIN_LCS_FOR_BLOCKHASH as u64
                <= BlockSize::from_log_unchecked(log_block_size) as u64 / BlockSize::MIN as u64
    }

    // Prerequisite for 64-bit position array
    // grcov-excl-br-start
    #[cfg(test)]
    #[test]
    fn test_position_array_fits_in_64_bits() {
        assert!(
            u32::try_from(BlockHash::FULL_SIZE)
                .and_then(|x| Ok(x <= u64::BITS))
                .unwrap_or(false)
        );
    }
    // grcov-excl-br-end

    // Prerequisite for 64-bit position array
    const_assert!(BlockHash::FULL_SIZE <= 64);

    // Compare with the precomputed value
    // (block_size / BlockSize::MIN >= 15, log_block_size >= 4 [2^log_block_size >= 16])
    const_assert_eq!(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER, 4);

    // Regular tests.
    const_assert!(BlockSize::is_log_valid(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));
    const_assert!(!is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER - 1));
    const_assert!( is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));

    // Regular tests (dynamic)
    #[cfg(test)]
    #[test]
    fn test_log_block_size_capping_border() {
        assert!(!is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER - 1));
        assert!( is_log_block_size_needs_no_capping(FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER));
    }
}
