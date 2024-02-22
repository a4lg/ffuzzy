// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;

use crate::base64::BASE64_TABLE_U8;
use crate::hash::{FuzzyHashData, fuzzy_norm_type, fuzzy_raw_type};
use crate::hash::block::{
    block_size, block_hash,
    BlockHashSize, ConstrainedBlockHashSize,
    BlockHashSizes, ConstrainedBlockHashSizes
};
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin,
    BlockHashParseState
};
use crate::intrinsics::unlikely;
use crate::macros::{optionally_unsafe, invariant};


#[cfg(test)]
mod tests;


/// An RLE Encoding as used in [`FuzzyHashDualData`].
///
/// # Compression Scheme
///
/// See: ["Bit Fields" section](Self#bit-fields) below for detailed encoding.
///
/// Suppose that we have a block hash `ABCCCCCCDDDDDDDDDDDD`
/// (`A`, `B` and then 6 `C`s and 12 `D`s).
///
/// We also have a normalized block hash.
///
/// ```text
/// Raw:        ABCCCCCCDDDDDDDDDDDD
/// Normalized: ABCCCDDD
/// ```
///
/// To reconstruct the raw block hash, we store "where and how many
/// characters to repeat".  That's the idea of classic run-length encoding.
///
/// ```text
/// ABCCC...
///     |
///     +--Repeat 3 more times: RLE(pos=4, len=3)
///
/// -> ABCCCCCC...
///         ^^^
/// ```
///
/// The `pos` field is that of the normalized block hash and the *last
/// character* of the consecutive characters (to prohibit redundant encodings
/// and to reserve position `0` for [the terminator](rle_encoding::TERMINATOR)).
///
/// Due to the limitation of the bit field encoding, we can only repeat
/// up to 4 characters by one RLE encoding.  On such cases, we use multiple RLE
/// encodings with the same `pos` field:
///
/// ```text
///     +--Repeat 3 more times: RLE(pos=4, len=3)
///     |
/// ABCCCDDD
///        |
///        +-- Repeat 9 more times:
///               RLE(pos=7, len=4)
///               RLE(pos=7, len=4)
///               RLE(pos=7, len=1)
///
/// -> ABCCCCCCDDDDDDDDDDDD
///         ^^^   ^^^^----^
/// ```
///
/// For reasons below, lengths larger than 4 are encoded by consecutive 4s and
/// a remainder.  So, `9` is encoded as `4+4+1`, not `1+4+4`, `3+3+3`
/// or `2+2+2+2+1`:
///
/// *   To avoid issues regarding redundant encodings,
/// *   To make sure that plain memory comparison is sufficient
///     to check equivalence and
/// *   To maximize the compression rate.
///
/// # Bit Fields
///
/// Current design of the RLE block is basic and compact RLE encoded bytes
/// each consisting of following bitfields:
///
/// *   6 bits of offset (`pos`)
/// *   2 bits of length (`len`)
///
/// 6 bits is enough to store any block hash offset.
///
/// This `pos` is the one of a normalized block hash (and must be the last
/// character offset of the sequence).
///
/// Because [`block_hash::MAX_SEQUENCE_SIZE`] is larger than `1`, we can use the
/// offset zero as the terminator (if the offset is zero, the length must be
/// encoded as zero, making the RLE block
/// [zero-terminated](rle_encoding::TERMINATOR)).
///
/// 2 bits of length is enough to compress
/// [`block_hash::MAX_SEQUENCE_SIZE`]` + 1` bytes into one RLE encoding, making
/// the long sequence able to be compressed in a fixed-size RLE block.
///
/// The encoded length is one less than the actual length for efficiency.
/// For instance, encoded `len` of `0` actually means repeating a character
/// once (`1` time) to reverse normalization.  Likewise, encoded `1` means
/// repeating a character twice (`2` times).
///
/// 2 bits of length is still small.  If we need to extend a character 5
/// (`4 + 1`) times or more, we need multiple RLE encodings (with the same
/// `pos` field).
mod rle_encoding {
    /// Bits used to represent the position (offset).
    ///
    /// This is the start offset to repeat the same character.
    ///
    /// If this field is zero, all succeeding encodings are
    /// not meant to be used.
    pub const BITS_POSITION: u32 = 6;

    /// Mask used to represent the position (offset).
    pub const MASK_POSITION: u8 = (1u8 << BITS_POSITION) - 1;

    /// Bits used to represent the run length.
    ///
    /// If this RLE encoding is valid, high bits are used to represent
    /// `len + 1` because we don't encode zero length.
    pub const BITS_RUN_LENGTH: u32 = 2;

    /// Maximum run length for the RLE encoding.
    pub const MAX_RUN_LENGTH: usize = 1usize << BITS_RUN_LENGTH;

    /// The terminator symbol.
    ///
    /// A valid RLE block must be terminated by this symbol (and filled
    /// thereafter).  It can be detected as `pos == 0` after decoding.
    pub const TERMINATOR: u8 = 0;

    /// Constant assertions related to RLE encoding prerequisites.
    #[doc(hidden)]
    #[allow(clippy::int_plus_one)]
    mod const_asserts {
        use super::*;
        use static_assertions::{const_assert, const_assert_eq, const_assert_ne};
        use crate::hash::block::block_hash;

        // Basic Constraints
        const_assert_ne!(BITS_POSITION, 0);
        const_assert_ne!(BITS_RUN_LENGTH, 0);
        const_assert_eq!(BITS_POSITION + BITS_RUN_LENGTH, u8::BITS);

        // To use `offset` of zero can be used as the terminator,
        // MAX_SEQUENCE_SIZE must be larger than 1 (must be at least 2).
        const_assert!(block_hash::MAX_SEQUENCE_SIZE >= 2);

        // Offset can contain any block hash index
        const_assert!(block_hash::FULL_SIZE <= (1usize << BITS_POSITION));
        // Length is large enough to compress MAX_SEQUENCE_SIZE + 1 bytes.
        const_assert!(block_hash::MAX_SEQUENCE_SIZE + 1 <= MAX_RUN_LENGTH);
    }

    /// Encode an RLE encoding from a (position, length) pair.
    #[inline(always)]
    pub(crate) fn encode(pos: u8, len: u8) -> u8 {
        debug_assert!(len != 0);
        debug_assert!(len <= MAX_RUN_LENGTH as u8);
        debug_assert!(pos != 0);
        debug_assert!(pos <= MASK_POSITION);
        pos | ((len - 1) << BITS_POSITION)
    }

    /// Decode an RLE encoding into a (position, length) pair.
    #[inline(always)]
    pub(crate) fn decode(value: u8) -> (u8, u8) {
        (value & MASK_POSITION, (value >> BITS_POSITION) + 1)
    }

    #[cfg(test)]
    #[test]
    fn decode_terminator() {
        let (pos, _) = decode(TERMINATOR);
        assert_eq!(pos, 0);
    }
}


/// A generic type to constrain given block hash size using [`ConstrainedBlockHashSize`].
///
/// # Unstable Type
///
/// Despite that this type is public, it is strongly discouraged to use this
/// type because it exposes a part of opaque "reverse normalization" data and
/// the only reason this type is public is due to restrictions of Rust's
/// current constant generics.
///
/// This type should not be considered stable.
pub struct ReconstructionBlockSize<const SZ_BH: usize, const SZ_R: usize> {}

mod private {
    use super::*;
    use crate::hash::block::block_hash;

    /// A trait to constrain RLE block size for given block hash size.
    ///
    /// This type is implemented for [`ReconstructionBlockSize`]
    /// with following block hash sizes:
    ///
    /// *   [`block_hash::FULL_SIZE`]
    /// *   [`block_hash::HALF_SIZE`]
    ///
    /// This is a sealed trait.
    pub trait SealedReconstructionBlockSize {}

    /// Template to generate RLE block size constraints
    /// including constant assertions.
    macro_rules! rle_size_for_block_hash_template {
        { $(sizes_def($block_hash_size: expr, $rle_size: expr);)* } => {
            $(impl SealedReconstructionBlockSize for ReconstructionBlockSize<{$block_hash_size}, {$rle_size}> {})*

            /// Constant assertions related to RLE block size requirements.
            #[doc(hidden)]
            mod const_asserts {
                use super::*;
                use static_assertions::const_assert;

                // grcov-excl-br-start
                // Consider removing it once MSRV of 1.73 is acceptable.
                #[cfg_attr(feature = "nightly", coverage(off))]
                #[allow(dead_code)]
                const fn div_ceil(a: usize, b: usize) -> usize {
                    cfg_if::cfg_if! {
                        if #[cfg(ffuzzy_div_ceil = "fallback")] {
                            a / b + (if a % b == 0 { 0 } else { 1 })
                        }
                        else {
                            usize::div_ceil(a, b)
                        }
                    }
                }

                #[cfg(test)]
                #[test]
                fn div_ceil_examples() {
                    assert_eq!(div_ceil(0, 1), 0);
                    assert_eq!(div_ceil(1, 1), 1);
                    assert_eq!(div_ceil(2, 1), 2);
                    assert_eq!(div_ceil(3, 1), 3);
                    assert_eq!(div_ceil(4, 1), 4);
                    assert_eq!(div_ceil(5, 1), 5);
                    assert_eq!(div_ceil(6, 1), 6);
                    assert_eq!(div_ceil(7, 1), 7);
                    assert_eq!(div_ceil(8, 1), 8);
                    assert_eq!(div_ceil(0, 2), 0);
                    assert_eq!(div_ceil(1, 2), 1);
                    assert_eq!(div_ceil(2, 2), 1);
                    assert_eq!(div_ceil(3, 2), 2);
                    assert_eq!(div_ceil(4, 2), 2);
                    assert_eq!(div_ceil(5, 2), 3);
                    assert_eq!(div_ceil(6, 2), 3);
                    assert_eq!(div_ceil(7, 2), 4);
                    assert_eq!(div_ceil(8, 2), 4);
                    assert_eq!(div_ceil(0, 3), 0);
                    assert_eq!(div_ceil(1, 3), 1);
                    assert_eq!(div_ceil(2, 3), 1);
                    assert_eq!(div_ceil(3, 3), 1);
                    assert_eq!(div_ceil(4, 3), 2);
                    assert_eq!(div_ceil(5, 3), 2);
                    assert_eq!(div_ceil(6, 3), 2);
                    assert_eq!(div_ceil(7, 3), 3);
                    assert_eq!(div_ceil(8, 3), 3);
                    assert_eq!(div_ceil(0, 4), 0);
                    assert_eq!(div_ceil(1, 4), 1);
                    assert_eq!(div_ceil(2, 4), 1);
                    assert_eq!(div_ceil(3, 4), 1);
                    assert_eq!(div_ceil(4, 4), 1);
                    assert_eq!(div_ceil(5, 4), 2);
                    assert_eq!(div_ceil(6, 4), 2);
                    assert_eq!(div_ceil(7, 4), 2);
                    assert_eq!(div_ceil(8, 4), 2);
                }
                // grcov-excl-br-stop

                // Test each RLE block sizes
                $(
                    // This lower bound is exact.
                    const_assert!(
                        div_ceil($block_hash_size, block_hash::MAX_SEQUENCE_SIZE + 1) <= $rle_size
                    );
                    // This lower bound might be too pessimistic.
                    const_assert!(
                        div_ceil($block_hash_size, rle_encoding::MAX_RUN_LENGTH) <= $rle_size
                    );
                )*
            }
        };
    }

    rle_size_for_block_hash_template! {
        sizes_def(block_hash::FULL_SIZE, block_hash::FULL_SIZE / 4);
        sizes_def(block_hash::HALF_SIZE, block_hash::HALF_SIZE / 4);
    }
}

/// A trait to constrain RLE block size for given block hash size.
///
/// This type is implemented for [`ReconstructionBlockSize`] with
/// following block hash sizes:
///
/// *   [`block_hash::FULL_SIZE`]
/// *   [`block_hash::HALF_SIZE`]
///
/// Note that this trait is intentionally designed to be non-extensible
/// (using the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html)).
///
/// # Unstable Trait
///
/// Despite that this trait is public, it is strongly discouraged to use this
/// trait because it exposes a part of opaque "reverse normalization" data and
/// the only reason this trait is public is due to restrictions of Rust's
/// current constant generics.
///
/// This trait should not be considered stable.
pub trait ConstrainedReconstructionBlockSize: private::SealedReconstructionBlockSize {}
impl<T> ConstrainedReconstructionBlockSize for T where T: private::SealedReconstructionBlockSize {}


mod algorithms {
    use super::*;

    /// Update the RLE block to compressed given sequence.
    ///
    /// `pos` is of the last consecutive character in the sequence and
    /// `len` is the raw sequence length.
    ///
    /// It returns new `rle_offset` to use.
    #[inline(always)]
    pub(crate) fn update_rle_block<const SZ_RLE: usize>(
        rle_block: &mut [u8; SZ_RLE],
        rle_offset: usize,
        pos: usize,
        len: usize
    ) -> usize {
        debug_assert!(len > block_hash::MAX_SEQUENCE_SIZE);
        optionally_unsafe! {
            let extend_len_minus_one = len - block_hash::MAX_SEQUENCE_SIZE - 1;
            let seq_fill_size = extend_len_minus_one / rle_encoding::MAX_RUN_LENGTH;
            let start = rle_offset;
            invariant!(start <= rle_block.len());
            invariant!(start + seq_fill_size <= rle_block.len());
            invariant!(start <= start + seq_fill_size);
            rle_block[start..start + seq_fill_size]
                .fill(rle_encoding::encode(pos as u8, rle_encoding::MAX_RUN_LENGTH as u8)); // grcov-excl-br-line:ARRAY
            invariant!(start + seq_fill_size < rle_block.len());
            rle_block[start + seq_fill_size] = rle_encoding::encode(
                pos as u8,
                (extend_len_minus_one % rle_encoding::MAX_RUN_LENGTH) as u8 + 1
            ); // grcov-excl-br-line:ARRAY
            start + seq_fill_size + 1
        }
    }

    /// Compress a raw block hash with normalizing and generating RLE encodings.
    ///
    /// Note that, the length of `blockhash_in` must not exceed the maximum
    /// length of `blockhash_out` (`SZ_BH`).
    #[inline]
    pub(crate) fn compress_block_hash_with_rle<const SZ_BH: usize, const SZ_RLE: usize>(
        blockhash_out: &mut [u8; SZ_BH],
        rle_block_out: &mut [u8; SZ_RLE],
        blockhash_len_out: &mut u8,
        blockhash_in: &[u8]
    )
    where
        BlockHashSize<SZ_BH>: ConstrainedBlockHashSize,
        ReconstructionBlockSize<SZ_BH, SZ_RLE>: ConstrainedReconstructionBlockSize
    {
        debug_assert!(blockhash_in.len() <= SZ_BH);
        optionally_unsafe! {
            let mut rle_offset = 0;
            let mut seq = 0usize;
            let mut len = 0usize;
            let mut prev = crate::base64::BASE64_INVALID;
            for &curr in blockhash_in {
                if curr == prev {
                    seq += 1;
                    if seq >= block_hash::MAX_SEQUENCE_SIZE {
                        // Preserve sequence length for RLE encoding.
                        continue;
                    }
                }
                else {
                    if seq >= block_hash::MAX_SEQUENCE_SIZE {
                        rle_offset = update_rle_block(rle_block_out, rle_offset, len - 1, seq + 1);
                    }
                    seq = 0;
                    prev = curr;
                }
                invariant!(len < blockhash_out.len());
                blockhash_out[len] = curr; // grcov-excl-br-line:ARRAY
                len += 1;
            }
            // If we processed all original block hash, there's a case where
            // we are in an identical character sequence.
            if seq >= block_hash::MAX_SEQUENCE_SIZE {
                rle_offset = update_rle_block(rle_block_out, rle_offset, len - 1, seq + 1);
            }
            *blockhash_len_out = len as u8;
            invariant!(len <= blockhash_out.len());
            blockhash_out[len..].fill(0); // grcov-excl-br-line:ARRAY
            invariant!(rle_offset <= rle_block_out.len());
            rle_block_out[rle_offset..].fill(rle_encoding::TERMINATOR); // grcov-excl-br-line:ARRAY
        }
    }

    /// Expand a normalized block hash to a raw form using RLE encodings.
    #[inline]
    pub(crate) fn expand_block_hash_using_rle<const SZ_BH: usize, const SZ_RLE: usize>(
        blockhash_out: &mut [u8; SZ_BH],
        blockhash_len_out: &mut u8,
        blockhash_in: &[u8; SZ_BH],
        blockhash_len_in: u8,
        rle_block_in: &[u8; SZ_RLE]
    )
    where
        BlockHashSize<SZ_BH>: ConstrainedBlockHashSize,
        ReconstructionBlockSize<SZ_BH, SZ_RLE>: ConstrainedReconstructionBlockSize
    {
        optionally_unsafe! {
            let mut offset_src = 0usize;
            let mut offset_dst = 0usize;
            let mut len_out = blockhash_len_in;
            let copy_as_is = |blockhash_out: &mut [u8; SZ_BH], dst, src, len| {
                invariant!(src <= blockhash_in.len());
                invariant!(src + len <= blockhash_in.len());
                invariant!(src <= src + len);
                invariant!(dst <= blockhash_out.len());
                invariant!(dst + len <= blockhash_out.len());
                invariant!(dst <= dst + len);
                blockhash_out[dst..dst+len].clone_from_slice(&blockhash_in[src..src+len]); // grcov-excl-br-line:ARRAY
            };
            for rle in rle_block_in {
                // Decode position and length
                let (pos, len) = rle_encoding::decode(*rle);
                if pos == 0 {
                    // Met the terminator
                    debug_assert!(*rle == rle_encoding::TERMINATOR);
                    break;
                }
                let pos = pos as usize;
                len_out += len;
                let len = len as usize;
                // Copy as is
                let copy_len = pos - offset_src;
                copy_as_is(blockhash_out, offset_dst, offset_src, copy_len);
                // Copy with duplication
                invariant!(pos < blockhash_in.len());
                let lastch = blockhash_in[pos]; // grcov-excl-br-line:ARRAY
                invariant!(offset_dst + copy_len <= blockhash_out.len());
                invariant!(offset_dst + copy_len + len <= blockhash_out.len());
                invariant!(offset_dst + copy_len <= offset_dst + copy_len + len);
                blockhash_out[offset_dst+copy_len..offset_dst+copy_len+len].fill(lastch); // grcov-excl-br-line:ARRAY
                // Update next offset
                offset_src += copy_len;
                offset_dst += copy_len + len;
            }
            // Copy as is (tail)
            let copy_len = len_out as usize - offset_dst;
            copy_as_is(blockhash_out, offset_dst, offset_src, copy_len);
            // Finalize
            invariant!(offset_dst + copy_len <= blockhash_out.len());
            blockhash_out[offset_dst+copy_len..].fill(0); // grcov-excl-br-line:ARRAY
            *blockhash_len_out = len_out;
        }
    }

    /// Expand a normalized block hash to a raw form using RLE encodings.
    pub(crate) fn is_valid_rle_block_for_block_hash<const SZ_BH: usize, const SZ_RLE: usize>(
        blockhash: &[u8; SZ_BH],
        rle_block: &[u8; SZ_RLE],
        blockhash_len: u8
    ) -> bool
    where
        BlockHashSize<SZ_BH>: ConstrainedBlockHashSize,
        ReconstructionBlockSize<SZ_BH, SZ_RLE>: ConstrainedReconstructionBlockSize
    {
        let mut expanded_len = blockhash_len as u32;
        let mut terminator_expected = false;
        let mut prev_pos = 0u8;
        let mut prev_len = 0u8;
        for rle in rle_block {
            if unlikely(*rle != rle_encoding::TERMINATOR && terminator_expected) {
                // Non-zero byte after null-terminated encoding.
                return false;
            }
            if *rle == rle_encoding::TERMINATOR {
                // Null terminator or later.
                terminator_expected = true;
                continue;
            }
            // Decode position and length
            let (pos, len) = rle_encoding::decode(*rle);
            // Check position
            if unlikely(
                pos < block_hash::MAX_SEQUENCE_SIZE as u8 - 1 || pos >= blockhash_len || pos < prev_pos
            ) {
                return false;
            }
            if prev_pos == pos {
                // For extension with the same position, check canonicality.
                if unlikely(prev_len != rle_encoding::MAX_RUN_LENGTH as u8) {
                    return false;
                }
            }
            else {
                // For new sequence, check if corresponding block hash makes
                // identical character sequence.
                let end = pos as usize;
                let start = end - (block_hash::MAX_SEQUENCE_SIZE - 1);
                optionally_unsafe! {
                    invariant!(start < blockhash.len());
                    invariant!(end < blockhash.len());
                    #[allow(clippy::int_plus_one)]
                    {
                        invariant!(start + 1 <= end);
                    }
                }
                let ch = blockhash[start]; // grcov-excl-br-line:ARRAY
                if unlikely(
                    blockhash[start+1..=end] // grcov-excl-br-line:ARRAY
                        .iter().any(|x| *x != ch)
                )
                {
                    return false;
                }
            }
            // Update the state.
            prev_pos = pos;
            prev_len = len;
            expanded_len += len as u32;
        }
        if unlikely(expanded_len as usize > SZ_BH) {
            return false;
        }
        true
    }
}


/// An efficient compressed fuzzy hash representation, containing both
/// normalized and raw block hash contents.
///
/// This struct contains a normalized [fuzzy hash object](FuzzyHashData) and
/// opaque data to perform "reverse normalization" afterwards.
///
/// On the current design, it allows compression ratio of about 5 / 8
/// (compared to two fuzzy hash objects, one normalized and another raw).
///
/// With this, you can compare many fuzzy hashes efficiently while preserving
/// the original string representation without requesting too much memory.
///
/// Some methods accept [`AsRef`] to the normalized [`FuzzyHashData`].
/// On such cases, it is possible to pass this object directly
/// (e.g. [`FuzzyHashCompareTarget::compare()`](crate::compare::FuzzyHashCompareTarget::compare())).
///
/// # Ordering
///
/// Sorting objects of this type will result in the following order.
///
/// *   Two equivalent [`FuzzyHashDualData`] objects are considered equal
///     (and the underlying sorting algorithm decides ordering of equivalent
///     objects).
/// *   Two different [`FuzzyHashDualData`] objects with different normalized
///     [`FuzzyHashData`] objects (inside) will be ordered as the same order as
///     the underlying [`FuzzyHashData`].
/// *   Two different [`FuzzyHashDualData`] objects with the same normalized
///     [`FuzzyHashData`] objects (inside) will be ordered
///     in an implementation-defined manner.
///
/// The implementation-defined order is not currently guaranteed to be stable.
/// For instance, different versions of this crate may order them differently.
/// However, it is guaranteed deterministic so that you can expect the same
/// order in the same version of this crate.
///
/// # Safety
///
/// Generic parameters of this type should not be considered stable because some
/// generic parameters are just there because of the current restrictions of
/// Rust's constant generics (that will be resolved after the feature
/// `generic_const_exprs` is stabilized).
///
/// **Do not** use [`FuzzyHashDualData`] directly.
///
/// Instead, use instantiations of this generic type:
/// *   [`DualFuzzyHash`] (will be sufficient on most cases)
/// *   [`LongDualFuzzyHash`]
///
/// # Examples
///
/// ```
/// // Requires either the "alloc" feature or std environment on your crate
/// // to use the `to_string()` method (default enabled).
/// use ssdeep::{DualFuzzyHash, FuzzyHash, RawFuzzyHash};
///
/// let hash_str_raw  = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
/// let hash_str_norm = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccei:+Klhav84a5sxJ";
///
/// let dual_hash: DualFuzzyHash = str::parse(hash_str_raw).unwrap();
///
/// // This object can effectively contain both
/// // normalized and raw fuzzy hash representations.
/// assert_eq!(dual_hash.to_raw_form().to_string(),   hash_str_raw);
/// assert_eq!(dual_hash.to_normalized().to_string(), hash_str_norm);
///
/// let another_hash: FuzzyHash = str::parse(
///     "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK"
/// ).unwrap();
///
/// // You can directly compare a DualFuzzyHash against a FuzzyHash.
/// //
/// // This is almost as fast as comparison between two FuzzyHash objects
/// // because the native representation inside DualFuzzyHash
/// // is a FuzzyHash object.
/// assert_eq!(another_hash.compare(dual_hash), 88);
///
/// // But DualFuzzyHash is not a drop-in replacement of FuzzyHash.
/// // You need to use `as_normalized()` to compare a FuzzyHash against
/// // a DualFuzzyHash (direct comparison may be provided on the later version).
/// assert_eq!(dual_hash.as_normalized().compare(&another_hash), 88);
/// ```
#[repr(align(8))]
#[derive(Copy, Clone)]
pub struct FuzzyHashDualData<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    /// RLE block 1 for reverse normalization of
    /// [block hash 1](crate::hash::FuzzyHashData::blockhash1).
    ///
    /// See [`rle_encoding`] for encoding details and full compression scheme.
    rle_block1: [u8; C1],

    /// RLE block 2 for reverse normalization of
    /// [block hash 2](crate::hash::FuzzyHashData::blockhash2).
    ///
    /// See [`rle_encoding`] for encoding details and full compression scheme.
    rle_block2: [u8; C2],

    /// A normalized fuzzy hash object for comparison and the base storage
    /// before RLE-based decompression.
    norm_hash: fuzzy_norm_type!(S1, S2)
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize> FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    /// The maximum size of the block hash 1.
    ///
    /// This value is the same as the
    /// [underlying fuzzy hash type](FuzzyHashData::MAX_BLOCK_HASH_SIZE_1).
    pub const MAX_BLOCK_HASH_SIZE_1: usize = <fuzzy_norm_type!(S1, S2)>::MAX_BLOCK_HASH_SIZE_1;

    /// The maximum size of the block hash 2.
    ///
    /// This value is the same as the
    /// [underlying fuzzy hash type](FuzzyHashData::MAX_BLOCK_HASH_SIZE_2).
    pub const MAX_BLOCK_HASH_SIZE_2: usize = <fuzzy_norm_type!(S1, S2)>::MAX_BLOCK_HASH_SIZE_2;

    /// The number of RLE block entries in the block hash 1.
    #[allow(dead_code)]
    const RLE_BLOCK_SIZE_1: usize = C1;

    /// The number of RLE block entries in the block hash 2.
    #[allow(dead_code)]
    const RLE_BLOCK_SIZE_2: usize = C2;

    /// Denotes whether the fuzzy type only contains a normalized form.
    ///
    /// In this type, it is always [`false`].
    pub const IS_NORMALIZED_FORM: bool = false;

    /// Denotes whether the fuzzy type can contain a non-truncated fuzzy hash.
    ///
    /// This value is the same as the
    /// [underlying fuzzy hash type](FuzzyHashData::IS_LONG_FORM).
    pub const IS_LONG_FORM: bool = <fuzzy_norm_type!(S1, S2)>::IS_LONG_FORM;

    /// The maximum length in the string representation.
    ///
    /// This value is the same as the
    /// [underlying fuzzy hash type](FuzzyHashData::MAX_LEN_IN_STR).
    pub const MAX_LEN_IN_STR: usize = <fuzzy_norm_type!(S1, S2)>::MAX_LEN_IN_STR;

    /// Creates a new fuzzy hash object with empty contents.
    ///
    /// This is equivalent to the fuzzy hash string `3::`.
    pub fn new() -> Self {
        Self {
            rle_block1: [rle_encoding::TERMINATOR; C1],
            rle_block2: [rle_encoding::TERMINATOR; C2],
            norm_hash: FuzzyHashData::new()
        }
    }

    /// Initialize the object from a raw fuzzy hash.
    pub fn init_from_raw_form(&mut self, hash: &fuzzy_raw_type!(S1, S2)) {
        self.norm_hash.log_blocksize = hash.log_blocksize;
        algorithms::compress_block_hash_with_rle(
            &mut self.norm_hash.blockhash1,
            &mut self.rle_block1,
            &mut self.norm_hash.len_blockhash1,
            hash.block_hash_1()
        );
        algorithms::compress_block_hash_with_rle(
            &mut self.norm_hash.blockhash2,
            &mut self.rle_block2,
            &mut self.norm_hash.len_blockhash2,
            hash.block_hash_2()
        );
    }

    /// The internal implementation of [`Self::new_from_internals_near_raw_unchecked()`].
    fn new_from_internals_near_raw_internal(
        log_block_size: u8,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        debug_assert!(block_size::is_log_valid(log_block_size));
        debug_assert!(block_hash_1.iter().all(|&x| x < block_hash::ALPHABET_SIZE as u8));
        debug_assert!(block_hash_2.iter().all(|&x| x < block_hash::ALPHABET_SIZE as u8));
        optionally_unsafe! {
            invariant!(block_hash_1.len() <= S1);
            invariant!(block_hash_2.len() <= S2);
        }
        let mut hash = Self::new();
        hash.norm_hash.log_blocksize = log_block_size;
        algorithms::compress_block_hash_with_rle(
            &mut hash.norm_hash.blockhash1,
            &mut hash.rle_block1,
            &mut hash.norm_hash.len_blockhash1,
            block_hash_1
        );
        algorithms::compress_block_hash_with_rle(
            &mut hash.norm_hash.blockhash2,
            &mut hash.rle_block2,
            &mut hash.norm_hash.len_blockhash2,
            block_hash_2
        );
        hash
    }

    /// Creates a new fuzzy hash object with internal contents (with raw block size).
    ///
    /// # Safety
    ///
    /// *   `block_hash_1` and `block_hash_2` must have valid lengths.
    /// *   Elements of `block_hash_1` and `block_hash_2` must consist of valid
    ///     Base64 indices.
    /// *   `log_block_size` must hold a valid
    ///     *base-2 logarithm* form of a block size.
    ///
    /// If they are not satisfied, the resulting object will be corrupted.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
    #[inline(always)]
    pub unsafe fn new_from_internals_near_raw_unchecked(
        log_block_size: u8,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        Self::new_from_internals_near_raw_internal(log_block_size, block_hash_1, block_hash_2)
    }

    /// Creates a new fuzzy hash object with internal contents (with raw block size).
    ///
    /// Because this function assumes that you know the fuzzy hash internals,
    /// it panics when you fail to satisfy fuzzy hash constraints.
    ///
    /// # Usage Constraints
    ///
    /// *   `block_hash_1` and `block_hash_2` must have valid lengths.
    /// *   Elements of `block_hash_1` and `block_hash_2` must consist of valid
    ///     Base64 indices.
    /// *   `log_block_size` must hold a valid
    ///     *base-2 logarithm* form of a block size.
    #[inline]
    pub fn new_from_internals_near_raw(
        log_block_size: u8,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        assert!(block_size::is_log_valid(log_block_size));
        assert!(block_hash_1.len() <= S1);
        assert!(block_hash_2.len() <= S2);
        assert!(block_hash_1.iter().all(|&x| x < block_hash::ALPHABET_SIZE as u8));
        assert!(block_hash_2.iter().all(|&x| x < block_hash::ALPHABET_SIZE as u8));
        Self::new_from_internals_near_raw_internal(
            log_block_size,
            block_hash_1,
            block_hash_2
        )
    }

    /// The internal implementation of [`Self::new_from_internals_unchecked()`].
    #[allow(dead_code)]
    #[inline(always)]
    fn new_from_internals_internal(
        block_size: u32,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        debug_assert!(block_size::is_valid(block_size));
        Self::new_from_internals_near_raw_internal(
            block_size::log_from_valid_internal(block_size),
            block_hash_1, block_hash_2
        )
    }

    /// Creates a new fuzzy hash object with internal contents.
    ///
    /// # Safety
    ///
    /// *   `block_hash_1` and `block_hash_2` must have valid lengths.
    /// *   Elements of `block_hash_1` and `block_hash_2` must consist of valid
    ///     Base64 indices.
    /// *   `block_size` must hold a valid block size.
    ///
    /// If they are not satisfied, the resulting object will be corrupted.
    #[cfg(feature = "unchecked")]
    #[allow(unsafe_code)]
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
    #[inline]
    pub fn new_from_internals(
        block_size: u32,
        block_hash_1: &[u8],
        block_hash_2: &[u8]
    ) -> Self
    {
        assert!(block_size::is_valid(block_size));
        Self::new_from_internals_near_raw(
            block_size::log_from_valid_internal(block_size),
            block_hash_1, block_hash_2
        )
    }

    /// The *base-2 logarithm* form of the block size.
    ///
    /// See also: ["Block Size" section of `FuzzyHashData`](crate::hash::FuzzyHashData#block-size)
    #[inline(always)]
    pub fn log_block_size(&self) -> u8 { self.norm_hash.log_blocksize }

    /// The block size of the fuzzy hash.
    #[inline]
    pub fn block_size(&self) -> u32 {
        block_size::from_log_internal(self.norm_hash.log_blocksize)
    }

    /// A reference to the normalized fuzzy hash.
    ///
    /// To note, this operation should be fast enough because this type
    /// contains this object directly.
    #[inline(always)]
    pub fn as_normalized(&self) -> &fuzzy_norm_type!(S1, S2) {
        &self.norm_hash
    }

    /// Constructs an object from a raw fuzzy hash.
    pub fn from_raw_form(hash: &fuzzy_raw_type!(S1, S2)) -> Self {
        let mut dual_hash = FuzzyHashDualData::new();
        dual_hash.init_from_raw_form(hash);
        dual_hash
    }

    /// Constructs an object from a normalized fuzzy hash.
    pub fn from_normalized(hash: &fuzzy_norm_type!(S1, S2)) -> Self {
        Self {
            rle_block1: [rle_encoding::TERMINATOR; C1],
            rle_block2: [rle_encoding::TERMINATOR; C2],
            norm_hash: *hash
        }
    }

    /// Decompresses a raw variant of the fuzzy hash and stores into
    /// an existing object.
    pub fn into_mut_raw_form(&self, hash: &mut fuzzy_raw_type!(S1, S2)) {
        hash.log_blocksize = self.norm_hash.log_blocksize;
        algorithms::expand_block_hash_using_rle(
            &mut hash.blockhash1,
            &mut hash.len_blockhash1,
            &self.norm_hash.blockhash1,
            self.norm_hash.len_blockhash1,
            &self.rle_block1
        );
        algorithms::expand_block_hash_using_rle(
            &mut hash.blockhash2,
            &mut hash.len_blockhash2,
            &self.norm_hash.blockhash2,
            self.norm_hash.len_blockhash2,
            &self.rle_block2
        );
    }

    /// Decompresses and generates a raw variant of the fuzzy hash.
    ///
    /// Based on the normalized fuzzy hash representation and the "reverse
    /// normalization" data, this method generates the original, a raw variant
    /// of the fuzzy hash.
    pub fn to_raw_form(&self) -> fuzzy_raw_type!(S1, S2) {
        let mut hash = FuzzyHashData::new();
        self.into_mut_raw_form(&mut hash);
        hash
    }

    /// Returns the clone of the normalized fuzzy hash.
    ///
    /// Where possible, [`as_normalized()`](Self::as_normalized()) or
    /// [`AsRef::as_ref()`] should be used instead.
    #[inline(always)]
    pub fn to_normalized(&self) -> fuzzy_norm_type!(S1, S2) {
        self.norm_hash
    }

    /// Converts the fuzzy hash to the string (normalized form).
    ///
    /// This method returns the string corresponding
    /// the normalized form.
    #[cfg(feature = "alloc")]
    pub fn to_normalized_string(&self) -> String {
        self.norm_hash.to_string()
    }

    /// Converts the fuzzy hash to the string (raw form).
    ///
    /// This method returns the string corresponding the raw
    /// (non-normalized) form.
    #[cfg(feature = "alloc")]
    pub fn to_raw_form_string(&self) -> String {
        self.to_raw_form().to_string()
    }

    /// The internal implementation of [`from_bytes_with_last_index()`](Self::from_bytes_with_last_index()).
    #[inline(always)]
    fn from_bytes_with_last_index_internal(str: &[u8], index: &mut usize)
        -> Result<Self, ParseError>
    {
        use crate::hash_dual::algorithms::update_rle_block;
        use crate::hash::{algorithms, hash_from_bytes_with_last_index_internal_template};
        let mut fuzzy = Self::new();
        hash_from_bytes_with_last_index_internal_template! {
            str, index, true,
            fuzzy.norm_hash.log_blocksize,
            { let mut  rle_offset = 0; },
            |pos, len| rle_offset = update_rle_block(
                &mut fuzzy.rle_block1, rle_offset, pos + block_hash::MAX_SEQUENCE_SIZE - 1, len),
            fuzzy.norm_hash.blockhash1, fuzzy.norm_hash.len_blockhash1,
            { let mut  rle_offset = 0; },
            |pos, len| rle_offset = update_rle_block(
                &mut fuzzy.rle_block2, rle_offset, pos + block_hash::MAX_SEQUENCE_SIZE - 1, len),
            fuzzy.norm_hash.blockhash2, fuzzy.norm_hash.len_blockhash2
        }
        Ok(fuzzy)
    }

    /// Parse a fuzzy hash from given bytes (a slice of [`u8`])
    /// of a string representation.
    ///
    /// If the parser succeeds, it also updates the `index` argument to the
    /// first non-used index to construct the fuzzy hash, which is that of
    /// either the end of the string or the character `','` to separate the rest
    /// of the fuzzy hash and the file name field.
    ///
    /// If the parser fails, `index` is not updated.
    ///
    /// The behavior of this method is affected by the `strict-parser` feature.
    /// For more information, see [The Strict Parser](FuzzyHashData#the-strict-parser).
    pub fn from_bytes_with_last_index(str: &[u8], index: &mut usize)
        -> Result<Self, ParseError>
    {
        Self::from_bytes_with_last_index_internal(str, index)
    }

    /// Parse a fuzzy hash from given bytes (a slice of [`u8`])
    /// of a string representation.
    ///
    /// The behavior of this method is affected by the `strict-parser` feature.
    /// For more information, see [The Strict Parser](FuzzyHashData#the-strict-parser).
    pub fn from_bytes(str: &[u8]) -> Result<Self, ParseError> {
        Self::from_bytes_with_last_index_internal(str, &mut 0usize)
    }

    /// Normalize the fuzzy hash in place.
    ///
    /// After calling this method, `self` will be normalized.
    ///
    /// In this implementation, it clears all "reverse normalization" data.
    ///
    /// See also: ["Normalization" section of `FuzzyHashData`](FuzzyHashData#normalization)
    pub fn normalize_in_place(&mut self) {
        self.rle_block1 = [rle_encoding::TERMINATOR; C1];
        self.rle_block2 = [rle_encoding::TERMINATOR; C2];
    }

    /// Returns whether the dual fuzzy hash is normalized.
    pub fn is_normalized(&self) -> bool {
        self.rle_block1[0] == rle_encoding::TERMINATOR &&
        self.rle_block2[0] == rle_encoding::TERMINATOR
    }

    /// Performs full validity checking of the internal structure.
    ///
    /// The primary purpose of this is debugging and it should always
    /// return [`true`] unless...
    ///
    /// *   There is a bug in this crate, corrupting this structure or
    /// *   A memory corruption is occurred somewhere else.
    ///
    /// Because of its purpose, this method is not designed to be fast.
    ///
    /// Note that, despite that it is only relevant to users when the
    /// `unchecked` feature is enabled but made public without any features
    /// because this method is not *unsafe* or *unchecked* in any way.
    ///
    /// # Safety: No Panic Guarantee
    ///
    /// This method is guaranteed to be panic-free as long as the underlying
    /// memory region corresponding to `self` is sound.
    /// In other words, it won't cause panic by itself if *any* data is
    /// contained in this object.
    pub fn is_valid(&self) -> bool {
        self.norm_hash.is_valid() &&
            algorithms::is_valid_rle_block_for_block_hash(
                &self.norm_hash.blockhash1,
                &self.rle_block1,
                self.norm_hash.len_blockhash1
            ) &&
            algorithms::is_valid_rle_block_for_block_hash(
                &self.norm_hash.blockhash2,
                &self.rle_block2,
                self.norm_hash.len_blockhash2
            )
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    AsRef<fuzzy_norm_type!(S1, S2)> for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline(always)]
    fn as_ref(&self) -> &fuzzy_norm_type!(S1, S2) {
        &self.norm_hash
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    Default for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    PartialEq for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    fn eq(&self, other: &Self) -> bool {
        self.norm_hash == other.norm_hash &&
        self.rle_block1 == other.rle_block1 &&
        self.rle_block2 == other.rle_block2
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    Eq for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::hash::Hash for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.norm_hash.hash(state);
        state.write(&self.rle_block1);
        state.write(&self.rle_block2);
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    Ord for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (
            self.norm_hash,
            self.rle_block1,
            self.rle_block2
        ).cmp(&(
            other.norm_hash,
            other.rle_block1,
            other.rle_block2
        ))
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    PartialOrd for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::fmt::Debug for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        /// The type to print an RLE encoded byte.
        struct DebugBuilderForRLEBlockEntry(u8);
        /// The type to print a valid RLE block.
        struct DebugBuilderForValidRLEBlock<'a, const N: usize> {
            block: &'a [u8; N]
        }
        /// The type to print an invalid RLE block.
        struct DebugBuilderForInvalidRLEBlock<'a, const N: usize> {
            block: &'a [u8; N]
        }
        impl<'a, const N: usize> DebugBuilderForValidRLEBlock<'a, N> {
            pub fn new(rle_block: &'a [u8; N]) -> Self {
                Self { block: rle_block }
            }
        }
        impl<'a, const N: usize> DebugBuilderForInvalidRLEBlock<'a, N> {
            pub fn new(rle_block: &'a [u8; N]) -> Self {
                Self { block: rle_block }
            }
        }
        impl core::fmt::Debug for DebugBuilderForRLEBlockEntry {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                if self.0 != rle_encoding::TERMINATOR {
                    let (pos, len) = rle_encoding::decode(self.0);
                    f.debug_tuple("RLE")
                        .field(&pos).field(&len)
                        .finish()
                }
                else {
                    f.debug_tuple("RLENull").finish()
                }
            }
        }
        impl<'a, const N: usize>
            core::fmt::Debug for DebugBuilderForValidRLEBlock<'a, N>
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_list()
                    .entries(self.block.iter().cloned().filter(|x| *x != rle_encoding::TERMINATOR)
                    .map(DebugBuilderForRLEBlockEntry))
                    .finish()
            }
        }
        impl<'a, const N: usize>
            core::fmt::Debug for DebugBuilderForInvalidRLEBlock<'a, N>
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Don't filter zeroes when invalid,
                // unlike DebugBuilderForValidRLEBlock above.
                f.debug_list()
                    .entries(self.block.iter().cloned().map(DebugBuilderForRLEBlockEntry))
                    .finish()
            }
        }

        // It's for debug purposes and do the full checking.
        if self.is_valid() {
            // Table lookup is safe.  All entries are `0 <= x < 64`.
            let buffer1 = self.norm_hash.blockhash1.map(|x| { BASE64_TABLE_U8[x as usize] }); // grcov-excl-br-line:ARRAY
            let buffer2 = self.norm_hash.blockhash2.map(|x| { BASE64_TABLE_U8[x as usize] }); // grcov-excl-br-line:ARRAY
            f.debug_struct("FuzzyHashDualData")
                .field("LONG", &(S2 == block_hash::FULL_SIZE))
                .field("block_size", &block_size::from_log_internal(self.norm_hash.log_blocksize))
                .field("blockhash1", &core::str::from_utf8(&buffer1[..self.norm_hash.len_blockhash1 as usize]).unwrap())
                .field("blockhash2", &core::str::from_utf8(&buffer2[..self.norm_hash.len_blockhash2 as usize]).unwrap())
                .field("rle_block1", &(DebugBuilderForValidRLEBlock::new(&self.rle_block1)))
                .field("rle_block2", &(DebugBuilderForValidRLEBlock::new(&self.rle_block2)))
                .finish()
        }
        else {
            f.debug_struct("FuzzyHashDualData")
                .field("ILL_FORMED", &true)
                .field("LONG", &(S2 == block_hash::FULL_SIZE))
                .field("log_blocksize", &self.norm_hash.log_blocksize)
                .field("len_blockhash1", &self.norm_hash.len_blockhash1)
                .field("len_blockhash2", &self.norm_hash.len_blockhash2)
                .field("blockhash1", &self.norm_hash.blockhash1)
                .field("blockhash2", &self.norm_hash.blockhash2)
                .field("rle_block1", &(DebugBuilderForInvalidRLEBlock::new(&self.rle_block1)))
                .field("rle_block2", &(DebugBuilderForInvalidRLEBlock::new(&self.rle_block2)))
                .finish()
        }
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::fmt::Display for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{{}|{}}}", self.norm_hash, self.to_raw_form())
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::str::FromStr for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    type Err = ParseError;
    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::convert::From<fuzzy_norm_type!(S1, S2)> for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline]
    fn from(value: fuzzy_norm_type!(S1, S2)) -> Self {
        Self::from_normalized(&value)
    }
}

impl<const S1: usize, const S2: usize, const C1: usize, const C2: usize>
    core::convert::From<fuzzy_raw_type!(S1, S2)> for FuzzyHashDualData<S1, S2, C1, C2>
where
    BlockHashSize<S1>: ConstrainedBlockHashSize,
    BlockHashSize<S2>: ConstrainedBlockHashSize,
    BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    ReconstructionBlockSize<S1, C1>: ConstrainedReconstructionBlockSize,
    ReconstructionBlockSize<S2, C2>: ConstrainedReconstructionBlockSize
{
    #[inline]
    fn from(value: fuzzy_raw_type!(S1, S2)) -> Self {
        Self::from_raw_form(&value)
    }
}


/// Regular (truncated) dual fuzzy hash type which contains both normalized
/// and raw contents.
///
/// This type effectively contains the data equivalent to those two objects:
///
/// *   [`FuzzyHash`](crate::hash::FuzzyHash) (native)
/// *   [`RawFuzzyHash`](crate::hash::RawFuzzyHash) (compressed)
///
/// See also: [`FuzzyHashDualData`]
pub type DualFuzzyHash = FuzzyHashDualData<
    {block_hash::FULL_SIZE},
    {block_hash::HALF_SIZE},
    {block_hash::FULL_SIZE / 4},
    {block_hash::HALF_SIZE / 4}
>;

/// Long (non-truncated) dual fuzzy hash type which contains both normalized
/// and raw contents.
///
/// This type effectively contains the data equivalent to those two objects:
///
/// *   [`LongFuzzyHash`](crate::hash::LongFuzzyHash) (native)
/// *   [`LongRawFuzzyHash`](crate::hash::LongRawFuzzyHash) (compressed)
///
/// See also: [`FuzzyHashDualData`]
pub type LongDualFuzzyHash = FuzzyHashDualData<
    {block_hash::FULL_SIZE},
    {block_hash::FULL_SIZE},
    {block_hash::FULL_SIZE / 4},
    {block_hash::FULL_SIZE / 4}
>;
