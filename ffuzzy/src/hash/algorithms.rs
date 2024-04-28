// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

//! Algorithms used to handle fuzzy hashes.

use crate::base64::{base64_index, BASE64_INVALID, BASE64_TABLE_U8};
use crate::hash::block::{block_hash, block_size, BlockHashSize, ConstrainedBlockHashSize};
use crate::hash::parser_state::{
    BlockHashParseState, ParseError, ParseErrorKind, ParseErrorOrigin,
};
use crate::macros::{invariant, optionally_unsafe};

/// Normalize a block hash in place only if the original (expected) form is raw.
#[inline(always)]
pub(crate) fn normalize_block_hash_in_place_internal<const N: usize>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    originally_normalized: bool,
) where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    if !originally_normalized {
        let mut seq: usize = 0;
        let mut prev = BASE64_INVALID;
        let old_blockhash_len = *blockhash_len;
        let mut len: usize = 0;
        optionally_unsafe! {
            invariant!(old_blockhash_len as usize <= N);
        }
        for i in 0..old_blockhash_len as usize {
            let curr: u8 = blockhash[i]; // grcov-excl-br-line:ARRAY
            if curr == prev {
                seq += 1;
                if seq >= block_hash::MAX_SEQUENCE_SIZE {
                    seq = block_hash::MAX_SEQUENCE_SIZE;
                    continue;
                }
            } else {
                seq = 0;
                prev = curr;
            }
            optionally_unsafe! {
                invariant!(len < N);
            }
            blockhash[len] = curr; // grcov-excl-br-line:ARRAY
            len += 1;
        }
        *blockhash_len = len as u8;
        // Clear old (possibly) non-zero hash buffer (for default Eq)
        optionally_unsafe! {
            invariant!(len as u8 <= old_blockhash_len);
            invariant!(len <= N);
        }
        blockhash[len..old_blockhash_len as usize].fill(0); // grcov-excl-br-line:ARRAY
    }
}

/// Normalize a block hash in place only if the original (expected) form is raw.
pub(crate) fn normalize_block_hash_in_place<const N: usize, const ORIG_NORM: bool>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
) where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    normalize_block_hash_in_place_internal(blockhash, blockhash_len, ORIG_NORM)
}

/// Check whether a given block hash is normalized only if `verify` is true.
#[inline(always)]
fn verify_block_hash_internal<const N: usize>(
    blockhash: &[u8; N],
    blockhash_len: u8,
    verify_data_range_in: bool,
    verify_data_range_out: bool,
    verify_normalization: bool,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    optionally_unsafe! {
        invariant!((blockhash_len as usize) <= N);
    }
    let blockhash_out = &blockhash[blockhash_len as usize..]; // grcov-excl-br-line:ARRAY
    let blockhash = &blockhash[..blockhash_len as usize]; // grcov-excl-br-line:ARRAY
    if verify_normalization {
        let mut seq: usize = 0;
        let mut prev = BASE64_INVALID;
        for ch in blockhash {
            let curr: u8 = *ch;
            if verify_data_range_in && curr >= block_hash::ALPHABET_SIZE as u8 {
                return false;
            }
            if *ch == prev {
                seq += 1;
                if seq >= block_hash::MAX_SEQUENCE_SIZE {
                    return false;
                }
            } else {
                seq = 0;
                prev = curr;
            }
        }
    } else if verify_data_range_in
        && blockhash
            .iter()
            .any(|&x| x >= block_hash::ALPHABET_SIZE as u8)
    {
        return false;
    }
    if verify_data_range_out && blockhash_out.iter().any(|&x| x != 0) {
        return false;
    }
    true
}

/// Check whether a given block hash is normalized (or don't, depending on the input normalization).
pub(crate) fn verify_block_hash_input<const N: usize, const EXPECT_NORM: bool>(
    blockhash: &[u8; N],
    blockhash_len: u8,
    verify_data_range_in: bool,
    verify_data_range_out: bool,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    verify_block_hash_internal(
        blockhash,
        blockhash_len,
        verify_data_range_in,
        verify_data_range_out,
        EXPECT_NORM,
    )
}

/// Check whether a given block hash is normalized (or don't, depending on the type normalization).
pub(crate) fn verify_block_hash_current<const N: usize, const TYPE_NORM: bool>(
    blockhash: &[u8; N],
    blockhash_len: u8,
    verify_data_range_in: bool,
    verify_data_range_out: bool,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    verify_block_hash_internal(
        blockhash,
        blockhash_len,
        verify_data_range_in,
        verify_data_range_out,
        !TYPE_NORM,
    )
}

/// Push block hash contents at the end of a given [`u8`] slice.
///
/// It converts internal block hash contents into the sequence of Base64
/// alphabets and inserts into a given slice.
#[inline]
pub(crate) fn insert_block_hash_into_bytes<const N: usize>(buf: &mut [u8], hash: &[u8; N], len: u8)
where
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    optionally_unsafe! {
        invariant!((len as usize) <= N);
    }
    let hash = &hash[0..len as usize]; // grcov-excl-br-line:ARRAY
    for (i, idx) in hash.iter().enumerate() {
        optionally_unsafe! {
            invariant!((*idx as usize) < block_hash::ALPHABET_SIZE);
            invariant!(i < buf.len());
        }
        buf[i] = BASE64_TABLE_U8[*idx as usize]; // grcov-excl-br-line:ARRAY
    }
}

/// Parse block size part of the fuzzy hash from given bytes.
///
/// If success, [`Ok`] containing a valid block size is returned.
///
/// `i` (input/output) is updated to the last character index to continue
/// parsing if succeeds.  If it fails, the value of `i` is preserved.
#[inline]
pub(crate) fn parse_block_size_from_bytes(bytes: &mut &[u8]) -> Result<(u32, usize), ParseError> {
    let mut block_size = 0u32;
    let mut is_block_size_in_range = true;
    for (index, ch) in bytes.iter().enumerate() {
        match *ch {
            b'0'..=b'9' => {
                // Update block size (but check arithmetic overflow)
                if is_block_size_in_range {
                    match block_size
                        .checked_mul(10)
                        .and_then(|x| x.checked_add((*ch - b'0') as u32))
                    {
                        Some(bs) => {
                            block_size = bs;
                            if block_size == 0 {
                                return Err(ParseError(
                                    ParseErrorKind::BlockSizeStartsWithZero,
                                    ParseErrorOrigin::BlockSize,
                                    0,
                                ));
                            }
                        }
                        None => {
                            is_block_size_in_range = false;
                        }
                    }
                }
            }
            b':' => {
                // End of block size: ':' is expected and block size must not be empty.
                if index == 0 {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsEmpty,
                        ParseErrorOrigin::BlockSize,
                        0,
                    ));
                }
                if !is_block_size_in_range {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsTooLarge,
                        ParseErrorOrigin::BlockSize,
                        0,
                    ));
                }
                if !block_size::is_valid(block_size) {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsInvalid,
                        ParseErrorOrigin::BlockSize,
                        0,
                    ));
                }
                optionally_unsafe! {
                    invariant!(index < bytes.len());
                    *bytes = &bytes[index + 1..];
                    return Ok((block_size, index + 1));
                }
            }
            _ => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockSize,
                    index,
                ));
            }
        }
    }
    Err(ParseError(
        ParseErrorKind::UnexpectedEndOfString,
        ParseErrorOrigin::BlockSize,
        bytes.len(),
    ))
}

/// Parse block hash part (1/2) of the fuzzy hash from bytes.
///
/// `bytes` (input/output) is updated to start with the first character
/// to resume parsing the next part (i.e. block hash 1 → block hash 2,
/// block hash 2 → file name) if succeeds (the end of `bytes` is always
/// unchanged).
///
/// `report_norm_seq` is called when `normalize` (normalization) is true
/// (enabled) and we have found a sequence longer than
/// [`MAX_SEQUENCE_SIZE`](block_hash::MAX_SEQUENCE_SIZE).
///
/// Note that however, this function *may not* be called when we once know
/// that the parsing the block hash results in a failure and the last "length"
/// might assume that the overflow won't occur (i.e. the sum of two arguments
/// below may be capped to `N`, depending on the configuration).
///
/// Arguments to `report_norm_seq` is as follows:
///
/// 1.  The offset in the *normalized* block hash
///     (the first character of consecutive characters that are shortened).
/// 2.  The length of the *original* consecutive characters
///     (that are shortened into [`MAX_SEQUENCE_SIZE`](block_hash::MAX_SEQUENCE_SIZE)).
#[inline(always)]
pub(crate) fn parse_block_hash_from_bytes<F, const N: usize>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    normalize: bool,
    bytes: &mut &[u8],
    mut report_norm_seq: F,
) -> (BlockHashParseState, usize)
where
    F: FnMut(usize, usize),
    BlockHashSize<N>: ConstrainedBlockHashSize,
{
    let mut seq: usize = 0;
    let mut seq_start: usize = 0;
    let mut seq_start_in: usize = 0;
    let mut prev = BASE64_INVALID;
    let mut len: usize = 0;
    let mut index: usize = 0;
    let mut raw_ch: Option<u8>;
    cfg_if::cfg_if! {
        if #[cfg(feature = "strict-parser")] {
            let mut iter = bytes.iter().cloned().take(N);
        } else {
            let mut iter = bytes.iter().cloned();
        }
    }
    #[cfg_attr(not(feature = "strict-parser"), allow(unused_variables))]
    let has_char = loop {
        raw_ch = iter.next();
        if let Some(ch) = raw_ch {
            let bch = base64_index(ch);
            if bch == BASE64_INVALID {
                break true;
            }
            let curr = bch;
            if normalize {
                if curr == prev {
                    seq += 1;
                    if seq >= block_hash::MAX_SEQUENCE_SIZE {
                        seq = block_hash::MAX_SEQUENCE_SIZE;
                        index += 1;
                        continue;
                    }
                } else {
                    if seq == block_hash::MAX_SEQUENCE_SIZE {
                        let len = index - seq_start_in;
                        report_norm_seq(seq_start, len);
                    }
                    seq = 0;
                    seq_start = len;
                    seq_start_in = index;
                    prev = curr;
                }
            }
            #[cfg(not(feature = "strict-parser"))]
            if crate::intrinsics::unlikely(len >= N) {
                *blockhash_len = len as u8;
                optionally_unsafe! {
                    invariant!(index <= bytes.len());
                }
                *bytes = &bytes[index..]; // grcov-excl-br-line:ARRAY
                return (BlockHashParseState::OverflowError, index);
            }
            blockhash[len] = curr; // grcov-excl-br-line:ARRAY
            len += 1;
            index += 1;
        } else {
            break false;
        }
    };
    *blockhash_len = len as u8;
    #[cfg(feature = "strict-parser")]
    if !has_char {
        // Even if we reached to the end, that does not always mean that
        // we reached to the end of the string.
        // Try to fetch one more byte to decide what to do.
        optionally_unsafe! {
            invariant!(index <= bytes.len());
        }
        raw_ch = bytes[index..].iter().cloned().next(); // grcov-excl-br-line:ARRAY
    }
    if normalize && seq == block_hash::MAX_SEQUENCE_SIZE {
        let len = index - seq_start_in;
        report_norm_seq(seq_start, len);
    }
    let result = match raw_ch {
        Some(ch) => {
            match ch {
                b':' => (BlockHashParseState::MetColon, index + 1),
                b',' => (BlockHashParseState::MetComma, index + 1),
                _ => {
                    cfg_if::cfg_if! {
                        if #[cfg(feature = "strict-parser")] {
                            // grcov-excl-br-start
                            (
                                if has_char {
                                    BlockHashParseState::Base64Error
                                } else {
                                    BlockHashParseState::OverflowError
                                },
                                index,
                            )
                            // grcov-excl-br-stop
                        } else {
                            (BlockHashParseState::Base64Error, index)
                        }
                    }
                }
            }
        }
        None => (BlockHashParseState::MetEndOfString, index),
    };
    optionally_unsafe! {
        invariant!(result.1 <= bytes.len());
    }
    *bytes = &bytes[result.1..]; // grcov-excl-br-line:ARRAY
    result
}

mod tests;
