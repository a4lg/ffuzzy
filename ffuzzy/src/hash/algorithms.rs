// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

use crate::base64::{BASE64_INVALID, BASE64_TABLE_U8, base64_index};
use crate::hash::block::{
    block_hash, block_size, BlockHashSize, ConstrainedBlockHashSize
};
use crate::hash::parser_state::{
    BlockHashParseState, ParseError, ParseErrorKind, ParseErrorOrigin
};
use crate::macros::{optionally_unsafe, invariant};


#[cfg(test)]
mod tests;


/// Normalize a block hash in place only if the original (expected) form is raw.
#[inline(always)]
pub(crate) fn normalize_block_hash_in_place_internal<const N: usize>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    originally_normalized: bool
)
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    if !originally_normalized {
        let mut seq: usize = 0;
        let mut prev = BASE64_INVALID;
        let old_blockhash_len = *blockhash_len;
        let mut len: usize = 0;
        optionally_unsafe! {
            for i in 0..old_blockhash_len as usize {
                invariant!(i < N);
                let curr: u8 = blockhash[i]; // grcov-excl-br-line:ARRAY
                if curr == prev {
                    seq += 1;
                    if seq >= block_hash::MAX_SEQUENCE_SIZE {
                        seq = block_hash::MAX_SEQUENCE_SIZE;
                        continue;
                    }
                }
                else {
                    seq = 0;
                    prev = curr;
                }
                invariant!(len < N);
                blockhash[len] = curr; // grcov-excl-br-line:ARRAY
                len += 1;
            }
            *blockhash_len = len as u8;
            // Clear old (possibly) non-zero hash buffer (for default Eq)
            invariant!(len as u8 <= old_blockhash_len);
            invariant!(len <= N);
            invariant!((old_blockhash_len as usize) <= N);
            blockhash[len..old_blockhash_len as usize].fill(0); // grcov-excl-br-line:ARRAY
        }
    }
}

/// Normalize a block hash in place only if the original (expected) form is raw.
pub(crate) fn normalize_block_hash_in_place<const N: usize, const ORIG_NORM: bool>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
)
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    normalize_block_hash_in_place_internal(blockhash, blockhash_len, ORIG_NORM)
}

/// Check whether a given block hash is normalized only if `verify` is true.
#[inline(always)]
fn is_block_hash_normalized_internal<const N: usize>(
    blockhash: &[u8; N],
    blockhash_len: u8,
    verify: bool
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    if verify {
        optionally_unsafe! {
            let mut seq: usize = 0;
            let mut prev = BASE64_INVALID;
            invariant!((blockhash_len as usize) <= N);
            for ch in &blockhash[..blockhash_len as usize] { // grcov-excl-br-line:ARRAY
                let curr: u8 = *ch;
                if *ch == prev {
                    seq += 1;
                    if seq >= block_hash::MAX_SEQUENCE_SIZE {
                        return false;
                    }
                }
                else {
                    seq = 0;
                    prev = curr;
                }
            }
        }
    }
    true
}

/// Check whether a given block hash is normalized (or don't, depending on the input normalization).
pub(crate) fn is_block_hash_normalized_input<const N: usize, const EXPECT_NORM: bool>(
    blockhash: &[u8; N],
    blockhash_len: u8,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    is_block_hash_normalized_internal(blockhash, blockhash_len, EXPECT_NORM)
}

/// Check whether a given block hash is normalized (or don't, depending on the type normalization).
pub(crate) fn is_block_hash_normalized_current<const N: usize, const TYPE_NORM: bool>(
    blockhash: &[u8; N],
    blockhash_len: u8,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    is_block_hash_normalized_internal(blockhash, blockhash_len, !TYPE_NORM)
}

/// Push block hash contents at the end of a given [`u8`] slice.
///
/// It converts internal block hash contents into the sequence of Base64
/// alphabets and inserts into a given slice.
#[inline]
pub(crate) fn insert_block_hash_into_bytes<const N: usize>(
    buf: &mut [u8],
    hash: &[u8; N],
    len: u8
)
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    optionally_unsafe! {
        invariant!((len as usize) <= N);
        for (i, idx) in hash[0..len as usize].iter().enumerate() { // grcov-excl-br-line:ARRAY
            invariant!((*idx as usize) < block_hash::ALPHABET_SIZE);
            invariant!(i < buf.len());
            buf[i] = BASE64_TABLE_U8[*idx as usize]; // grcov-excl-br-line:ARRAY
        }
    }
}

/// Parse block size part of the fuzzy hash from given bytes.
///
/// If success, [`Ok`] containing a valid block size is returned.
///
/// `i` (input/output) is updated to the last character index to continue
/// parsing if succeeds.  If it fails, the value of `i` is preserved.
#[inline]
pub(crate) fn parse_block_size_from_bytes(bytes: &mut &[u8])
    -> Result<(u32, usize), ParseError>
{
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
                                    ParseErrorOrigin::BlockSize, 0
                                ));
                            }
                        }
                        None => { is_block_size_in_range = false; }
                    }
                }
            }
            b':' => {
                // End of block size: ':' is expected and block size must not be empty.
                if index == 0 {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsEmpty,
                        ParseErrorOrigin::BlockSize, 0
                    ));
                }
                if !is_block_size_in_range {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsTooLarge,
                        ParseErrorOrigin::BlockSize, 0
                    ));
                }
                if !block_size::is_valid(block_size) {
                    return Err(ParseError(
                        ParseErrorKind::BlockSizeIsInvalid,
                        ParseErrorOrigin::BlockSize, 0
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
                    ParseErrorOrigin::BlockSize, index
                ));
            }
        }
    }
    Err(ParseError(
        ParseErrorKind::UnexpectedEndOfString,
        ParseErrorOrigin::BlockSize, bytes.len()
    ))
}

/// Parse block hash part (1/2) of the fuzzy hash from bytes.
///
/// `i` (input/output) is updated to the last character index
/// to continue parsing.
///
/// `report_norm_seq` is called when `NORM` (normalization) is true (enabled)
/// and we have found a sequence longer than
/// [`MAX_SEQUENCE_SIZE`](block_hash::MAX_SEQUENCE_SIZE).
///
/// Note that however, this function *may not* be called when we once know
/// that the parsing the block hash results in a failure.
///
/// Arguments to `report_norm_seq` is as follows:
///
/// 1.  The offset in the *normalized* block hash
///     (the first character of consecutive characters that are shortened).
/// 2.  The length of the *original* consecutive characters
///     (that are shortened into [`MAX_SEQUENCE_SIZE`](block_hash::MAX_SEQUENCE_SIZE)).
pub(crate) fn parse_block_hash_from_bytes<F, const N: usize, const NORM: bool>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    bytes: &mut &[u8],
    mut report_norm_seq: F
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
    optionally_unsafe! {
        cfg_if::cfg_if! {
            if #[cfg(feature = "strict-parser")] {
                let mut iter = bytes.iter().cloned().take(N);
            }
            else {
                let mut iter = bytes.iter().cloned();
            }
        }
        #[allow(unused_variables)]
        let has_char = loop {
            raw_ch = iter.next();
            if let Some(ch) = raw_ch {
                let bch = base64_index(ch);
                if bch == BASE64_INVALID {
                    break true;
                }
                let curr = bch;
                if NORM {
                    if curr == prev {
                        seq += 1;
                        if seq >= block_hash::MAX_SEQUENCE_SIZE {
                            seq = block_hash::MAX_SEQUENCE_SIZE;
                            index += 1;
                            continue;
                        }
                    }
                    else {
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
                    invariant!(index <= bytes.len());
                    *bytes = &bytes[index..]; // grcov-excl-br-line:ARRAY
                    return (BlockHashParseState::OverflowError, index);
                }
                blockhash[len] = curr; // grcov-excl-br-line:ARRAY
                len += 1;
                index += 1;
            }
            else {
                break false;
            }
        };
        *blockhash_len = len as u8;
        #[cfg(feature = "strict-parser")]
        if !has_char {
            // Even if we reached to the end, that does not always mean that
            // we reached to the end of the string.
            // Try to fetch one more byte to decide what to do.
            invariant!(index <= bytes.len());
            raw_ch = bytes[index..].iter().cloned().next(); // grcov-excl-br-line:ARRAY
        }
        if NORM && seq == block_hash::MAX_SEQUENCE_SIZE {
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
                                (if has_char { BlockHashParseState::Base64Error } else { BlockHashParseState::OverflowError }, index)
                            }
                            else {
                                (BlockHashParseState::Base64Error, index)
                            }
                        }
                    }
                }
            },
            None => (BlockHashParseState::MetEndOfString, index)
        };
        invariant!(result.1 <= bytes.len());
        *bytes = &bytes[result.1..]; // grcov-excl-br-line:ARRAY
        result
    }
}
