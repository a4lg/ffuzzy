// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::base64::{BASE64_INVALID, BASE64_TABLE_U8, base64_index};
#[cfg(feature = "alloc")]
use crate::base64::BASE64_TABLE;
use crate::hash::block::{
    block_hash, block_size, BlockHashSize, ConstrainedBlockHashSize
};
use crate::hash::parser_state::{
    BlockHashParseState, ParseError, ParseErrorKind, ParseErrorOrigin
};
use crate::macros::{optionally_unsafe, invariant};


#[cfg(test)]
mod tests;


/// Normalize a block hash in place.
pub(crate) fn normalize_block_hash_in_place<const N: usize>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
)
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    let mut seq: u32 = 0;
    let mut prev = BASE64_INVALID;
    let old_blockhash_len = *blockhash_len;
    let mut len: u32 = 0;
    optionally_unsafe! {
        for i in 0..old_blockhash_len as usize {
            invariant!(i < N);
            let curr: u8 = blockhash[i]; // grcov-excl-br-line:ARRAY
            if curr == prev {
                seq += 1;
                if seq >= block_hash::MAX_SEQUENCE_SIZE as u32 {
                    seq = block_hash::MAX_SEQUENCE_SIZE as u32;
                    continue;
                }
            }
            else {
                seq = 0;
                prev = curr;
            }
            invariant!((len as usize) < N);
            blockhash[len as usize] = curr; // grcov-excl-br-line:ARRAY
            len += 1;
        }
        *blockhash_len = len as u8;
        // Clear old (possibly) non-zero hash buffer (for default Eq)
        invariant!(len as u8 <= old_blockhash_len);
        invariant!((len as usize) <= N);
        invariant!((old_blockhash_len as usize) <= N);
        blockhash[len as usize..old_blockhash_len as usize].fill(0); // grcov-excl-br-line:ARRAY
    }
}

/// Check whether a given block hash is normalized.
pub(crate) fn is_normalized<const N: usize>(
    blockhash: &[u8; N],
    blockhash_len: u8,
) -> bool
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    let mut seq: u32 = 0;
    let mut prev = BASE64_INVALID;
    for ch in &blockhash[..blockhash_len as usize] { // grcov-excl-br-line:ARRAY
        let curr: u8 = *ch;
        if *ch == prev {
            seq += 1;
            if seq >= block_hash::MAX_SEQUENCE_SIZE as u32 {
                return false;
            }
        }
        else {
            seq = 0;
            prev = curr;
        }
    }
    true
}

/// Push block hash contents at the end of a given [`String`].
///
/// It converts internal block hash contents into the sequence of Base64
/// alphabets and appends to a given [`String`].
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn insert_block_hash_into_str<const N: usize>(
    buf: &mut String,
    hash: &[u8; N],
    len: u8
)
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    optionally_unsafe! {
        invariant!((len as usize) <= N);
        for idx in &hash[0..len as usize] { // grcov-excl-br-line:ARRAY
            invariant!((*idx as usize) < block_hash::ALPHABET_SIZE);
            buf.push(BASE64_TABLE[*idx as usize]); // grcov-excl-br-line:ARRAY
        }
    }
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
pub(crate) fn parse_block_size_from_bytes(bytes: &[u8], i: &mut usize)
    -> Result<u32, ParseError>
{
    let mut block_size = 0u32;
    let mut is_block_size_in_range = true;
    let mut j = 0;
    for ch in bytes {
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
                if j == 0 {
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
                *i = j + 1;
                return Ok(block_size);
            }
            _ => {
                return Err(ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockSize, j
                ));
            }
        }
        j += 1;
    }
    Err(ParseError(
        ParseErrorKind::UnexpectedEndOfString,
        ParseErrorOrigin::BlockSize, j
    ))
}

/// Parse block hash part (1/2) of the fuzzy hash from bytes.
///
/// `i` (input/output) is updated to the last character index
/// to continue parsing.
pub(crate) fn parse_block_hash_from_bytes<const N: usize, const NORM: bool>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    bytes: &[u8],
    i: &mut usize
) -> BlockHashParseState
where
    BlockHashSize<N>: ConstrainedBlockHashSize
{
    let mut seq: u32 = 0;
    let mut prev = BASE64_INVALID;
    let mut j = *i;
    let mut len: u32 = 0;
    #[doc(hidden)]
    macro_rules! pre_ret {() => { *blockhash_len = len as u8 }}
    #[doc(hidden)]
    macro_rules! ret {($expr: expr) => { *i = j; return $expr }}
    optionally_unsafe! {
        invariant!(j <= bytes.len());
        for ch in &bytes[j..] { // grcov-excl-br-line:ARRAY
            let bch = base64_index(*ch);
            if bch != BASE64_INVALID {
                let curr = bch;
                if NORM {
                    if curr == prev {
                        seq += 1;
                        if seq >= block_hash::MAX_SEQUENCE_SIZE as u32 {
                            seq = block_hash::MAX_SEQUENCE_SIZE as u32;
                            j += 1;
                            continue;
                        }
                    }
                    else {
                        seq = 0;
                        prev = curr;
                    }
                }
                if len as usize == N {
                    pre_ret!();
                    ret!(BlockHashParseState::OverflowError);
                }
                invariant!((len as usize) < N);
                blockhash[len as usize] = curr; // grcov-excl-br-line:ARRAY
                len += 1;
            }
            else {
                pre_ret!();
                match ch {
                    b':' => { j += 1; ret!(BlockHashParseState::MetColon); }
                    b',' => { j += 1; ret!(BlockHashParseState::MetComma); }
                    _ => { ret!(BlockHashParseState::Base64Error); }
                }
            }
            j += 1;
        }
    }
    pre_ret!();
    ret!(BlockHashParseState::MetEndOfString);
}
