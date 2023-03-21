// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

#[cfg(feature = "alloc")]
use alloc::string::String;
use crate::base64::{BASE64_INVALID, BASE64_TABLE_U8, base64_index};
#[cfg(feature = "alloc")]
use crate::base64::BASE64_TABLE;
use crate::hash::BlockHashParseState;
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
use crate::hash::block::{
    BlockHash, BlockSize, BlockHashSize, ConstrainedBlockHashSize
};
use crate::macros::{optionally_unsafe, invariant};

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
                if seq >= BlockHash::MAX_SEQUENCE_SIZE as u32 {
                    seq = BlockHash::MAX_SEQUENCE_SIZE as u32;
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

/// Check whether the given block hash is normalized.
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
            if seq >= BlockHash::MAX_SEQUENCE_SIZE as u32 {
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

/// Push block hash contents at the end of the given [`String`].
///
/// It converts internal block hash contents into the sequence of Base64
/// alphabets and appends to the [`String`].
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
            invariant!((*idx as usize) < BlockHash::ALPHABET_SIZE);
            buf.push(BASE64_TABLE[*idx as usize]); // grcov-excl-br-line:ARRAY
        }
    }
}

/// Push block hash contents at the end of the given [`u8`] slice.
///
/// It converts internal block hash contents into the sequence of Base64
/// alphabets and inserts into given slice.
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
            invariant!((*idx as usize) < BlockHash::ALPHABET_SIZE);
            invariant!(i < buf.len());
            buf[i] = BASE64_TABLE_U8[*idx as usize]; // grcov-excl-br-line:ARRAY
        }
    }
}

/// Parse block size part of the fuzzy hash from bytes.
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
                        Some(bs) => { block_size = bs; }
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
                if !BlockSize::is_valid(block_size) {
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
/// `i` (input/output) is updated to the last character index to continue parsing.
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
                        if seq >= BlockHash::MAX_SEQUENCE_SIZE as u32 {
                            seq = BlockHash::MAX_SEQUENCE_SIZE as u32;
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





// grcov-excl-br-start
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::format;
    use crate::base64::BASE64_TABLE_U8;
    use crate::hash::block::BlockHash;
    #[cfg(feature = "alloc")]
    use crate::hash::block::BlockSize;

    /// Fills given buffer with [0, 1, 2, 3...]
    /// (no consecutive identical characters).
    macro_rules! fill_noseq {
        (&mut $buffer: expr) => {
            for (i, n) in &mut $buffer.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *n = i as u8;
            }
        };
    }

    macro_rules! test_for_each_norm {
        ($test: ident) => {
            $test!(false);
            $test!(true);
        };
    }

    macro_rules! test_for_each_block_size {
        ($test: ident, [$bs: expr]) => {{
            const N: usize = $bs;
            $test!();
        }};
        ($test: ident, [$bs: expr, $($rest: expr),+]) => {
            test_for_each_block_size!($test, [$bs]);
            test_for_each_block_size!($test, [$($rest),+]);
        };
    }

    #[test]
    fn test_normalize_block_hash_in_place() {
        macro_rules! test {() => {
            let mut buffer: [u8; N] = [0; N];
            // Make artificial sequence of seq_len beginning with index seq_start.
            for seq_len in 2usize..=N {
                for seq_start in 0..(N - seq_len + 1) {
                    fill_noseq!(&mut buffer);
                    for i in 1..seq_len {
                        buffer[seq_start + i] = buffer[seq_start];
                    }
                    let backup = buffer;
                    let mut len = N as u8;
                    // Make sure that the buffer tail is overwritten
                    // if loop variable `seq_start` is the maximum value.
                    if seq_start == N - seq_len {
                        assert_ne!(buffer[buffer.len() - 1], (buffer.len() - 1) as u8);
                    }
                    normalize_block_hash_in_place(&mut buffer, &mut len);
                    if seq_len <= BlockHash::MAX_SEQUENCE_SIZE {
                        // No sequence elimination occur.
                        assert_eq!(len, N as u8);
                        assert_eq!(buffer, backup);
                    }
                    else {
                        // Sequence elimination (normalization) occurs.
                        let len = len as usize;
                        assert_eq!(len, N - (seq_len - BlockHash::MAX_SEQUENCE_SIZE));
                        // First half
                        assert_eq!(
                            buffer[..seq_start + BlockHash::MAX_SEQUENCE_SIZE],
                            backup[..seq_start + BlockHash::MAX_SEQUENCE_SIZE]
                        );
                        // Second half (index will be changed due to normalization)
                        assert_eq!(
                            buffer[seq_start + BlockHash::MAX_SEQUENCE_SIZE..len],
                            backup[seq_start + seq_len..backup.len()]
                        );
                        // Trailing zeroes
                        assert!(buffer[len..buffer.len()].iter().all(|&x| x == 0));
                    }
                }
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_is_normalized() {
        macro_rules! test {() => {
            let mut buffer: [u8; N] = [0; N];
            fill_noseq!(&mut buffer);
            assert!(is_normalized(&buffer, N as u8));
            // Make artificial sequence of seq_len beginning with index seq_start.
            for seq_len in 2usize..=N {
                for seq_start in 0..(N - seq_len + 1) {
                    fill_noseq!(&mut buffer);
                    for i in 1..seq_len {
                        buffer[seq_start + i] = buffer[seq_start];
                    }
                    // Make sure that the buffer tail is overwritten
                    // if loop variable `seq_start` is the maximum value.
                    if seq_start == N - seq_len {
                        assert_ne!(buffer[buffer.len() - 1], (buffer.len() - 1) as u8);
                    }
                    // If seq_len is greater than MAX_SEQUENCE_SIZE,
                    // a non-normalized sequence exists.
                    assert_eq!(
                        seq_len <= BlockHash::MAX_SEQUENCE_SIZE,
                        is_normalized(&buffer, N as u8)
                    );
                }
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_insert_block_hash_into_str() {
        use alloc::string::String;
        macro_rules! test {() => {
            let mut buffer: [u8; N] = [0; N];
            for (i, n) in &mut buffer.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *n = i as u8;
            }
            let mut str: String = String::new();
            let mut total_len = 0;
            for hash_len in 0..=buffer.len() {
                // This operation is "append".
                // Since this function does not clear the string,
                // all results will be accumlated on this string.
                insert_block_hash_into_str(&mut str, &buffer, hash_len as u8);
                total_len += hash_len;
                let bytes = str.as_bytes();
                assert_eq!(str.len(), total_len);
                assert_eq!(bytes.len(), total_len);
                // Check the pattern: AABABCABCD...
                let mut p = 0;
                for partial_hash_len in 0..=hash_len {
                    for i in 0..partial_hash_len {
                        assert_eq!(bytes[p], BASE64_TABLE_U8[i]);
                        p += 1;
                    }
                }
                assert_eq!(p, total_len);
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_insert_block_hash_into_bytes() {
        macro_rules! test {() => {
            let mut buffer_in: [u8; N] = [0; N];
            for (i, n) in &mut buffer_in.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *n = i as u8;
            }
            let buffer_in = &buffer_in;
            for hash_len in 0..=buffer_in.len() {
                // Only hash_len bytes are converted and copied to the output.
                let mut buffer_out: [u8; N] = [0xff; N];
                insert_block_hash_into_bytes(&mut buffer_out[..], buffer_in, hash_len as u8);
                for j in 0..hash_len {
                    assert_eq!(buffer_out[j], BASE64_TABLE_U8[j]);
                }
                for j in hash_len..buffer_in.len() {
                    assert_eq!(buffer_out[j], 0xff);
                }
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_parse_block_size_from_bytes() {
        // Test macros
        #[doc(hidden)]
        macro_rules! test_ok {
            ($str: expr, $block_size: expr) => {
                let mut offset = usize::MAX;
                assert_eq!(parse_block_size_from_bytes($str, &mut offset), Ok($block_size));
                // offset is updated to point the index just after ':'.
                assert_eq!(offset, $str.iter().position(|&x| x == b':').unwrap() + 1);
            };
        }
        #[doc(hidden)]
        macro_rules! test_ng {
            ($str: expr, $err: expr) => {
                let mut offset = usize::MAX;
                assert_eq!(parse_block_size_from_bytes($str, &mut offset), Err($err));
                // offset is not touched on error.
                assert_eq!(offset, usize::MAX);
            };
        }
        // Valid block size part
        test_ok!(b"3:", 3);
        test_ok!(b"6144:", 6144);
        // Valid block size part (suffix after a colon is ignored)
        test_ok!(b"3:ABC", 3);
        test_ok!(b"6144:abc:de,f", 6144);
        // Empty block size part
        test_ng!(
            b":",
            ParseError(
                ParseErrorKind::BlockSizeIsEmpty,
                ParseErrorOrigin::BlockSize,
                0
            )
        );
        // Valid format block size part (but block size itself is not valid)
        test_ng!(
            b"4:",
            ParseError(
                ParseErrorKind::BlockSizeIsInvalid,
                ParseErrorOrigin::BlockSize,
                0
            )
        );
        // Block size part ends with end-of-string.
        for invalid_str in [&b""[..], b"3", b"4", b"12", b"6144"] {
            test_ng!(
                invalid_str,
                ParseError(
                    ParseErrorKind::UnexpectedEndOfString,
                    ParseErrorOrigin::BlockSize,
                    invalid_str.len()
                )
            );
        }
        // Block size part ends with invalid character
        for invalid_str in [&b","[..], b"3,", b"4,", b"12,", b"6144,", b"A", b"3A"] {
            test_ng!(
                invalid_str,
                ParseError(
                    ParseErrorKind::UnexpectedCharacter,
                    ParseErrorOrigin::BlockSize,
                    invalid_str.len() - 1
                )
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_parse_block_size_from_bytes_overflow() {
        // Block size with u32::MAX
        assert!(!BlockSize::is_valid(u32::MAX)); // ssdeep-specific
        let mut offset = usize::MAX;
        let invalid_str = format!("{}:", u32::MAX);
        assert_eq!(
            parse_block_size_from_bytes(invalid_str.as_bytes(), &mut offset),
            Err(ParseError(
                ParseErrorKind::BlockSizeIsInvalid,
                ParseErrorOrigin::BlockSize,
                0
            ))
        );
        assert_eq!(offset, usize::MAX); // offset is not touched on error
        // Block size with u32::MAX + 1
        let mut offset = usize::MAX;
        let invalid_str = format!("{}:", (u32::MAX as u64) + 1);
        assert_eq!(
            parse_block_size_from_bytes(invalid_str.as_bytes(), &mut offset),
            Err(ParseError(
                ParseErrorKind::BlockSizeIsTooLarge,
                ParseErrorOrigin::BlockSize,
                0
            ))
        );
        assert_eq!(offset, usize::MAX); // offset is not touched on error
    }

    #[test]
    fn test_parse_block_hash_from_bytes_states() {
        macro_rules! test {() => {
            let mut num_buffer = [0u8; N+1];
            fill_noseq!(&mut num_buffer[..N]);
            num_buffer[N] = match num_buffer[N-1] {
                1 => 0,
                _ => 1,
            };
            let mut str_buffer = [0u8; N+1];
            for (i, ch) in str_buffer.iter_mut().enumerate() {
                *ch = BASE64_TABLE_U8[num_buffer[i] as usize];
            }
            // MetEndOfString
            for out_len in 0..=N {
                for out_offset in 0..(N - out_len + 1) {
                    macro_rules! test {($NORM: expr) => {
                        let mut buffer_out = [u8::MAX; N];
                        let mut buffer_len = u8::MAX;
                        let mut offset = out_offset;
                        // We can correctly parse the string and will result in MetEndOfString.
                        assert_eq!(
                            parse_block_hash_from_bytes::<N, $NORM>(
                                &mut buffer_out,
                                &mut buffer_len, 
                                &str_buffer[..out_offset + out_len],
                                &mut offset
                            ),
                            BlockHashParseState::MetEndOfString
                        );
                        // The output slice matches the expected part of the original number-based buffer.
                        assert_eq!(buffer_out[..out_len], num_buffer[out_offset..out_offset+out_len]);
                        // Rest of the buffer is untouched.
                        assert!(buffer_out[out_len..].iter().all(|x| *x == u8::MAX));
                        // Block hash length is set accordingly.
                        assert_eq!(buffer_len, out_len as u8);
                        // Offset is updated accordingly.
                        assert_eq!(offset, out_offset + out_len);
                    }}
                    test_for_each_norm!(test);
                }
            }
            // MetColon, MetComma, Base64Error
            for (status, ch, is_err) in &[
                (BlockHashParseState::MetColon, b':', false),
                (BlockHashParseState::MetComma, b',', false),
                (BlockHashParseState::Base64Error, b'@', true),
            ] {
                #[cfg(feature = "std")]
                {
                    println!("Testing: {:?}", *status);
                }
                for insert_offset in 0..=N {
                    let mut str_buffer = str_buffer;
                    str_buffer[insert_offset] = *ch;
                    for offset_1 in 0..=insert_offset {
                        for offset_2 in offset_1 + 1..=N {
                            if !(offset_1..offset_2).contains(&insert_offset) { continue; }
                            macro_rules! test {($NORM: expr) => {
                                let pos_term = insert_offset - offset_1;
                                let mut buffer_out = [u8::MAX; N];
                                let mut buffer_len = u8::MAX;
                                let mut offset = offset_1;
                                // We can parse the string and will result in expected status.
                                assert_eq!(
                                    parse_block_hash_from_bytes::<N, $NORM>(
                                        &mut buffer_out,
                                        &mut buffer_len,
                                        &str_buffer[..offset_2],
                                        &mut offset
                                    ),
                                    *status
                                );
                                // The output slice matches the expected part of
                                // the original number-based buffer.
                                assert_eq!(buffer_out[..pos_term], num_buffer[offset_1..offset_1+pos_term]);
                                // Rest of the buffer is untouched.
                                assert!(buffer_out[pos_term..].iter().all(|x| *x == u8::MAX));
                                // Block hash length is set accordingly.
                                assert_eq!(buffer_len, pos_term as u8);
                                // Offset is updated accordingly
                                // (if non-error, the offset accounts the "terminator" character)
                                assert_eq!(offset, insert_offset + (if *is_err { 0 } else { 1 }));
                            }}
                            test_for_each_norm!(test);
                        }
                    }
                }
            }    
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_parse_block_hash_from_bytes_seq_with_norm() {
        macro_rules! test {() => {
            // Make artificial sequence of seq_len beginning with index seq_start.
            for seq_len in 2usize..=N {
                for seq_start in 0..(N - seq_len + 1) {
                    let mut buffer_in = [0; N];
                    fill_noseq!(&mut buffer_in[..N]);
                    for i in 1..seq_len {
                        buffer_in[seq_start + i] = buffer_in[seq_start];
                    }
                    let mut backup: [u8; N] = [0; N];
                    backup[..N].clone_from_slice(&buffer_in[..N]);
                    // Convert to Base64 characters
                    for b in &mut buffer_in[..N] {
                        *b = BASE64_TABLE_U8[*b as usize];
                    }
                    let mut len = 0;
                    let mut offset: usize = 0;
                    // Make sure that the buffer tail is overwritten
                    // if loop variable `seq_start` is the maximum value.
                    if seq_start == N - seq_len {
                        assert_ne!(buffer_in[buffer_in.len() - 1], (buffer_in.len() - 1) as u8);
                    }
                    // Parse block hash WITH normalization.
                    let mut buffer: [u8; N] = [u8::MAX; N];
                    assert_eq!(
                        parse_block_hash_from_bytes::<N, true>(
                            &mut buffer,
                            &mut len,
                            &buffer_in[..],
                            &mut offset
                        ),
                        BlockHashParseState::MetEndOfString
                    );
                    assert_eq!(offset, N);
                    if seq_len <= BlockHash::MAX_SEQUENCE_SIZE {
                        // No sequence elimination occur.
                        // Blockhash size is N.
                        assert_eq!(len, N as u8);
                        // Output offset is the end of the string.
                        assert_eq!(offset, N);
                        // The result matches to that of pre-Base64 conversion.
                        assert_eq!(buffer, backup);
                    }
                    else {
                        // Sequence elimination (normalization) occurs.
                        let len = len as usize;
                        // Blockhash size is affected by seq_len.
                        assert_eq!(len, N - (seq_len - BlockHash::MAX_SEQUENCE_SIZE));
                        // Output offset is the end of the string.
                        assert_eq!(offset, N);
                        // First half
                        assert_eq!(
                            buffer[..seq_start + BlockHash::MAX_SEQUENCE_SIZE],
                            backup[..seq_start + BlockHash::MAX_SEQUENCE_SIZE]
                        );
                        // Second half (index will be changed due to normalization)
                        assert_eq!(
                            buffer[seq_start + BlockHash::MAX_SEQUENCE_SIZE..len],
                            backup[seq_start + seq_len..backup.len()]
                        );
                        // Trailing bytes (not overwritten)
                        assert!(buffer[len..buffer.len()].iter().all(|&x| x == u8::MAX));
                    }
                }
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_parse_block_hash_from_bytes_invalid_base64_seq_with_norm() {
        macro_rules! test {() => {
            for corrupt_offset in 0..N {
                let mut buffer_in: [u8; N + 1] = [b'A'; N + 1];
                buffer_in[buffer_in.len() - 1] = b':';
                // Corrupt Base64 character
                buffer_in[corrupt_offset] = b'@';
                // Check parse_block_hash_from_bytes
                let mut len = 0;
                let mut offset: usize = 0;
                let mut buffer: [u8; N] = [u8::MAX; N];
                assert_eq!(
                    parse_block_hash_from_bytes::<N, true>(
                        &mut buffer,
                        &mut len,
                        &buffer_in[..],
                        &mut offset
                    ),
                    BlockHashParseState::Base64Error
                );
                let len = len as usize;
                // Corrupt offset is raw offset from the beginning.
                assert_eq!(offset, corrupt_offset);
                // Candidate `len` is capped to MAX_SEQUENCE_SIZE.
                assert_eq!(len, usize::min(len, BlockHash::MAX_SEQUENCE_SIZE));
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_parse_block_hash_from_bytes_overflow_noseq() {
        macro_rules! test {() => {
            let buffer_in = [b'B'; N + 20];
            for overflow_size in 1usize..=20 {
                let corrupt_size = N.checked_add(overflow_size).unwrap();
                let mut len = 0;
                let mut offset: usize = 0;
                let mut buffer: [u8; N] = [u8::MAX; N];
                assert_eq!(
                    parse_block_hash_from_bytes::<N, false>(
                        &mut buffer,
                        &mut len,
                        &buffer_in[..corrupt_size],
                        &mut offset
                    ),
                    BlockHashParseState::OverflowError
                );
                // Corrupt offset is N.
                assert_eq!(offset, N);
                // Candidate `len` is N.
                assert_eq!(len as usize, N);
                // Buffer is filled with 'B' (index 1).
                assert_eq!(buffer, [1u8; N]);
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }

    #[test]
    fn test_parse_block_hash_from_bytes_overflow_seq_with_norm() {
        macro_rules! test {() => {
            const M: usize = N + 20;
            // Make artificial sequence of seq_len beginning with index seq_start.
            for seq_len in 2usize..=M {
                for seq_start in 0..(M - seq_len + 1) {
                    let mut buffer_in: [u8; M] = [0; M];
                    for (i, s) in buffer_in.iter_mut().enumerate() {
                        *s = match i % 2 {
                            0 => b'A',
                            _ => b'B',
                        };
                    }
                    for i in 0..seq_len {
                        buffer_in[seq_start + i] = b'C';
                    }
                    // Make sure that the buffer tail is overwritten
                    // if loop variable `seq_start` is the maximum value.
                    if seq_start == M - seq_len {
                        assert_eq!(buffer_in[buffer_in.len() - 1], b'C');
                    }
                    let mut len = 0;
                    let mut offset: usize = 0;
                    // Parse blockhash WITH normalization.
                    let mut buffer: [u8; N] = [u8::MAX; N];
                    let post_len: usize;
                    if seq_len <= BlockHash::MAX_SEQUENCE_SIZE {
                        post_len = M;
                    }
                    else {
                        post_len = M - (seq_len - BlockHash::MAX_SEQUENCE_SIZE);
                    }
                    match parse_block_hash_from_bytes::<N, true>(
                        &mut buffer,
                        &mut len,
                        &buffer_in[..],
                        &mut offset
                    ) {
                        BlockHashParseState::MetEndOfString => {
                            assert!(post_len <= N);
                            assert_eq!(offset, M);
                            assert_eq!(len as usize, post_len);
                        }
                        BlockHashParseState::OverflowError => {
                            assert!(post_len > N);
                            assert_eq!(len as usize, N);
                            if seq_start + BlockHash::MAX_SEQUENCE_SIZE > N
                                || seq_len <= BlockHash::MAX_SEQUENCE_SIZE
                            {
                                // Sequence elimination does not occur or
                                // occurs outside the first N characters.
                                assert_eq!(offset, N);
                            }
                            else {
                                // Overflow offset is affected by seq_len.
                                assert_eq!(offset, N + seq_len - BlockHash::MAX_SEQUENCE_SIZE);
                            }
                        }
                        _ => {
                            // grcov-excl-start
                            panic!("unreachable!");
                            // grcov-excl-end
                        }
                    }
                }
            }
        }}
        test_for_each_block_size!(test, [BlockHash::FULL_SIZE, BlockHash::HALF_SIZE]);
    }
}
// grcov-excl-br-end
