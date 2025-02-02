// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::hash::algorithms`].

#![cfg(test)]

use alloc::format;

use crate::base64::{base64_index, BASE64_TABLE_U8};
use crate::hash::algorithms::{
    BlockHashParseState,
    insert_block_hash_into_bytes,
    verify_block_hash_internal,
    normalize_block_hash_in_place,
    parse_block_hash_from_bytes,
    parse_block_size_from_bytes,
};
use crate::hash::block::{
    block_hash, block_size,
    BlockHashSize as BHS, ConstrainedBlockHashSize as CBHS
};
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
use crate::hash::test_utils::test_blockhash_content_all;
use crate::test_utils::eq_slice_buf;

macro_rules! call_for_block_hash_sizes {
    { $test: ident ($($tokens: tt)*) ; } => {
        $test::<{block_hash::HALF_SIZE}>($($tokens)*);
        $test::<{block_hash::FULL_SIZE}>($($tokens)*);
    };
}

#[test]
fn test_normalize_block_hash_in_place() {
    fn test_body<const N: usize>(bh: &[u8], bh_norm: &[u8]) where BHS<N>: CBHS {
        let bhsz = N;
        if bh.len() > N { return; }
        let mut buffer = [0u8; N];
        buffer[..bh.len()].copy_from_slice(bh);
        let mut len = bh.len() as u8;
        normalize_block_hash_in_place::<N, false>(&mut buffer, &mut len);
        assert_eq!(bh_norm.len() as u8, len, "failed on bhsz={}, bh={:?}", bhsz, bh);
        assert_eq!(&buffer[..bh_norm.len()], bh_norm, "failed on bhsz={}, bh={:?}", bhsz, bh);
        assert!(buffer[bh_norm.len()..].iter().all(|&x| x == 0), "failed on bhsz={}, bh={:?}", bhsz, bh);
    }
    test_blockhash_content_all(&mut |bh, bh_norm| { call_for_block_hash_sizes! { test_body(bh, bh_norm); } });
}

#[test]
fn test_verify_block_hash_normalization() {
    fn test_body<const N: usize>(bh: &[u8], bh_norm: &[u8]) where BHS<N>: CBHS {
        let bhsz = N;
        if bh.len() > N { return; }
        let mut buffer = [0u8; N];
        buffer[..bh.len()].copy_from_slice(bh);
        let len = bh.len() as u8;
        assert_eq!(verify_block_hash_internal(&buffer, len, true, true, true), bh == bh_norm, "failed on bhsz={}, bh={:?}", bhsz, bh);
    }
    test_blockhash_content_all(&mut |bh, bh_norm| { call_for_block_hash_sizes! { test_body(bh, bh_norm); } });
}

#[test]
fn insert_block_hash_into_bytes_contents() {
    fn test_body<const N: usize>(bh: &[u8], bh_norm: &[u8]) where BHS<N>: CBHS {
        let bhsz = N;
        let verify_block_hash = |bh: &[u8]| {
            if bh.len() > N { return; }
            let mut buffer = [0u8; N];
            let mut buffer_out = [u8::MAX; N];
            buffer[..bh.len()].copy_from_slice(bh);
            let len = bh.len() as u8;
            insert_block_hash_into_bytes(&mut buffer_out[..], &buffer, len);
            // Block hash is converted to Base64 alphabets.
            for (index, (&idx_ch, &base64_ch)) in buffer[..bh.len()].iter().zip(&buffer_out[..bh.len()]).enumerate() {
                assert_eq!(BASE64_TABLE_U8[idx_ch as usize], base64_ch, "failed on bhsz={}, bh={:?}, index={}", bhsz, bh, index);
            }
            // Non block hash bytes are unchanged.
            assert!(buffer_out[bh.len()..].iter().all(|&x| x == u8::MAX), "failed on bhsz={}, bh={:?}", bhsz, bh);
        };
        verify_block_hash(bh);
        verify_block_hash(bh_norm);
    }
    test_blockhash_content_all(&mut |bh, bh_norm| { call_for_block_hash_sizes! { test_body(bh, bh_norm); } });
}

#[test]
fn parse_block_size_from_bytes_patterns() {
    // Prerequisites
    assert!(block_size::is_valid(3));
    assert!(block_size::is_valid(12));
    assert!(block_size::is_valid(6144));
    assert!(!block_size::is_valid(4));
    assert!(!block_size::is_valid(4294967295) && 4294967295 == u32::MAX);
    // Test okay cases
    const OKAY_CASES: &[(&str, u32)] = &[
        // Block hash only
        ("3:",        3),
        ("12:",      12),
        ("6144:",  6144),
        // Valid format
        ("3::",       3),
        ("12::",     12),
        ("6144::", 6144),
        // As long as the block size and the separator (':') is parsed,
        // the rest should be ignored.
        ("3:@",       3),
        ("12:@",     12),
        ("6144:@", 6144),
    ];
    for &(input_str, expected_block_size) in OKAY_CASES {
        let bytes = input_str.as_bytes();
        let bs_str_len = bytes.iter().position(|&x| x == b':').unwrap();
        let mut buf = bytes;
        // Check if the block hash is parsed
        assert_eq!(parse_block_size_from_bytes(&mut buf), Ok((expected_block_size, bs_str_len + 1)), "failed on input_str={:?}", input_str);
        // buf is updated to start right after the first ':'.
        assert!(eq_slice_buf(buf, &bytes[bs_str_len + 1..]), "failed on input_str={:?}", input_str);
    }
    // Test failure cases
    struct ParseBlockSizeFailureCase<'a> { input: &'a str, kind: ParseErrorKind, offset: usize }
    macro_rules! fail_cases { [ $(($str: literal, $kind: ident, $offset: expr $(,)?)),* $(,)?] => { &[
        $(ParseBlockSizeFailureCase { input: $str, kind: ParseErrorKind::$kind, offset: $offset }),*
    ] }}
    const FAIL_CASES: &[ParseBlockSizeFailureCase] = fail_cases![
        ("",    UnexpectedEndOfString, 0),
        // Empty block size part
        (":",   BlockSizeIsEmpty, 0),
        // Block size part cannot be prefixed with either '+' or '-'.
        ("+3:",  UnexpectedCharacter, 0),
        ("-3:",  UnexpectedCharacter, 0),
        // Block size prefixed with the digit zero (returns error on the first '0')
        ("03",  BlockSizeStartsWithZero, 0),
        ("03:", BlockSizeStartsWithZero, 0),
        ("03,", BlockSizeStartsWithZero, 0),
        ("03A", BlockSizeStartsWithZero, 0),
        // Valid format block size part (but block size itself is not valid)
        ("4:",  BlockSizeIsInvalid, 0),
        // Block size part does not end with colon
        ("3",   UnexpectedEndOfString, 1),
        ("12",  UnexpectedEndOfString, 2),
        ("@",   UnexpectedCharacter, 0),
        (",",   UnexpectedCharacter, 0),
        ("A",   UnexpectedCharacter, 0),
        ("3@",  UnexpectedCharacter, 1),
        ("3,",  UnexpectedCharacter, 1),
        ("3A",  UnexpectedCharacter, 1),
        ("12@", UnexpectedCharacter, 2),
        ("12,", UnexpectedCharacter, 2),
        ("12A", UnexpectedCharacter, 2),
        // Cases related to overflow (reported after processing the block size part including ':')
        ("4294967295",   UnexpectedEndOfString, 10),
        ("4294967295:",  BlockSizeIsInvalid,     0),
        ("4294967296",   UnexpectedEndOfString, 10),
        ("4294967296@",  UnexpectedCharacter,   10),
        ("4294967296:",  BlockSizeIsTooLarge,    0),
        ("99999999999",  UnexpectedEndOfString, 11),
        ("99999999999@", UnexpectedCharacter,   11),
        ("99999999999:", BlockSizeIsTooLarge,    0),
    ];
    for case in FAIL_CASES {
        let input_str = case.input;
        let expected_err = ParseError(case.kind, ParseErrorOrigin::BlockSize, case.offset);
        // Expected error does occur.
        let bytes = input_str.as_bytes();
        let mut buf = bytes;
        assert_eq!(parse_block_size_from_bytes(&mut buf), Err(expected_err), "failed on input_str={:?}", input_str);
        // buf is not touched on error.
        assert!(eq_slice_buf(buf, bytes), "failed on input_str={:?}", input_str);
    }
}

#[test]
fn parse_block_size_from_bytes_all_valid() {
    for log_block_size in block_size::RANGE_LOG_VALID {
        let bs = block_size::from_log_internal(log_block_size);
        let input_str = format!("{}:@", bs);
        let bytes = input_str.as_bytes();
        let bs_str_len = bytes.iter().position(|&x| x == b':').unwrap();
        let mut buf = bytes;
        // Check if the block hash is parsed
        assert_eq!(parse_block_size_from_bytes(&mut buf), Ok((bs, bs_str_len + 1)), "failed on log_block_size={:?}", log_block_size);
        // buf is updated to start right after the first ':'.
        assert!(eq_slice_buf(buf, &bytes[bs_str_len + 1..]), "failed on log_block_size={:?}", log_block_size);
    }
}

// Common function for better coverage report
fn parse_block_hash_from_bytes_common<const N: usize, const NORM: bool>(
    blockhash: &mut [u8; N],
    blockhash_len: &mut u8,
    bytes: &mut &[u8],
) -> (BlockHashParseState, usize)
where
    BHS<N>: CBHS,
{
    parse_block_hash_from_bytes::<_, N>(blockhash, blockhash_len, NORM, bytes, |_, _| {})
}

#[test]
fn parse_block_hash_from_bytes_states_and_normalization() {
    fn test_body<const N: usize>(bh: &[u8], bh_norm: &[u8]) where BHS<N>: CBHS {
        if bh.len() > N { return; }
        let mut str_buffer = [0u8; block_hash::FULL_SIZE+1];
        let mut expected_buffer = [u8::MAX; N];
        let mut expected_buffer_norm = [u8::MAX; N];
        expected_buffer[..bh.len()].copy_from_slice(bh);
        expected_buffer_norm[..bh_norm.len()].copy_from_slice(bh_norm);
        for (i, ch) in bh.iter().map(|&x| BASE64_TABLE_U8[x as usize]).enumerate() {
            str_buffer[i] = ch;
        }
        // MetEndOfString
        fn test_terminator_eos<const N: usize, const NORM: bool>(
            bh: &[u8], bh_str: &[u8], expected_buffer: &[u8; N], expected_len: usize
        ) where BHS<N>: CBHS {
            let (bhsz, norm) = (N, NORM);
            let mut len_out = u8::MAX;
            let mut buf_out = [u8::MAX; N];
            let mut buf_in = bh_str;
            assert_eq!(
                parse_block_hash_from_bytes_common::<N, NORM>(&mut buf_out, &mut len_out, &mut buf_in),
                (BlockHashParseState::MetEndOfString, bh.len()),
                "failed on bhsz={}, norm={}, bh={:?}", bhsz, norm, bh
            );
            assert_eq!(&buf_out, expected_buffer, "failed on bhsz={}, norm={}, bh={:?}", bhsz, norm, bh);
            // len_out reflects normalization (if enabled), even on error.
            assert_eq!(len_out as usize, expected_len, "failed on bhsz={}, norm={}, bh={:?}", bhsz, norm, bh);
            // buf_in is updated to the end of the parsed buffer (and is empty).
            assert!(eq_slice_buf(buf_in, &bh_str[bh_str.len()..]), "failed on bhsz={}, norm={}, bh={:?}", bhsz, norm, bh);
        }
        let bh_str = &str_buffer[..bh.len()];
        test_terminator_eos::<N,  true>(bh, bh_str, &expected_buffer_norm, bh_norm.len());
        test_terminator_eos::<N, false>(bh, bh_str, &expected_buffer, bh.len());
        // MetColon, MetComma, Base64Error
        #[allow(clippy::too_many_arguments)]
        fn test_terminator_char<const N: usize, const NORM: bool>(
            bh: &[u8], bh_str: &[u8],
            ch: char, is_err: bool,
            expected_buffer: &[u8; N], expected_len: usize, expected_state: BlockHashParseState
        ) where BHS<N>: CBHS {
            let (bhsz, norm) = (N, NORM);
            let mut len_out = u8::MAX;
            let mut buf_out = [u8::MAX; N];
            let mut buf_in = bh_str;
            let (state, parsed_len) =
                parse_block_hash_from_bytes_common::<N, NORM>(&mut buf_out, &mut len_out, &mut buf_in);
            assert_eq!(state, expected_state, "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            assert_eq!(&buf_out, expected_buffer, "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            // len_out reflects normalization (if enabled), even on error.
            assert_eq!(len_out as usize, expected_len, "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            // buf_in is updated to the end of the string or the error character.
            let expected_remaining_len = is_err as usize;
            assert!(eq_slice_buf(buf_in, &bh_str[bh_str.len() - expected_remaining_len..]), "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            assert_eq!(parsed_len - (1 - expected_remaining_len), bh.len(), "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            if is_err {
                assert_eq!(buf_in[0] as char, ch, "failed on bhsz={}, norm={}, bh={:?}, ch={:?}", bhsz, norm, bh, ch);
            }
        }
        for &(expected_state, ch, is_err) in &[
            (BlockHashParseState::MetColon, b':', false),
            (BlockHashParseState::MetComma, b',', false),
            (BlockHashParseState::Base64Error, b'@', true),
        ]
        {
            // Insert trailing character
            let mut expected_state = expected_state;
            if cfg!(feature = "strict-parser") && bh.len() + 1 > N && expected_state == BlockHashParseState::Base64Error {
                expected_state = BlockHashParseState::OverflowError;
            }
            str_buffer[bh.len()] = ch;
            let ch = ch as char;
            let bh_str = &str_buffer[..bh.len() + 1];
            test_terminator_char::<N,  true>(bh, bh_str, ch, is_err, &expected_buffer_norm, bh_norm.len(), expected_state);
            test_terminator_char::<N, false>(bh, bh_str, ch, is_err, &expected_buffer, bh.len(), expected_state);
        }
    }
    test_blockhash_content_all(&mut |bh, bh_norm| { call_for_block_hash_sizes! { test_body(bh, bh_norm); } });
}

#[allow(clippy::type_complexity)]
#[test]
fn parse_block_hash_from_bytes_states_and_normalization_reporting() {
    use std::vec::Vec;
    // Prerequisite
    assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);
    // Shorthand for an invalid value
    const I: u8 = u8::MAX;
    let samples: &[(&[u8], &[(usize, usize)], [u8; 32], BlockHashParseState, usize, u8)] = &[
        // Test Group 1A: Terminating behavior ending with a sequence
        (
            b"ABBCCCDDDDEEEEEFFFFFFGGGGGGG",
            &[(6, 4), (9, 5), (12, 6), (15, 7)],
            [0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 28, 18
        ),
        (
            b"ABBCCCDDDDEEEEEFFFFFFGGGGGGG:",
            &[(6, 4), (9, 5), (12, 6), (15, 7)],
            [0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetColon, 28 + 1, 18
        ),
        (
            b"ABBCCCDDDDEEEEEFFFFFFGGGGGGG,",
            &[(6, 4), (9, 5), (12, 6), (15, 7)],
            [0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetComma, 28 + 1, 18
        ),
        (
            b"ABBCCCDDDDEEEEEFFFFFFGGGGGGG@",
            &[(6, 4), (9, 5), (12, 6), (15, 7)],
            [0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::Base64Error, 28, 18
        ),
        // Test Group 1B: Terminating behavior *not* ending with a sequence.
        (
            b"BBCCCDDDDEEEEEFFFFFFGGGGGGGA",
            &[(5, 4), (8, 5), (11, 6), (14, 7)],
            [1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 28, 18
        ),
        (
            b"BBCCCDDDDEEEEEFFFFFFGGGGGGGA:",
            &[(5, 4), (8, 5), (11, 6), (14, 7)],
            [1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetColon, 28 + 1, 18
        ),
        (
            b"BBCCCDDDDEEEEEFFFFFFGGGGGGGA,",
            &[(5, 4), (8, 5), (11, 6), (14, 7)],
            [1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetComma, 28 + 1, 18
        ),
        (
            b"BBCCCDDDDEEEEEFFFFFFGGGGGGGA@",
            &[(5, 4), (8, 5), (11, 6), (14, 7)],
            [1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::Base64Error, 28, 18
        ),
        // Test Group 2: Single Sequence
        (
            b"AAA",
            &[],
            [0, 0, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 3, 3
        ),
        (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &[(0, 32)],
            [0, 0, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 32, 3
        ),
        (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
            &[(0, 32)],
            [0, 0, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetColon, 32 + 1, 3
        ),
        (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,",
            &[(0, 32)],
            [0, 0, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetComma, 32 + 1, 3
        ),
        (
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &[(0, if cfg!(feature = "strict-parser") { 32 } else { 64 })],
            [0, 0, 0, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            if cfg!(feature = "strict-parser") { BlockHashParseState::OverflowError } else { BlockHashParseState::MetEndOfString },
            if cfg!(feature = "strict-parser") { 32 } else { 64 },
            3
        ),
        // Test Group 3: Complex
        (
            b"AAAAAAABCCCCCCCC",
            &[(0, 7), (4, 8)],
            [0, 0, 0, 1, 2, 2, 2, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 16, 7
        ),
        (
            b"DAAAAAAABCCCCCCCCEEE",
            &[(1, 7), (5, 8)],
            [3, 0, 0, 0, 1, 2, 2, 2, 4, 4, 4, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I],
            BlockHashParseState::MetEndOfString, 20, 11
        ),
        // Test Group 4: No sequences
        (
            b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGH",
            &[],
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            BlockHashParseState::MetEndOfString, 32, 32
        ),
        (
            b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGH:",
            &[],
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            BlockHashParseState::MetColon, 32 + 1, 32
        ),
        (
            b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGH,",
            &[],
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            BlockHashParseState::MetComma, 32 + 1, 32
        ),
        (
            b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGH@",
            &[],
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            if cfg!(feature = "strict-parser") { BlockHashParseState::OverflowError } else { BlockHashParseState::Base64Error }, 32, 32
        ),
        (
            b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGHI",
            &[],
            [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7],
            BlockHashParseState::OverflowError, 32, 32
        ),
    ];
    for sample in samples {
        let &(bytes, expected_reported_seqs, expected_buffer, expected_state, expected_input_offset, expected_blockhash_len) = sample;
        let mut reported_seqs = Vec::new();
        let mut buf_out = [I; 32];
        let mut blockhash_len = 0;
        let mut buf_in: &[u8] = bytes;
        let (state, parsed_len) = parse_block_hash_from_bytes::<_, 32>(
            &mut buf_out, &mut blockhash_len, true, &mut buf_in,
            |start_pos_norm, seq_len| {
                assert!(seq_len > block_hash::MAX_SEQUENCE_SIZE, "failed on bytes={:?}", bytes);
                reported_seqs.push((start_pos_norm, seq_len));
            }
        );
        match state {
            BlockHashParseState::Base64Error | BlockHashParseState::OverflowError => {
                // On error, the last run-length may not be reported but otherwise the same.
                assert!(
                    reported_seqs == expected_reported_seqs || reported_seqs == expected_reported_seqs[..expected_reported_seqs.len() - 1],
                    "failed on bytes={:?}", bytes);
            }
            _ => { assert_eq!(reported_seqs, expected_reported_seqs, "failed on bytes={:?}", bytes); }
        }
        assert_eq!(state, expected_state, "failed on bytes={:?}", bytes);
        assert_eq!(&buf_out, &expected_buffer, "failed on bytes={:?}", bytes);
        assert_eq!(parsed_len, expected_input_offset, "failed on bytes={:?}", bytes); // TODO
        assert_eq!(blockhash_len, expected_blockhash_len, "failed on bytes={:?}", bytes);
    }
}

#[test]
fn parse_block_hash_from_bytes_overflow_noseq() {
    fn test_body<const N: usize>() where BHS<N>: CBHS {
        let mut str_buffer = [0u8; block_hash::FULL_SIZE + 20];
        for (i, ch) in str_buffer.iter_mut().enumerate() {
            // Make a sequence at the tail (overflowing part) but
            // it will not be affected by normalization.
            *ch = if i >= N { b'D' } else if i % 2 == 0 { b'B' } else { b'C' };
        }
        let mut expected_buffer = [0u8; N];
        for (i, ch) in expected_buffer.iter_mut().enumerate() {
            *ch = base64_index(str_buffer[i]);
        }
        for overflow_size in 1usize..=20 {
            fn test_overflow<const N: usize, const NORM: bool>(
                overflow_size: usize,
                str_buffer: &[u8; block_hash::FULL_SIZE + 20],
                expected_buffer: &[u8; N]
            ) where BHS<N>: CBHS {
                let (bhsz, norm) = (N, NORM);
                let corrupt_size = N.checked_add(overflow_size).unwrap();
                let mut len = 0;
                let mut buf_out: [u8; N] = [u8::MAX; N];
                let mut buf_in = &str_buffer[..corrupt_size];
                let (state, parsed_len) = parse_block_hash_from_bytes_common::<N, NORM>(&mut buf_out, &mut len, &mut buf_in);
                assert_eq!(state, BlockHashParseState::OverflowError, "failed on bhsz={}, norm={}, overflow_size={}", bhsz, norm, overflow_size);
                // Stopped parsed_len is N.
                assert_eq!(parsed_len, N, "failed on bhsz={}, norm={}, overflow_size={}", bhsz, norm, overflow_size);
                // Candidate `len` is N.
                assert_eq!(len as usize, N, "failed on bhsz={}, norm={}, overflow_size={}", bhsz, norm, overflow_size);
                // Buffer is filled with specific pattern.
                assert_eq!(&buf_out, expected_buffer, "failed on bhsz={}, norm={}, overflow_size={}", bhsz, norm, overflow_size);
            }
            test_overflow::<N,  true>(overflow_size, &str_buffer, &expected_buffer);
            test_overflow::<N, false>(overflow_size, &str_buffer, &expected_buffer);
        }
    }
    call_for_block_hash_sizes! { test_body(); }
}
