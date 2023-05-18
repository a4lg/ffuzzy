// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

#[cfg(feature = "alloc")]
use alloc::format;
use crate::base64::{base64_index, BASE64_TABLE_U8};
#[cfg(feature = "alloc")]
use crate::base64::BASE64_TABLE;
use crate::hash::algorithms::{
    BlockHashParseState,
    insert_block_hash_into_bytes,
    is_normalized,
    normalize_block_hash_in_place,
    parse_block_hash_from_bytes,
    parse_block_size_from_bytes,
};
#[cfg(feature = "alloc")]
use crate::hash::algorithms::insert_block_hash_into_str;
use crate::hash::block::block_hash;
#[cfg(feature = "alloc")]
use crate::hash::block::block_size;
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
use crate::hash::test_utils::test_blockhash_content_all;

macro_rules! test_for_each_norm {
    ($test: ident) => {
        loop { $test!(false); break; }
        loop { $test!(true);  break; }
    };
}

macro_rules! test_for_each_block_size {
    ($test: ident) => {
        loop { const N: usize = block_hash::FULL_SIZE; $test!(); break; }
        loop { const N: usize = block_hash::HALF_SIZE; $test!(); break; }
    };
}

#[test]
fn test_normalize_block_hash_in_place() {
    test_blockhash_content_all(&|bh, bh_norm| {
        macro_rules! test {() => {
            if bh.len() > N { break; }
            let mut buffer: [u8; N] = [0u8; N];
            buffer[..bh.len()].copy_from_slice(bh);
            let mut len = bh.len() as u8;
            normalize_block_hash_in_place(&mut buffer, &mut len);
            assert_eq!(bh_norm.len() as u8, len, "failed (1) on bhsz={:?}, bh={:?}", N, bh);
            assert_eq!(&buffer[..bh_norm.len()], bh_norm, "failed (2) on bhsz={:?}, bh={:?}", N, bh);
            assert!(buffer[bh_norm.len()..].iter().all(|&x| x == 0), "failed (3) on bhsz={:?}, bh={:?}", N, bh);
        }}
        test_for_each_block_size!(test);
    });
}

#[test]
fn test_is_normalized() {
    test_blockhash_content_all(&|bh, bh_norm| {
        macro_rules! test {() => {
            if bh.len() > N { break; }
            let mut buffer: [u8; N] = [0u8; N];
            buffer[..bh.len()].copy_from_slice(bh);
            let len = bh.len() as u8;
            assert_eq!(is_normalized(&buffer, len), bh == bh_norm, "failed on bhsz={:?}, bh={:?}", N, bh);
        }}
        test_for_each_block_size!(test);
    });
}

#[test]
fn insert_block_hash_into_bytes_contents() {
    test_blockhash_content_all(&|bh, bh_norm| {
        macro_rules! test {() => {
            let verify_block_hash = |test_num: i32, bh: &[u8]| {
                if bh.len() > N { return; }
                let mut buffer: [u8; N] = [0u8; N];
                let mut buffer_out: [u8; N] = [u8::MAX; N];
                buffer[..bh.len()].copy_from_slice(bh);
                let len = bh.len() as u8;
                insert_block_hash_into_bytes(&mut buffer_out[..], &buffer, len);
                // Block hash is converted to Base64 alphabets.
                for (index, (&idx_ch, &base64_ch)) in buffer[..bh.len()].iter().zip(&buffer_out[..bh.len()]).enumerate() {
                    assert_eq!(BASE64_TABLE_U8[idx_ch as usize], base64_ch,
                        "failed ({}-1) on bhsz={:?}, bh={:?}, index={:?}", test_num, N, bh, index);
                }
                // Non block hash bytes are unchanged.
                assert!(buffer_out[bh.len()..].iter().all(|&x| x == u8::MAX), "failed ({}-2) on bhsz={:?}, bh={:?}", test_num, N, bh);
            };
            verify_block_hash(1, bh);
            verify_block_hash(2, bh_norm);
        }}
        test_for_each_block_size!(test);
    });
}

#[cfg(feature = "alloc")]
#[test]
fn insert_block_hash_into_str_contents() {
    use alloc::string::String;
    test_blockhash_content_all(&|bh, bh_norm| {
        macro_rules! test {() => {
            let test = |test_num: i32, bh: &[u8]| {
                if bh.len() > N { return; }
                let mut buffer: [u8; N] = [0u8; N];
                buffer[..bh.len()].copy_from_slice(bh);
                let len = bh.len() as u8;
                let mut s: String = String::new();
                insert_block_hash_into_str(&mut s, &buffer, len);
                assert_eq!(s.len(), bh.len(), "failed ({}-1) on bhsz={:?}, bh={:?}", test_num, N, bh);
                assert_eq!(s.bytes().len(), bh.len(), "failed ({}-2) on bhsz={:?}, bh={:?}", test_num, N, bh);
                // Block hash is converted to Base64 alphabets.
                for (index, (&idx_ch, base64_ch)) in buffer[..bh.len()].iter().zip(s.bytes()).enumerate() {
                    assert_eq!(BASE64_TABLE_U8[idx_ch as usize], base64_ch,
                        "failed ({}-3) on bhsz={:?}, bh={:?}, index={:?}", test_num, N, bh, index);
                }
                #[cfg(feature = "alloc")]
                for (index, (&idx_ch, base64_ch)) in buffer[..bh.len()].iter().zip(s.chars()).enumerate() {
                    assert_eq!(BASE64_TABLE[idx_ch as usize], base64_ch,
                        "failed ({}-4) on bhsz={:?}, bh={:?}, index={:?}", test_num, N, bh, index);
                }
            };
            test(1, bh);
            test(2, bh_norm);
        }}
        test_for_each_block_size!(test);
    });
}

#[cfg(feature = "alloc")]
#[test]
fn insert_block_hash_into_str_examples_and_append() {
    use alloc::string::String;
    let mut buffer: [u8; block_hash::FULL_SIZE] = [0u8; block_hash::FULL_SIZE];
    for (i, ch) in buffer.iter_mut().enumerate().take(7) {
        *ch = i as u8;
    } // "ABCDEFG"
    let len = 7u8;
    let mut s: String = String::from("@@");
    // This operation is "append".
    insert_block_hash_into_str(&mut s, &buffer, len);
    assert_eq!("@@ABCDEFG", s);
}

#[test]
fn parse_block_size_from_bytes_patterns() {
    // Test macros
    macro_rules! test_okay {
        ($str: expr, $block_size: expr) => {
            let mut offset = usize::MAX;
            assert_eq!(parse_block_size_from_bytes($str, &mut offset), Ok($block_size), "failed (1) on str={:?}", $str);
            // offset is updated to point the index just after ':'.
            assert_eq!(offset, $str.iter().position(|&x| x == b':').unwrap() + 1, "failed (2) on str={:?}", $str);
        };
    }
    macro_rules! test_fail {
        ($str: expr, $err: expr) => {
            let mut offset = usize::MAX;
            assert_eq!(parse_block_size_from_bytes($str, &mut offset), Err($err), "failed (1) on str={:?}", $str);
            // offset is not touched on error.
            assert_eq!(offset, usize::MAX, "failed (2) on str={:?}", $str);
        };
    }
    // Valid block size part
    test_okay!(b"3:", 3);
    test_okay!(b"6144:", 6144);
    // Valid block size part (suffix after a colon is ignored)
    test_okay!(b"3:ABC", 3);
    test_okay!(b"6144:abc:de,f", 6144);
    // Empty block size part
    test_fail!(b":",   ParseError(ParseErrorKind::BlockSizeIsEmpty,        ParseErrorOrigin::BlockSize, 0));
    // Block size part starts with '0'
    test_fail!(b"03:", ParseError(ParseErrorKind::BlockSizeStartsWithZero, ParseErrorOrigin::BlockSize, 0));
    // Valid format block size part (but block size itself is not valid)
    test_fail!(b"4:",  ParseError(ParseErrorKind::BlockSizeIsInvalid,      ParseErrorOrigin::BlockSize, 0));
    // Block size part ends with end-of-string.
    for invalid_str in [&b""[..], b"3", b"4", b"12", b"6144"] {
        test_fail!(
            invalid_str,
            ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize, invalid_str.len())
        );
    }
    // Block size part ends with invalid character
    for invalid_str in [&b","[..], b"3,", b"4,", b"12,", b"6144,", b"A", b"3A"] {
        test_fail!(
            invalid_str,
            ParseError(ParseErrorKind::UnexpectedCharacter, ParseErrorOrigin::BlockSize, invalid_str.len() - 1)
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn parse_block_size_from_bytes_overflow_on_block_size() {
    // Block size with u32::MAX
    assert!(!block_size::is_valid(u32::MAX)); // ssdeep-specific
    let mut offset = usize::MAX;
    let invalid_str = format!("{}:", u32::MAX);
    assert_eq!(
        parse_block_size_from_bytes(invalid_str.as_bytes(), &mut offset),
        Err(ParseError(ParseErrorKind::BlockSizeIsInvalid, ParseErrorOrigin::BlockSize, 0))
    );
    assert_eq!(offset, usize::MAX); // offset is not touched on error
    // Block size with u32::MAX + 1
    let mut offset = usize::MAX;
    let invalid_str = format!("{}:", (u32::MAX as u64) + 1);
    assert_eq!(
        parse_block_size_from_bytes(invalid_str.as_bytes(), &mut offset),
        Err(ParseError(ParseErrorKind::BlockSizeIsTooLarge, ParseErrorOrigin::BlockSize, 0))
    );
    assert_eq!(offset, usize::MAX); // offset is not touched on error
}

#[test]
fn parse_block_hash_from_bytes_states_and_normalization() {
    test_blockhash_content_all(&|bh, bh_norm| {
        macro_rules! test {() => {
            if bh.len() > N { break; }
            for insert_offset in 0..=(N - bh.len()) {
                let mut str_buffer: [u8; N+1] = [0u8; N+1];
                let mut expected_buffer: [u8; N] = [u8::MAX; N];
                let mut expected_buffer_norm: [u8; N] = [u8::MAX; N];
                expected_buffer[..bh.len()].copy_from_slice(bh);
                expected_buffer_norm[..bh_norm.len()].copy_from_slice(bh_norm);
                for (i, ch) in bh.iter().map(|&x| BASE64_TABLE_U8[x as usize]).enumerate() {
                    str_buffer[insert_offset + i] = ch;
                }
                // MetEndOfString
                macro_rules! test_case {($norm: expr) => {
                    let test_num = if $norm { 2 } else { 1 };
                    let mut len_out = u8::MAX;
                    let mut buffer = [u8::MAX; N];
                    let mut input_offset = insert_offset;
                    assert_eq!(
                        parse_block_hash_from_bytes::<N, $norm>(
                            &mut buffer,
                            &mut len_out,
                            &str_buffer[..insert_offset + bh.len()],
                            &mut input_offset
                        ),
                        BlockHashParseState::MetEndOfString,
                        "failed (1-{}-1) on bhsz={:?}, bh={:?}, insert_offset={:?}", test_num, N, bh, insert_offset
                    );
                    assert_eq!(buffer, if $norm { expected_buffer_norm } else { expected_buffer },
                        "failed (1-{}-2) on bhsz={:?}, bh={:?}, insert_offset={:?}", test_num, N, bh, insert_offset);
                    // len_out reflects normalization (if enabled), even on error.
                    assert_eq!(len_out, (if $norm { bh_norm } else { bh }).len() as u8,
                        "failed (1-{}-3) on bhsz={:?}, bh={:?}, insert_offset={:?}", test_num, N, bh, insert_offset);
                    // input_offset is updated to the end of the string.
                    assert_eq!(input_offset, insert_offset + bh.len(),
                        "failed (1-{}-4) on bhsz={:?}, bh={:?}, insert_offset={:?}", test_num, N, bh, insert_offset);
                }}
                test_for_each_norm!(test_case);
                // MetColon, MetComma, Base64Error
                for &(status, ch, is_err) in &[
                    (BlockHashParseState::MetColon, b':', false),
                    (BlockHashParseState::MetComma, b',', false),
                    (BlockHashParseState::Base64Error, b'@', true),
                ]
                {
                    // Insert trailing character
                    str_buffer[insert_offset + bh.len()] = ch;
                    let ch = ch as char;
                    macro_rules! test_case {($norm: expr) => {
                        let test_num = if $norm { 2 } else { 1 };
                        let mut len_out = u8::MAX;
                        let mut buffer = [u8::MAX; N];
                        let mut input_offset = insert_offset;
                        assert_eq!(
                            parse_block_hash_from_bytes::<N, $norm>(
                                &mut buffer,
                                &mut len_out,
                                &str_buffer[..insert_offset + bh.len() + 1],
                                &mut input_offset
                            ),
                            status,
                            "failed (2-{}-1) on bhsz={:?}, bh={:?}, insert_offset={:?}, ch={:?}", test_num, N, bh, insert_offset, ch
                        );
                        assert_eq!(buffer, if $norm { expected_buffer_norm } else { expected_buffer },
                            "failed (2-{}-2) on bhsz={:?}, bh={:?}, insert_offset={:?}, ch={:?}", test_num, N, bh, insert_offset, ch);
                        // len_out reflects normalization (if enabled), even on error.
                        assert_eq!(len_out, (if $norm { bh_norm } else { bh }).len() as u8,
                            "failed (2-{}-3) on bhsz={:?}, bh={:?}, insert_offset={:?}, ch={:?}", test_num, N, bh, insert_offset, ch);
                        // input_offset is updated to the terminator (if error)
                        // or the next non-separating character (if not).
                        assert_eq!(input_offset, insert_offset + bh.len() + (if is_err { 0 } else { 1 }),
                            "failed (2-{}-4) on bhsz={:?}, bh={:?}, insert_offset={:?}, ch={:?}", test_num, N, bh, insert_offset, ch);
                    }}
                    test_for_each_norm!(test_case);
                }
            }
        }}
        test_for_each_block_size!(test);
    });
}

#[test]
fn parse_block_hash_from_bytes_overflow_noseq() {
    macro_rules! test {() => {
        let mut str_buffer = [0u8; N + 20];
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
            macro_rules! test_case {($norm: expr) => {
                let corrupt_size = N.checked_add(overflow_size).unwrap();
                let mut len = 0;
                let mut offset: usize = 0;
                let mut buffer: [u8; N] = [u8::MAX; N];
                assert_eq!(
                    parse_block_hash_from_bytes::<N, $norm>(
                        &mut buffer,
                        &mut len,
                        &str_buffer[..corrupt_size],
                        &mut offset
                    ),
                    BlockHashParseState::OverflowError,
                    "failed (1) on bhsz={:?}, overflow_size={:?}, norm={:?}", N, overflow_size, $norm
                );
                // Corrupt offset is N.
                assert_eq!(offset, N, "failed (2) on bhsz={:?}, overflow_size={:?}, norm={:?}", N, overflow_size, $norm);
                // Candidate `len` is N.
                assert_eq!(len as usize, N, "failed (3) on bhsz={:?}, overflow_size={:?}, norm={:?}", N, overflow_size, $norm);
                // Buffer is filled with specific pattern.
                assert_eq!(buffer, expected_buffer, "failed (4) on bhsz={:?}, overflow_size={:?}, norm={:?}", N, overflow_size, $norm);
            }}
            test_for_each_norm!(test_case);
        }
    }}
    test_for_each_block_size!(test);
}
