// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2024–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::base64`].

#![cfg(test)]

use super::{base64_index, base64_index_simple, BASE64_INVALID, BASE64_TABLE_U8};

#[test]
fn values_and_indices() {
    macro_rules! assert_base64_cases {
        {[ $($ch: expr),* $(,)? ]} => {
            let mut idx = 0usize;
            $(
                assert!(idx < 64);
                assert_eq!(base64_index_simple($ch), Some(idx as u8));
                assert_eq!(BASE64_TABLE_U8[idx], $ch);
                idx += 1;
            )*
            // Make sure that all 64 alphabets are covered.
            assert_eq!(idx, 64);
        }
    }
    assert_base64_cases! {
        [
            b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
            b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
            b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
            b'+', b'/',
        ]
    }
}

#[test]
fn alphabets() {
    // Each alphabet must be unique (no duplicates in BASE64_TABLE_U8)
    let mut alphabets = std::collections::HashSet::new();
    for ch in BASE64_TABLE_U8 {
        assert!(alphabets.insert(ch));
    }
}

#[test]
fn invalid_chars() {
    // Collect valid alphabets first.
    let mut alphabets = std::collections::HashSet::new();
    for ch in BASE64_TABLE_U8 {
        alphabets.insert(ch);
    }
    // If `ch` is not a Base64 alphabet,
    // base64_index for that `ch` must return None.
    for ch in u8::MIN..=u8::MAX {
        if alphabets.contains(&ch) {
            continue;
        }
        assert_eq!(base64_index_simple(ch), None);
    }
    // Invalid character has invalid index.
    assert!(BASE64_TABLE_U8.len() <= BASE64_INVALID as usize);
    // Just to make sure
    assert!(BASE64_INVALID >= 64);
}

#[test]
fn compare_impls() {
    // Test that the simple implementation and
    // the branchless implementation are equivalent.
    for ch in u8::MIN..=u8::MAX {
        assert_eq!(
            base64_index(ch),
            base64_index_simple(ch).unwrap_or(BASE64_INVALID)
        );
    }
}
