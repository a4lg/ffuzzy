// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::base64`].

#![cfg(test)]

use super::{base64_index, base64_index_simple, BASE64_INVALID, BASE64_TABLE_U8};

#[test]
fn values_and_indices() {
    let mut covered_idxes = 0u64;
    let mut expected_idx = 0;
    let mut assert_base64 = |idx: usize, ch| {
        // Test indices sequentially (0..=63).
        assert!(idx < 64);
        assert_eq!(expected_idx, idx);
        assert_eq!(base64_index_simple(ch), Some(idx as u8));
        assert_eq!(BASE64_TABLE_U8[idx], ch);
        covered_idxes |= 1 << idx;
        expected_idx += 1;
    };
    assert_base64(0, b'A');
    assert_base64(1, b'B');
    assert_base64(2, b'C');
    assert_base64(3, b'D');
    assert_base64(4, b'E');
    assert_base64(5, b'F');
    assert_base64(6, b'G');
    assert_base64(7, b'H');
    assert_base64(8, b'I');
    assert_base64(9, b'J');
    assert_base64(10, b'K');
    assert_base64(11, b'L');
    assert_base64(12, b'M');
    assert_base64(13, b'N');
    assert_base64(14, b'O');
    assert_base64(15, b'P');
    assert_base64(16, b'Q');
    assert_base64(17, b'R');
    assert_base64(18, b'S');
    assert_base64(19, b'T');
    assert_base64(20, b'U');
    assert_base64(21, b'V');
    assert_base64(22, b'W');
    assert_base64(23, b'X');
    assert_base64(24, b'Y');
    assert_base64(25, b'Z');
    assert_base64(26, b'a');
    assert_base64(27, b'b');
    assert_base64(28, b'c');
    assert_base64(29, b'd');
    assert_base64(30, b'e');
    assert_base64(31, b'f');
    assert_base64(32, b'g');
    assert_base64(33, b'h');
    assert_base64(34, b'i');
    assert_base64(35, b'j');
    assert_base64(36, b'k');
    assert_base64(37, b'l');
    assert_base64(38, b'm');
    assert_base64(39, b'n');
    assert_base64(40, b'o');
    assert_base64(41, b'p');
    assert_base64(42, b'q');
    assert_base64(43, b'r');
    assert_base64(44, b's');
    assert_base64(45, b't');
    assert_base64(46, b'u');
    assert_base64(47, b'v');
    assert_base64(48, b'w');
    assert_base64(49, b'x');
    assert_base64(50, b'y');
    assert_base64(51, b'z');
    assert_base64(52, b'0');
    assert_base64(53, b'1');
    assert_base64(54, b'2');
    assert_base64(55, b'3');
    assert_base64(56, b'4');
    assert_base64(57, b'5');
    assert_base64(58, b'6');
    assert_base64(59, b'7');
    assert_base64(60, b'8');
    assert_base64(61, b'9');
    assert_base64(62, b'+');
    assert_base64(63, b'/');
    // Make sure that all 64 alphabets are covered.
    assert_eq!(covered_idxes, u64::MAX);
    assert_eq!(expected_idx, 64);
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
