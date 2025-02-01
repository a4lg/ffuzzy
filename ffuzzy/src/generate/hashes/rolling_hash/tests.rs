// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::generate::hashes::rolling_hash`].

#![cfg(test)]

use alloc::vec::Vec;

use crate::test_utils::test_recommended_default;

use super::RollingHash;

#[test]
fn basic_impls() {
    test_recommended_default!(RollingHash);
}

#[test]
fn usage() {
    const STR: &[u8] = b"Hello, World!\n";
    const EXPECTED_HASH: u32 = 0x19179d98;

    // Usage: Single function call or series of calls
    // Update function 1: update_by_byte
    let mut hash = RollingHash::new();
    for &ch in STR.iter() {
        hash.update_by_byte(ch);
    }
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 2: update_by_iter
    let mut hash = RollingHash::new();
    hash.update_by_iter(STR.iter().cloned());
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 3: update
    let mut hash = RollingHash::new();
    hash.update(STR);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (update_by_byte and folding)
    let mut hash = RollingHash::new();
    let p1 = &hash as *const RollingHash;
    let h = STR
        .iter()
        .fold(&mut hash, |hash, &ch| hash.update_by_byte(ch));
    let p2 = h as *const RollingHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (all update functions)
    let mut hash = RollingHash::new();
    let p1 = &hash as *const RollingHash;
    let h = hash
        .update(b"Hello, ")
        .update_by_iter(b"World!".iter().cloned())
        .update_by_byte(b'\n');
    let p2 = h as *const RollingHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Add-assign operator
    const STR_1: &[u8] = b"Hello, "; // slice
    const STR_2: &[u8; 6] = b"World!"; // array
    let mut hash = RollingHash::new();
    hash += STR_1;
    hash += STR_2;
    hash += b'\n';
    assert_eq!(hash.value(), EXPECTED_HASH);
}

#[test]
fn rolling_basic() {
    // h2_multiplier := 1+2+...+WINDOW_SIZE
    let mut h2_multiplier = 0u32;
    for i in 0..RollingHash::WINDOW_SIZE {
        h2_multiplier += (i as u32) + 1;
    }
    // Check rolling hash internals by supplying WINDOW_SIZE bytes
    let mut hash = RollingHash::new();
    for ch in u8::MIN..=u8::MAX {
        for _ in 0..RollingHash::WINDOW_SIZE {
            hash.update_by_byte(ch);
        }
        // h1: Plain sum
        assert_eq!(
            hash.h1,
            (ch as u32) * (RollingHash::WINDOW_SIZE as u32),
            "failed on ch={}",
            ch
        );
        // h2: Weighted sum
        assert_eq!(hash.h2, (ch as u32) * h2_multiplier, "failed on ch={}", ch);
        // h3: shift-xor
        let mut h3_expected = 0u32;
        for _ in 0..RollingHash::WINDOW_SIZE {
            h3_expected <<= RollingHash::H3_LSHIFT;
            h3_expected ^= ch as u32;
        }
        assert_eq!(hash.h3, h3_expected, "failed on ch={}", ch);
    }
}

#[test]
fn inspect_internal_state_while_rolling() {
    // [0]: fading byte, [RollingHash::WINDOW_SIZE-1]: last (the most weighted) byte
    let mut last_bytes = Vec::<u8>::with_capacity(RollingHash::WINDOW_SIZE);
    let mut last_bytes_actual = Vec::<u8>::with_capacity(RollingHash::WINDOW_SIZE);
    last_bytes.extend([0u8].iter().cycle().take(RollingHash::WINDOW_SIZE));
    // Test with (0..=255), two more pseudo-random sequences and some `u8::MAX` bytes.
    let mut hash = RollingHash::new();
    for (pos, ch) in (u8::MIN..=u8::MAX)
        .chain((u8::MIN..=u8::MAX).map(|x| x.wrapping_mul(0xe3).wrapping_add(0x52)))
        .chain((u8::MIN..=u8::MAX).map(|x| x.wrapping_mul(0x17).wrapping_add(0xe7)))
        .chain([u8::MAX].iter().copied().cycle().take(RollingHash::WINDOW_SIZE * 2))
        .enumerate()
    {
        hash.update_by_byte(ch);
        // window
        last_bytes.remove(0);
        last_bytes.push(ch);
        last_bytes_actual.clear();
        let (segment2, segment1) = hash.window.split_at(hash.index as usize);
        last_bytes_actual.extend(segment1);
        last_bytes_actual.extend(segment2);
        assert_eq!(last_bytes, last_bytes_actual, "failed on pos={}", pos);
        // h1: Plain sum
        let h1_expected = last_bytes.iter().fold(0u32, |acc, &x| acc + (x as u32));
        assert_eq!(hash.h1, h1_expected, "failed on pos={}", pos);
        // h2: Weighted sum
        let mut h2_expected = 0u32;
        for (i, &ch) in last_bytes.iter().enumerate() {
            h2_expected += ((i as u32) + 1) * (ch as u32);
        }
        assert_eq!(hash.h2, h2_expected, "failed on pos={}", pos);
        // h3: shift-xor
        let mut h3_expected = 0u32;
        for &ch in last_bytes.iter() {
            h3_expected <<= RollingHash::H3_LSHIFT;
            h3_expected ^= ch as u32;
        }
        assert_eq!(hash.h3, h3_expected, "failed on pos={}", pos);
        // value: h1+h2+h3
        assert_eq!(
            hash.value(),
            h1_expected
                .wrapping_add(h2_expected)
                .wrapping_add(h3_expected),
            "failed on pos={}",
            pos
        );
    }
}
