// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Test utilities for rolling hash.

#![cfg(any(test, doc))]
#![cfg_attr(feature = "unstable", doc(cfg(test)))]

use super::RollingHash;

#[test]
fn new_hash_with_prefix_zeroes_prerequisites() {
    assert_eq!(RollingHash::WINDOW_SIZE, 7);
}

/// Generate [`RollingHash`] object which has the exact same state
/// as after processing specified number of zero bytes.
///
/// To simulate the condition after processing huge amount of data
/// (e.g. multiple gigabytes), the way to simulate the state is required.
/// This methods provides one of the ways to do that.
///
/// If all previous window bytes have the value `0`, all
/// [`RollingHash::h1`], [`RollingHash::h2`] and [`RollingHash::h3`]
/// will have the value zero and [`RollingHash::index`] will have the
/// value depending on the number of bytes processed.
pub(crate) fn new_hash_with_prefix_zeroes(size: u64) -> RollingHash {
    let mut hash = RollingHash::new();
    hash.h1 = 0;
    hash.h2 = 0;
    hash.h3 = 0;
    hash.index = (size % (RollingHash::WINDOW_SIZE as u64)) as u32;
    hash
}

#[test]
fn new_hash_with_prefix_zeroes_state() {
    let mut hash = RollingHash::new();
    for size in 0..=(RollingHash::WINDOW_SIZE as u64) * 2 {
        assert_eq!(
            hash,
            new_hash_with_prefix_zeroes(size),
            "failed on size={}",
            size
        );
        hash.update_by_byte(0);
    }
}
