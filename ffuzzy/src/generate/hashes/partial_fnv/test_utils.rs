// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Test utilities for partial FNV hash.

#![cfg(any(test, doc))]
#![cfg_attr(feature = "unstable", doc(cfg(test)))]

use super::PartialFNVHash;

/// Period of this partial FNV hash when only zero bytes are processed.
///
/// After processing specified count of zero bytes from the initial state of
/// [`PartialFNVHash`], the resulting state is now back to the original one.
///
/// Note that this will not apply to full FNV-1 hash (only applies to the
/// lowest 6 bits and with a ssdeep-specific initial state).
pub(crate) const ZERO_DATA_PERIOD: u64 = 16;

#[test]
fn test_zero_data_period() {
    let initial_hash = PartialFNVHash::new();
    let mut hash = PartialFNVHash::new();
    // Repeat the process to ensure that it repeats
    // with the `opt-reduce-fnv-table` feature
    // (remove this repetition on the next major release).
    for _ in 0..((256 + ZERO_DATA_PERIOD - 1) / ZERO_DATA_PERIOD) {
        hash.update_by_iter([0].iter().cloned().cycle().take(ZERO_DATA_PERIOD as usize));
        assert_eq!(initial_hash.value(), hash.value());
    }
}

/// Generate [`PartialFNVHash`] object which has the exact same state
/// as after processing specified number of zero bytes.
///
/// To simulate the condition after processing huge amount of data
/// (e.g. multiple gigabytes), the way to simulate the state is required.
/// This methods provides one of the ways to do that.
///
/// Starting from [`PartialFNVHash::FNV_HASH_INIT`], it will return to the
/// original state after processing [`ZERO_DATA_PERIOD`] zero bytes, making
/// the state only depend on the size mod [`ZERO_DATA_PERIOD`] (which is `16`).
pub(crate) fn new_hash_with_prefix_zeroes(size: u64) -> PartialFNVHash {
    let mut hash = PartialFNVHash::new();
    for _ in 0..(size % ZERO_DATA_PERIOD) {
        hash.update_by_byte(0);
    }
    hash
}
