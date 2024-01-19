// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::cmp::Ordering;
use core::ops::{Range, RangeInclusive};

use crate::hash::block::{block_size, block_hash, BlockSizeRelation};
use crate::test_utils::assert_fits_in;


#[test]
fn prerequisites() {
    // NUM_VALID must be a valid u8 value.
    assert_fits_in!(block_size::NUM_VALID, u8);
}


const RANGE_LOG_VALID:   Range<u8> = 0..block_size::NUM_VALID as u8;
const RANGE_LOG_INVALID: RangeInclusive<u8> = block_size::NUM_VALID as u8..=u8::MAX;

#[test]
fn block_size_log_whole_range() {
    for log_block_size in u8::MIN..=u8::MAX {
        // Make sure that those two ranges are mutually exclusive.
        assert_ne!(
            RANGE_LOG_VALID.contains(&log_block_size),
            RANGE_LOG_INVALID.contains(&log_block_size),
            "failed on log_block_size={}", log_block_size
        );
    }
}

#[test]
fn block_size_validness_near_the_border() {
    const WIDTH: u32 = 10;
    for log_block_size in RANGE_LOG_VALID {
        let block_size = block_size::from_log_internal(log_block_size);
        let block_size_prev_plus_1 =
            if log_block_size > 0 {
                block_size::from_log_internal(log_block_size - 1) + 1
            }
            else {
                0
            };
        let block_size_next_minus_1 =
            if block_size::is_log_valid(log_block_size + 1) {
                block_size::from_log_internal(log_block_size + 1) - 1
            }
            else {
                u32::MAX
            };
        for bs in
            u32::max(
                block_size.saturating_sub(WIDTH),
                block_size_prev_plus_1
            )..block_size
        {
            assert!(!block_size::is_valid(bs), "failed on bs={}", bs);
        }
        assert!(block_size::is_valid(block_size), "failed on block_size={}", block_size);
        if block_size == u32::MAX { continue; }
        for bs in
            (block_size + 1)..=u32::min(
                block_size.saturating_add(WIDTH),
                block_size_next_minus_1
            )
        {
            assert!(!block_size::is_valid(bs), "failed on bs={}", bs);
        }
    }
}

#[cfg(feature = "tests-slow")]
#[test]
fn block_size_validness_all() {
    assert!(!block_size::is_valid(0));
    let mut num_valid_total = 0;
    let mut next_log_block_size = 0;
    let mut next_bs_minus_1 = block_size::from_log_internal(next_log_block_size) - 1;
    let mut test_next = false;
    for bs in u32::MIN..=u32::MAX {
        let test_curr = test_next;
        test_next = false;
        assert_eq!(block_size::is_valid(bs), test_curr, "failed on bs={}", bs);
        if test_curr {
            let log_block_size = next_log_block_size - 1;
            assert!(block_size::is_log_valid(log_block_size), "failed on bs={}", bs);
            assert_eq!(block_size::log_from_valid(bs), log_block_size, "failed on bs={}", bs);
            num_valid_total += 1;
        }
        if bs == next_bs_minus_1 {
            test_next = true;
            next_log_block_size += 1;
            next_bs_minus_1 =
                if block_size::is_log_valid(next_log_block_size) {
                    block_size::from_log_internal(next_log_block_size) - 1
                }
                else {
                    u32::MAX // next valid value does not exist (breaks before checking).
                };
        }
    }
    assert_eq!(num_valid_total, block_size::NUM_VALID);
}

#[test]
fn block_size_log_valid() {
    for log_block_size in RANGE_LOG_VALID {
        assert!(block_size::is_log_valid(log_block_size), "failed on log_block_size={}", log_block_size);
        // exp(i)
        let bs = {
            let bs_1 = block_size::from_log(log_block_size).unwrap();
            let bs_2 = block_size::from_log_internal(log_block_size);
            assert_eq!(bs_1, bs_2, "failed on log_block_size={}", log_block_size);
            #[cfg(feature = "unchecked")]
            unsafe {
                let bs_3 = block_size::from_log_unchecked(log_block_size);
                assert_eq!(bs_1, bs_3, "failed on log_block_size={}", log_block_size);
            }
            bs_1
        };
        assert!(block_size::is_valid(bs), "failed on log_block_size={}", log_block_size);
        // log(exp(i)) == i.
        assert_eq!(log_block_size, block_size::log_from_valid(bs), "failed on log_block_size={}", log_block_size);
        assert_eq!(log_block_size, block_size::log_from_valid_internal(bs), "failed on log_block_size={}", log_block_size);
        #[cfg(feature = "unchecked")]
        unsafe {
            assert_eq!(
                log_block_size,
                block_size::log_from_valid_unchecked(bs),
                "failed on log_block_size={}", log_block_size
            );
        }
        // Relations with block_size::MIN
        assert_eq!(bs % block_size::MIN, 0, "failed on log_block_size={}", log_block_size);
        assert!((bs / block_size::MIN).is_power_of_two(), "failed on log_block_size={}", log_block_size);
        assert_eq!(
            u8::try_from(crate::utils::u64_ilog2((bs / block_size::MIN) as u64)).unwrap(),
            log_block_size,
            "failed on log_block_size={}", log_block_size
        );
    }
}

#[test]
fn block_size_log_invalid() {
    for log_block_size in RANGE_LOG_INVALID {
        assert!(!block_size::is_log_valid(log_block_size), "failed on log_block_size={}", log_block_size);
        assert_eq!(block_size::from_log(log_block_size), None, "failed on log_block_size={}", log_block_size);
    }
}

#[test]
fn block_size_strings() {
    use alloc::string::ToString;
    // Prerequisites
    assert_eq!(block_size::NUM_VALID, block_size::BLOCK_SIZES_STR.len());
    // Test all valid *base-2 logarithm* values.
    for log_block_size_raw in RANGE_LOG_VALID {
        let log_block_size = log_block_size_raw as usize;
        // BLOCK_SIZES_STR[i] must have direct correspondence with valid block size.
        let block_size = block_size::from_log(log_block_size_raw).unwrap();
        let block_size_from_str: u32 = str::parse(block_size::BLOCK_SIZES_STR[log_block_size]).unwrap();
        assert_eq!(block_size, block_size_from_str, "failed on log_block_size={}", log_block_size);
        // The length must be bounded by MAX_BLOCK_SIZE_LEN_IN_CHARS.
        assert!(block_size::BLOCK_SIZES_STR[log_block_size].len() <= block_size::MAX_BLOCK_SIZE_LEN_IN_CHARS,
            "failed on log_block_size={}", log_block_size);
        assert_eq!(block_size::BLOCK_SIZES_STR[log_block_size], block_size.to_string(),
            "failed on log_block_size={}", log_block_size);
    }
}


#[test]
fn block_size_relation_impls() {
    // Test Clone
    crate::test_utils::test_auto_clone::<BlockSizeRelation>(&BlockSizeRelation::Far);
    // Test Debug
    crate::test_utils::test_auto_debug_for_enum!(
        BlockSizeRelation, [Far, NearEq, NearGt, NearLt]
    );
}

#[test]
fn block_size_relation_consistency() {
    for bs1 in RANGE_LOG_VALID {
        for bs2 in RANGE_LOG_VALID {
            // Use cmp.
            let ord = block_size::cmp(bs1, bs2);
            match ord {
                Ordering::Equal   => assert!(bs1 == bs2, "failed on bs1={}, bs2={}", bs1, bs2),
                Ordering::Less    => assert!(bs1 < bs2,  "failed on bs1={}, bs2={}", bs1, bs2),
                Ordering::Greater => assert!(bs1 > bs2,  "failed on bs1={}, bs2={}", bs1, bs2),
            }
            // Use compare_sizes.
            let rel = block_size::compare_sizes(bs1, bs2);
            // Test consistency between logical expressions and the BlockSizeRelation value.
            // TODO: Replace plain subtraction with abs_diff when MSRV 1.60 is acceptable.
            assert_eq!(bs1 == bs2, rel == BlockSizeRelation::NearEq,     "failed on bs1={}, bs2={}", bs1, bs2);
            assert_eq!(bs1 == bs2 + 1, rel == BlockSizeRelation::NearGt, "failed on bs1={}, bs2={}", bs1, bs2);
            assert_eq!(bs1 + 1 == bs2, rel == BlockSizeRelation::NearLt, "failed on bs1={}, bs2={}", bs1, bs2);
            assert_eq!(((bs1 as i32) - (bs2 as i32)).abs() > 1, rel == BlockSizeRelation::Far,
                "failed on bs1={}, bs2={}", bs1, bs2);
            // Test consistency between the result of other functions and the BlockSizeRelation value.
            #[allow(clippy::bool_assert_comparison)]
            match rel {
                BlockSizeRelation::Far => {
                    assert_eq!(rel.is_near(), false,                    "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near(bs1, bs2), false,    "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_lt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_eq(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_gt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_ne!(ord, Ordering::Equal,                    "failed on bs1={}, bs2={}", bs1, bs2);
                }
                BlockSizeRelation::NearLt => {
                    assert_eq!(rel.is_near(), true,                     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near(bs1, bs2), true,     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_lt(bs1, bs2), true,  "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_eq(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_gt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(ord, Ordering::Less,                     "failed on bs1={}, bs2={}", bs1, bs2);
                }
                BlockSizeRelation::NearEq => {
                    assert_eq!(rel.is_near(), true,                     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near(bs1, bs2), true,     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_lt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_eq(bs1, bs2), true,  "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_gt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(ord, Ordering::Equal,                    "failed on bs1={}, bs2={}", bs1, bs2);
                }
                BlockSizeRelation::NearGt => {
                    assert_eq!(rel.is_near(), true,                     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near(bs1, bs2), true,     "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_lt(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_eq(bs1, bs2), false, "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(block_size::is_near_gt(bs1, bs2), true,  "failed on bs1={}, bs2={}", bs1, bs2);
                    assert_eq!(ord, Ordering::Greater,                  "failed on bs1={}, bs2={}", bs1, bs2);
                }
            }
        }
    }
}


#[test]
fn block_hash_numeric_window_prerequisites() {
    // Note:
    // Some depends on the current MSRV.  If we update the MSRV,
    // we may need to change here (and/or remove some of the tests).
    assert!(block_hash::ALPHABET_SIZE.is_power_of_two());
    assert_eq!(1usize.checked_shl(block_hash::NumericWindows::ILOG2_OF_ALPHABETS).unwrap(), block_hash::ALPHABET_SIZE);
    assert_fits_in!(block_hash::MIN_LCS_FOR_COMPARISON, u32);
    let bits = (block_hash::MIN_LCS_FOR_COMPARISON as u32).checked_mul(block_hash::NumericWindows::ILOG2_OF_ALPHABETS).unwrap();
    assert_eq!(block_hash::NumericWindows::BITS, bits);
    assert_eq!(block_hash::NumericWindows::MASK, crate::utils::u64_lsb_ones(bits));
}
