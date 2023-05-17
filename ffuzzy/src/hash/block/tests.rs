// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::cmp::Ordering;
#[cfg(feature = "alloc")]
use alloc::string::ToString;

use crate::hash::{BlockSize, BlockSizeRelation};


#[test]
fn prerequisites() {
    // NUM_VALID must be a valid u8 value.
    crate::test_utils::assert_fits_in!(BlockSize::NUM_VALID, u8);
}

#[test]
fn block_size_validness_near_the_border() {
    const WIDTH: u32 = 10;
    for log_block_size in 0..BlockSize::NUM_VALID as u8 {
        let block_size = BlockSize::from_log_internal(log_block_size);
        let block_size_prev_plus_1 =
            if log_block_size > 0 {
                BlockSize::from_log_internal(log_block_size - 1) + 1
            }
            else {
                0
            };
        let block_size_next_minus_1 =
            if BlockSize::is_log_valid(log_block_size + 1) {
                BlockSize::from_log_internal(log_block_size + 1) - 1
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
            assert!(!BlockSize::is_valid(bs), "failed on bs={:?}", bs);
        }
        assert!(BlockSize::is_valid(block_size), "failed on block_size={:?}", block_size);
        if block_size == u32::MAX { continue; }
        for bs in
            (block_size + 1)..=u32::min(
                block_size.saturating_add(WIDTH),
                block_size_next_minus_1
            )
        {
            assert!(!BlockSize::is_valid(bs), "failed on bs={:?}", bs);
        }
    }
}

#[cfg(feature = "tests-slow")]
#[test]
fn block_size_validness_all() {
    assert!(!BlockSize::is_valid(0));
    let mut next_log_block_size = 0;
    let mut next_block_size_minus_1 = BlockSize::from_log_internal(next_log_block_size) - 1;
    let mut test_next = false;
    for block_size in u32::MIN..=u32::MAX {
        if test_next {
            assert!(BlockSize::is_valid(block_size),
                "failed on block_size={:?}", block_size);
            test_next = false;
        }
        else {
            assert!(!BlockSize::is_valid(block_size),
                "failed on block_size={:?}", block_size);
        }
        if block_size == next_block_size_minus_1 {
            test_next = true;
            next_log_block_size += 1;
            next_block_size_minus_1 =
                if BlockSize::is_log_valid(next_log_block_size) {
                    BlockSize::from_log_internal(next_log_block_size) - 1
                }
                else {
                    u32::MAX
                };
        }
    }
}

#[test]
fn block_size_log_validness() {
    for log_block_size in 0..BlockSize::NUM_VALID as u8 {
        assert!(BlockSize::is_log_valid(log_block_size),
            "failed on log_block_size={:?}", log_block_size);
        // exp(i)
        let block_size = {
            let block_size_1 = BlockSize::from_log(log_block_size).unwrap();
            let block_size_2 = BlockSize::from_log_internal(log_block_size);
            assert_eq!(block_size_1, block_size_2,
                "failed on log_block_size={:?}", log_block_size);
            #[cfg(feature = "unsafe")]
            unsafe {
                let block_size_3 = BlockSize::from_log_unchecked(log_block_size);
                assert_eq!(block_size_1, block_size_3,
                    "failed on log_block_size={:?}", log_block_size);
            }
            block_size_1
        };
        assert!(BlockSize::is_valid(block_size),
            "failed on log_block_size={:?}", log_block_size);
        // log(exp(i)) == i.
        assert_eq!(
            log_block_size,
            BlockSize::log_from_valid(block_size),
            "failed on log_block_size={:?}", log_block_size
        );
        assert_eq!(
            log_block_size,
            BlockSize::log_from_valid_internal(block_size),
            "failed on log_block_size={:?}", log_block_size
        );
        #[cfg(feature = "unsafe")]
        unsafe {
            assert_eq!(
                log_block_size,
                BlockSize::log_from_valid_unchecked(block_size),
                "failed on log_block_size={:?}", log_block_size
            );
        }
        // Relations with BlockSize::MIN
        assert_eq!(block_size % BlockSize::MIN, 0,
            "failed on log_block_size={:?}", log_block_size);
        assert!((block_size / BlockSize::MIN).is_power_of_two(),
            "failed on log_block_size={:?}", log_block_size);
        assert_eq!(
            u8::try_from(crate::utils::u64_ilog2((block_size / BlockSize::MIN) as u64)).unwrap(),
            log_block_size,
            "failed on log_block_size={:?}", log_block_size);
    }
}

#[test]
fn block_size_log_invalid() {
    for log_block_size in BlockSize::NUM_VALID as u8..=u8::MAX {
        assert!(!BlockSize::is_log_valid(log_block_size),
            "failed on log_block_size={:?}", log_block_size);
        assert_eq!(BlockSize::from_log(log_block_size), None,
            "failed on log_block_size={:?}", log_block_size);
    }
}

#[test]
fn block_size_strings() {
    // Prerequisites
    assert_eq!(BlockSize::NUM_VALID, BlockSize::BLOCK_SIZES_STR.len());
    // Test all valid *base-2 logarithm* values.
    for log_block_size in 0..BlockSize::NUM_VALID {
        // BLOCK_SIZES_STR[i] must have direct correspondence with valid block size.
        let block_size = BlockSize::from_log(log_block_size as u8).unwrap();
        let block_size_from_str: u32 = str::parse(BlockSize::BLOCK_SIZES_STR[log_block_size]).unwrap();
        assert_eq!(block_size, block_size_from_str,
            "failed on log_block_size={:?}", log_block_size);
        // The length must be bounded by MAX_BLOCK_SIZE_LEN_IN_CHARS.
        assert!(BlockSize::BLOCK_SIZES_STR[log_block_size].len() <= BlockSize::MAX_BLOCK_SIZE_LEN_IN_CHARS,
            "failed on log_block_size={:?}", log_block_size);
        #[cfg(feature = "alloc")]
        {
            assert_eq!(BlockSize::BLOCK_SIZES_STR[log_block_size], block_size.to_string(),
                "failed on log_block_size={:?}", log_block_size);
        }
    }
}


#[test]
fn block_size_relation_impls() {
    // Test Clone
    crate::test_utils::test_auto_clone::<BlockSizeRelation>(&BlockSizeRelation::Far);
    #[cfg(feature = "alloc")]
    {
        // Test Debug
        crate::test_utils::test_auto_debug_for_enum!(
            BlockSizeRelation, [Far, NearEq, NearGt, NearLt]
        );
    }
}

#[test]
fn block_size_relation_consistency() {
    for bs1 in 0..BlockSize::NUM_VALID as u8 {
        for bs2 in 0..BlockSize::NUM_VALID as u8 {
            // Use cmp.
            let ord = BlockSize::cmp(bs1, bs2);
            match ord {
                Ordering::Equal   => assert!(bs1 == bs2, "failed on bs1={:?}, bs2={:?}", bs1, bs2),
                Ordering::Less    => assert!(bs1 < bs2,  "failed on bs1={:?}, bs2={:?}", bs1, bs2),
                Ordering::Greater => assert!(bs1 > bs2,  "failed on bs1={:?}, bs2={:?}", bs1, bs2),
            }
            // Use compare_sizes.
            let rel = BlockSize::compare_sizes(bs1, bs2);
            // Test consistency between logical expressions and the BlockSizeRelation value.
            // TODO: Replace plain subtraction with abs_diff when MSRV 1.60 is acceptable.
            assert_eq!(bs1 == bs2, rel == BlockSizeRelation::NearEq,     "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(bs1 == bs2 + 1, rel == BlockSizeRelation::NearGt, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(bs1 + 1 == bs2, rel == BlockSizeRelation::NearLt, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(((bs1 as i32) - (bs2 as i32)).abs() > 1, rel == BlockSizeRelation::Far,
                "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            // Test consistency between the result of other functions and the BlockSizeRelation value.
            #[allow(clippy::bool_assert_comparison)]
            match rel {
                BlockSizeRelation::Far => {
                    assert_eq!(rel.is_near(), false,                   "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near(bs1, bs2), false,    "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_lt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_eq(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_gt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_ne!(ord, Ordering::Equal,                   "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                }
                BlockSizeRelation::NearLt => {
                    assert_eq!(rel.is_near(), true,                    "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near(bs1, bs2), true,     "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_lt(bs1, bs2), true,  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_eq(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_gt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(ord, Ordering::Less,                    "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                }
                BlockSizeRelation::NearEq => {
                    assert_eq!(rel.is_near(), true,                    "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near(bs1, bs2), true,     "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_lt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_eq(bs1, bs2), true,  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_gt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(ord, Ordering::Equal,                   "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                }
                BlockSizeRelation::NearGt => {
                    assert_eq!(rel.is_near(), true,                    "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near(bs1, bs2), true,     "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_lt(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_eq(bs1, bs2), false, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(BlockSize::is_near_gt(bs1, bs2), true,  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(ord, Ordering::Greater,                 "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                }
            }
        }
    }
}
