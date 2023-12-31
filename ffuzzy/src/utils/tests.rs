// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use crate::utils::{u64_ilog2, u64_lsb_ones};


#[test]
fn u64_ilog2_examples() {
    assert_eq!(u64_ilog2(1), 0);
    assert_eq!(u64_ilog2(2), 1);
    assert_eq!(u64_ilog2(3), 1);
    assert_eq!(u64_ilog2(4), 2);
    assert_eq!(u64_ilog2(5), 2);
    assert_eq!(u64_ilog2(6), 2);
    assert_eq!(u64_ilog2(7), 2);
    assert_eq!(u64_ilog2(8), 3);
    assert_eq!(u64_ilog2(9), 3);
}

#[test]
fn u64_ilog2_near_borders() {
    for n in 1..=(u64::BITS - 1) {
        let border = 1u64 << n;
        assert_eq!(u64_ilog2(border - 1), n - 1, "failed on n={}", n);
        assert_eq!(u64_ilog2(border    ), n,     "failed on n={}", n);
        assert_eq!(u64_ilog2(border + 1), n,     "failed on n={}", n);
    }
}

#[test]
fn u64_lsb_ones_from_binary_string() {
    use std::borrow::ToOwned;
    // Make binary number string "01...1" (with `n` ones), parse and compare
    for n in 0..=u64::BITS {
        let size = usize::try_from(n).unwrap();
        let s = "0".to_owned() + &"1".repeat(size);
        assert_eq!(u64_lsb_ones(n), u64::from_str_radix(s.as_str(), 2).unwrap());
    }
}

#[test]
fn u64_lsb_ones_table() {
    let mut expected_idx = 0;
    let mut assert_next = |n, expected_value| {
        assert_eq!(expected_idx, n);
        assert_eq!(expected_value, u64_lsb_ones(n));
        expected_idx += 1;
    };
    assert_next( 0, 0x0000_0000_0000_0000);
    assert_next( 1, 0x0000_0000_0000_0001);
    assert_next( 2, 0x0000_0000_0000_0003);
    assert_next( 3, 0x0000_0000_0000_0007);
    assert_next( 4, 0x0000_0000_0000_000f);
    assert_next( 5, 0x0000_0000_0000_001f);
    assert_next( 6, 0x0000_0000_0000_003f);
    assert_next( 7, 0x0000_0000_0000_007f);
    assert_next( 8, 0x0000_0000_0000_00ff);
    assert_next( 9, 0x0000_0000_0000_01ff);
    assert_next(10, 0x0000_0000_0000_03ff);
    assert_next(11, 0x0000_0000_0000_07ff);
    assert_next(12, 0x0000_0000_0000_0fff);
    assert_next(13, 0x0000_0000_0000_1fff);
    assert_next(14, 0x0000_0000_0000_3fff);
    assert_next(15, 0x0000_0000_0000_7fff);
    assert_next(16, 0x0000_0000_0000_ffff);
    assert_next(17, 0x0000_0000_0001_ffff);
    assert_next(18, 0x0000_0000_0003_ffff);
    assert_next(19, 0x0000_0000_0007_ffff);
    assert_next(20, 0x0000_0000_000f_ffff);
    assert_next(21, 0x0000_0000_001f_ffff);
    assert_next(22, 0x0000_0000_003f_ffff);
    assert_next(23, 0x0000_0000_007f_ffff);
    assert_next(24, 0x0000_0000_00ff_ffff);
    assert_next(25, 0x0000_0000_01ff_ffff);
    assert_next(26, 0x0000_0000_03ff_ffff);
    assert_next(27, 0x0000_0000_07ff_ffff);
    assert_next(28, 0x0000_0000_0fff_ffff);
    assert_next(29, 0x0000_0000_1fff_ffff);
    assert_next(30, 0x0000_0000_3fff_ffff);
    assert_next(31, 0x0000_0000_7fff_ffff);
    assert_next(32, 0x0000_0000_ffff_ffff);
    assert_next(33, 0x0000_0001_ffff_ffff);
    assert_next(34, 0x0000_0003_ffff_ffff);
    assert_next(35, 0x0000_0007_ffff_ffff);
    assert_next(36, 0x0000_000f_ffff_ffff);
    assert_next(37, 0x0000_001f_ffff_ffff);
    assert_next(38, 0x0000_003f_ffff_ffff);
    assert_next(39, 0x0000_007f_ffff_ffff);
    assert_next(40, 0x0000_00ff_ffff_ffff);
    assert_next(41, 0x0000_01ff_ffff_ffff);
    assert_next(42, 0x0000_03ff_ffff_ffff);
    assert_next(43, 0x0000_07ff_ffff_ffff);
    assert_next(44, 0x0000_0fff_ffff_ffff);
    assert_next(45, 0x0000_1fff_ffff_ffff);
    assert_next(46, 0x0000_3fff_ffff_ffff);
    assert_next(47, 0x0000_7fff_ffff_ffff);
    assert_next(48, 0x0000_ffff_ffff_ffff);
    assert_next(49, 0x0001_ffff_ffff_ffff);
    assert_next(50, 0x0003_ffff_ffff_ffff);
    assert_next(51, 0x0007_ffff_ffff_ffff);
    assert_next(52, 0x000f_ffff_ffff_ffff);
    assert_next(53, 0x001f_ffff_ffff_ffff);
    assert_next(54, 0x003f_ffff_ffff_ffff);
    assert_next(55, 0x007f_ffff_ffff_ffff);
    assert_next(56, 0x00ff_ffff_ffff_ffff);
    assert_next(57, 0x01ff_ffff_ffff_ffff);
    assert_next(58, 0x03ff_ffff_ffff_ffff);
    assert_next(59, 0x07ff_ffff_ffff_ffff);
    assert_next(60, 0x0fff_ffff_ffff_ffff);
    assert_next(61, 0x1fff_ffff_ffff_ffff);
    assert_next(62, 0x3fff_ffff_ffff_ffff);
    assert_next(63, 0x7fff_ffff_ffff_ffff);
    assert_next(64, 0xffff_ffff_ffff_ffff);
    // Make sure that we have checked all the values.
    // Before the last `assert_next` call, expected_idx was u64::BITS (64).
    assert_eq!(expected_idx, u64::BITS + 1);
}

#[test]
fn u64_lsb_ones_and_ilog2() {
    // Test correspondence between LSB ones (2^n-1)
    // and ilog2 (floor(log_2(n))).
    for n in 0..=(u64::BITS - 1) {
        let ones_plus_1 = u64_lsb_ones(n).wrapping_add(1);
        assert!(ones_plus_1.is_power_of_two(), "failed on n={}", n);
        assert_eq!(u64_ilog2(ones_plus_1), n, "failed on n={}", n);
    }
    assert_eq!(u64_lsb_ones(u64::BITS).wrapping_add(1), 0);
}
