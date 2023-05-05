// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023


/// Computes the base-2 logarithm (floored) of an [`u64`] value.
///
/// This is the wrapper with fallbacks for stable [`u64::ilog2()`].
///
/// # Development Notes (TODO)
///
/// Consider removing it once MSRV of 1.67 is acceptable.
#[inline(always)]
pub(crate) fn u64_ilog2(value: u64) -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(ffuzzy_ilog2 = "fallback")] {
            {
                // Equiv: library/core/src/num/nonzero.rs (Rust 1.67)
                debug_assert!(value != 0u64);
                u64::BITS - 1 - value.leading_zeros()
            }
        }
        else if #[cfg(ffuzzy_ilog2 = "unstable_v1")] {
            u64::log2(value)
        }
        else {
            u64::ilog2(value)
        }
    }
}


/// Computes the lowest `n` bits of ones and return as an [`u64`] value.
///
/// Note that this function will only check the validity of `n`
/// on the debug build.
#[inline(always)]
pub(crate) fn u64_lsb_ones(n: u32) -> u64 {
    debug_assert!(n <= 64);
    (if n == 64 { 0 } else { 1u64 << n }).wrapping_sub(1)
}





// grcov-excl-br-start
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_ilog2_examples() {
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
    fn test_u64_ilog2_borders() {
        for n in 1..=(u64::BITS - 1) {
            let border = 1u64 << n;
            assert_eq!(u64_ilog2(border - 1), n - 1, "failed on {}", n);
            assert_eq!(u64_ilog2(border    ), n,     "failed on {}", n);
            assert_eq!(u64_ilog2(border + 1), n,     "failed on {}", n);
        }
    }

    #[test]
    fn test_u64_lsb_ones_table() {
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
    fn test_u64_lsb_ones_and_ilog2() {
        // Test correspondence between LSB ones (2^n-1)
        // and ilog2 (floor(log_2(n))).
        for n in 0..=(u64::BITS - 1) {
            let ones_plus_1 = u64_lsb_ones(n).wrapping_add(1);
            assert!(ones_plus_1.is_power_of_two(), "failed on {}", n);
            assert_eq!(u64_ilog2(ones_plus_1), n, "failed on {}", n);
        }
        assert_eq!(u64_lsb_ones(u64::BITS).wrapping_add(1), 0);
    }
}
// grcov-excl-br-end
