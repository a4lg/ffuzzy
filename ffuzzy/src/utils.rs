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
}
// grcov-excl-br-end
