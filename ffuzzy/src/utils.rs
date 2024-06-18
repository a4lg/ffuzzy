// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023, 2024

//! Various internal utilities.

/// Computes the base-2 logarithm (floored) of an [`u64`] value.
///
/// This is the wrapper with fallbacks for stable [`u64::ilog2()`].
///
/// # Development Notes (TODO)
///
/// It will be `const` once MSRV of 1.57 is acceptable.
///
/// Consider removing it once MSRV of 1.67 is acceptable.
#[allow(clippy::incompatible_msrv)]
#[inline(always)]
pub(crate) fn u64_ilog2(value: u64) -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(ffuzzy_ilog2 = "fallback")] {
            // Equiv: library/core/src/num/nonzero.rs (Rust 1.67)
            debug_assert!(value != 0u64);
            u64::BITS - 1 - value.leading_zeros()
        } else {
            u64::ilog2(value)
        }
    }
}

/// Computes the lowest `n` bits of ones and return as an [`u64`] value.
///
/// Note that this function will only check the validity of `n`
/// on the debug build.
///
/// # Development Notes (TODO)
///
/// It will be `const` once MSRV of 1.57 is acceptable.
#[inline(always)]
pub(crate) fn u64_lsb_ones(n: u32) -> u64 {
    debug_assert!(n <= u64::BITS);
    (if n == u64::BITS { 0 } else { 1u64 << n }).wrapping_sub(1)
}

mod tests;
