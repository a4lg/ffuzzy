// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023, 2024

//! Compiler intrinsics to control optimization of this crate.

/// Hints to the compiler that branch condition is likely to be [`true`].
///
/// This is a thin wrapper to [`core::intrinsics::likely()`] and requires
/// `#![feature(core_intrinsics)]` when the `unstable` feature is enabled.
#[inline(always)]
pub(crate) fn likely(value_likely_to_be_true: bool) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "unstable")] {
            core::intrinsics::likely(value_likely_to_be_true)
        }
        else {
            value_likely_to_be_true
        }
    }
}

/// Hints to the compiler that branch condition is unlikely to be [`true`].
///
/// This is a thin wrapper to [`core::intrinsics::unlikely()`] and requires
/// `#![feature(core_intrinsics)]` when the `unstable` feature is enabled.
#[inline(always)]
pub(crate) fn unlikely(value_unlikely_to_be_true: bool) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "unstable")] {
            core::intrinsics::unlikely(value_unlikely_to_be_true)
        }
        else {
            value_unlikely_to_be_true
        }
    }
}

mod tests;
