// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023–2025

//! Compiler intrinsics to control optimization of this crate.

use cfg_if::cfg_if;

/// Hints to the compiler that branch condition is likely to be [`true`].
///
/// This is a thin wrapper to [`core::hint::likely()`] and requires
/// `#![feature(likely_unlikely)]` when the `unstable` feature is enabled.
#[inline(always)]
pub(crate) const fn likely(b: bool) -> bool {
    cfg_if! {
        if #[cfg(feature = "unstable")] {
            core::hint::likely(b)
        } else {
            b
        }
    }
}

/// Hints to the compiler that branch condition is unlikely to be [`true`].
///
/// This is a thin wrapper to [`core::hint::unlikely()`] and requires
/// `#![feature(likely_unlikely)]` when the `unstable` feature is enabled.
#[inline(always)]
pub(crate) const fn unlikely(b: bool) -> bool {
    cfg_if! {
        if #[cfg(feature = "unstable")] {
            core::hint::unlikely(b)
        } else {
            b
        }
    }
}

mod tests;
