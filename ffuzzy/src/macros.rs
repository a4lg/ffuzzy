// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023, 2024

//! Internal macros (mainly to share safe/unsafe code).

/// "Optionally" unsafe block.
///
/// When this crate is built with the `unsafe` feature, this macro is
/// expanded to an `unsafe` block.
///
/// Inside this block, you may place statements that may change the behavior
/// depending on the feature `unsafe`.  For instance, you may place
/// [`invariant!()`] inside this block.
///
/// ```ignore
/// # // Because this is an internal macro, we must ignore on the doctest
/// # // because each Rust doctest's scope is external to this crate.
/// // INTERNAL USE (INSIDE THIS CRATE) ONLY
/// // let index: usize = ... (but proven to be inside the array).
/// # let index = 3usize;
/// let array = [0, 1, 2, 3];
/// optionally_unsafe! {
///     invariant!(index < array.len());
/// }
/// // Bound checking may be optimized out.
/// let result = array[index];
/// ```
#[doc(alias = "optionally_unsafe")]
macro_rules! optionally_unsafe_impl {
    {$($tokens: tt)*} => {
        cfg_if::cfg_if! {
            if #[cfg(feature = "unsafe")] {
                unsafe { $($tokens)* }
            }
            else {
                { $($tokens)* }
            }
        }
    };
}
pub(crate) use optionally_unsafe_impl as optionally_unsafe;

/// Declare an invariant for optimization.
///
/// When the feature `unsafe` is disabled, it only places [`debug_assert!()`].
/// If both `unsafe` and `unstable` are enabled, [`core::hint::assert_unchecked()`]
/// is used (which requires the `hint_assert_unchecked` Rust unstable feature).
/// If only the `unsafe` feature is enabled,
/// [`core::hint::unreachable_unchecked()`] is used.
///
/// If `unsafe` and `unstable` are enabled, enable unstable
/// `hint_assert_unchecked` feature.
///
/// Optimization behaviors are disabled on tests.
///
/// Use this macro along with [`optionally_unsafe!{}`].
#[doc(alias = "invariant")]
macro_rules! invariant_impl {
    ($expr: expr) => {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "unsafe", feature = "unstable", not(test)))] {
                core::hint::assert_unchecked($expr);
            }
            else if #[cfg(all(feature = "unsafe", not(test)))] {
                if !($expr) {
                    core::hint::unreachable_unchecked();
                }
            }
            else {
                debug_assert!($expr);
            }
        }
    };
}
pub(crate) use invariant_impl as invariant;

mod tests;
