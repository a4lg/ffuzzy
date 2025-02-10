// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023, 2024

//! Test utilities.

#![cfg(any(test, doc))]
#![cfg_attr(feature = "unstable", doc(cfg(test)))]

/// Check whether two slices are completely the same, including the address
/// they are pointing.
///
/// On some cases, comparing the slices aren't just enough because either of
/// the operands may originate from a superset of another.
///
/// Note that returning `true` implies `a == b` (but it also means that
/// two slices share the pointer).
pub(crate) fn eq_slice_buf<T>(a: &[T], b: &[T]) -> bool {
    a.as_ptr() == b.as_ptr() && a.len() == b.len()
}

/// Test whether the expression fits in the specified type.
#[doc(alias = "assert_fits_in")]
macro_rules! assert_fits_in_impl {
    ($expr: expr, $ty: ty) => {
        assert!(<$ty>::try_from($expr).is_ok(), "{} does not fit into {}", stringify!($expr), stringify!($ty))
    };
    ($expr: expr, $ty: ty, $($arg: tt)+) => {
        assert!(<$ty>::try_from($expr).is_ok(), $($arg)+)
    };
}

/// Test for each type.
///
/// Specify `id` without trailing `!`.
#[doc(alias = "test_for_each_type")]
macro_rules! test_for_each_type_impl {
    ($id: path, [$($($ty: ty),+ $(,)?)?]) => {
        $($(
            loop {
                $id!($ty);
                break;
            }
        )+)?
    };
}

/// Test recommended [`Default`] implementation.
#[doc(alias = "test_recommended_default")]
macro_rules! test_recommended_default_impl {
    ($ty: ty) => {{
        let value1 = <$ty>::new();
        let value2 = <$ty>::default();
        assert_eq!(value1, value2);
    }};
}

pub(crate) use assert_fits_in_impl as assert_fits_in;
pub(crate) use test_for_each_type_impl as test_for_each_type;
pub(crate) use test_recommended_default_impl as test_recommended_default;

mod tests;
