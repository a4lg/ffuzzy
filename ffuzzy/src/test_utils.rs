// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023
// grcov-excl-br-start

#![cfg(any(test, doc))]


#[cfg(test)]
mod tests;


/// Testing function for [`Default`] (for coverage).
///
/// This function is suitable if we have no particularly useful way to
/// check if certain properties of the default value is satisfied.
///
/// In other words, this function is for coverage tests.
pub(crate) fn cover_default<T: Default>() {
    let _value = T::default();
}


/// Testing function for [`Clone`] (for coverage).
///
/// This function is suitable if we have no comparison function for these.
///
/// In other words, this function is for coverage tests.
pub(crate) fn cover_auto_clone<T: Clone>(orig_value: &T) {
    let mut cloned: T = orig_value.clone();
    cloned.clone_from(orig_value);
}


/// Testing function for [`Eq`] + [`Clone`].
///
/// It also requires [`core::fmt::Debug`] for assertion.
pub(crate) fn test_auto_clone<T: Clone + Eq + core::fmt::Debug>(orig_value: &T) {
    let mut cloned: T = orig_value.clone();
    assert_eq!(*orig_value, cloned);
    cloned.clone_from(orig_value);
    assert_eq!(*orig_value, cloned);
}


/// Testing function for [`Debug`](core::fmt::Debug) (for coverage).
///
/// If an allocator is available, cover debug output.
pub(crate) fn cover_auto_debug<T: core::fmt::Debug>(_value: &T) {
    #[cfg(feature = "alloc")]
    {
        let _ = alloc::format!("{:?}", _value);
    }
}


/// Test automatically generated [`Debug`](core::fmt::Debug)
/// implementation of an enum with no variants with structs or tuples.
#[cfg(feature = "alloc")]
#[doc(alias = "test_auto_debug_for_enum")]
macro_rules! test_auto_debug_for_enum_impl {
    ($ty: ty, []) => {};
    ($ty: ty, [$var: ident]) => {{
        assert_eq!(::alloc::format!("{:?}", <$ty>::$var), stringify!($var));
    }};
    ($ty: ty, [$var: ident, $($rest: ident),+]) => {
        $crate::test_utils::test_auto_debug_for_enum!($ty, [$var]);
        $crate::test_utils::test_auto_debug_for_enum!($ty, [$($rest),+]);
    };
    ($ty: ty, [$var: ident,]) => {
        $crate::test_utils::test_auto_debug_for_enum!($ty, [$var]);
    };
    ($ty: ty, [$var: ident, $($rest: ident),+,]) => {
        $crate::test_utils::test_auto_debug_for_enum!($ty, [$var, $($rest),+]);
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

/// Test for each type.
#[doc(alias = "test_for_each_type")]
macro_rules! test_for_each_type_impl {
    ($test: ident, []) => {};
    ($test: ident, [$ty: ty]) => {
        loop {
            $test!($ty);
            break;
        }
    };
    ($test: ident, [$ty: ty, $($rest: ty),+]) => {
        $crate::test_utils::test_for_each_type!($test, [$ty]);
        $crate::test_utils::test_for_each_type!($test, [$($rest),+]);
    };
    ($test: ident, [$ty: ty,]) => {
        $crate::test_utils::test_for_each_type!($test, [$ty]);
    };
    ($test: ident, [$ty: ty, $($rest: ty),+,]) => {
        $crate::test_utils::test_for_each_type!($test, [$ty, $($rest),+]);
    };
}

/// Test whether the expression fits in the specified type.
#[doc(alias = "assert_fits_in")]
macro_rules! assert_fits_in_impl {
    ($expr: expr, $ty: ty) => {
        assert!(<$ty>::try_from($expr).is_ok(), "{} does not fit into {}", stringify!($expr), stringify!($ty))
    };
    ($expr: expr, $ty: ty, $($arg:tt)+) => {
        assert!(<$ty>::try_from($expr).is_ok(), $($arg)+)
    };
}

#[cfg(feature = "alloc")]
pub(crate) use test_auto_debug_for_enum_impl as test_auto_debug_for_enum;
pub(crate) use test_recommended_default_impl as test_recommended_default;
pub(crate) use test_for_each_type_impl as test_for_each_type;
pub(crate) use assert_fits_in_impl as assert_fits_in;
