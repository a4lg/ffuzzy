// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023
// grcov-excl-br-start

#![cfg(any(test, doc))]


/// Testing function for [`Default`] (for coverage).
///
/// This function is suitable if we have no particularly useful way to
/// check if certain properties of the default value is satisfied.
///
/// In other words, this function is for coverage tests.
pub(crate) fn cover_default<T: Default>() {
    let _value1 = T::default();
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
    cloned.clone_from(&orig_value);
    assert_eq!(*orig_value, cloned);
}


/// Test automatically generated [`Debug`](core::fmt::Debug)
/// implementation of an enum with no variants with structs or tuples.
#[cfg(feature = "alloc")]
#[doc(alias = "test_auto_debug_for_enum")]
macro_rules! test_auto_debug_for_enum_impl {
    ($ty: ty, []) => {};
    ($ty: ty, [$var: ident]) => {{
        assert_eq!(alloc::format!("{:?}", <$ty>::$var), stringify!($var));
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
        assert!(<$ty>::try_from($expr).is_ok())
    };
}

#[cfg(feature = "alloc")]
pub(crate) use test_auto_debug_for_enum_impl as test_auto_debug_for_enum;
pub(crate) use test_recommended_default_impl as test_recommended_default;
pub(crate) use test_for_each_type_impl as test_for_each_type;
pub(crate) use assert_fits_in_impl as assert_fits_in;





// grcov-excl-br-start
#[cfg(test)]
mod tests {
    #[test]
    fn test_auto_clone() {
        #[derive(PartialEq, Eq, Clone, Debug)]
        struct Example(u8);
        super::test_auto_clone(&Example(1));
    }

    #[test]
    #[should_panic]
    fn test_auto_clone_counterexample() {
        #[derive(PartialEq, Eq, Debug)]
        struct Counterexample(u8);
        impl Clone for Counterexample {
            // BROKEN: returns fixed value rather than itself.
            fn clone(&self) -> Self { Self(0) }
        }
        super::test_auto_clone(&Counterexample(1));
    }

    #[derive(Debug)]
    enum AutoEnumExample {
        OK1,
        OK2,
        OK3,
    }
    enum DebugImplEnumExample {
        OK1,
        OK2,
        OK3,
        Broken,
    }
    impl core::fmt::Debug for DebugImplEnumExample {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                // Matches to the auto-generated implementation.
                Self::OK1 => write!(f, "OK1"),
                Self::OK2 => write!(f, "OK2"),
                Self::OK3 => write!(f, "OK3"),
                // BROKEN: it does not match.
                // We could test enums with tuples or structs but that would
                // only make mostly duplicate test cases.
                Self::Broken => write!(f, "I_SAID_BROKEN"),
            }
        }
    }
    #[test]
    fn test_auto_debug_for_enum() {
        super::test_auto_debug_for_enum!(AutoEnumExample, []);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1 ]);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1, ]);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2 ]);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, ]);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, OK3 ]);
        super::test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, OK3, ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, []);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1 ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2 ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, OK3 ]);
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, OK3, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_01() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_02() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_03() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1 ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_04() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_05() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_06() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_07() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, OK2 ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_08() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, OK2, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_09() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, OK2 ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_10() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, OK2, ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_11() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, Broken ]);
    }
    #[test]
    #[should_panic]
    fn test_auto_debug_for_enum_counterexample_12() {
        super::test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, Broken, ]);
    }


    #[test]
    fn test_recommended_default() {
        #[derive(PartialEq, Eq, Debug)]
        struct Example(u8);
        impl Example {
            fn new() -> Self { Self(0) }
        }
        impl Default for Example {
            fn default() -> Self { Self::new() }
        }
        super::test_recommended_default!(Example);
    }

    #[test]
    #[should_panic]
    fn test_recommended_default_counterexample() {
        #[derive(PartialEq, Eq, Debug)]
        struct Counterexample(u8);
        impl Counterexample {
            fn new() -> Self { Self(0) }
        }
        impl Default for Counterexample {
            // BROKEN: intentionally different from the result of `new()`.
            fn default() -> Self { Self(1) }
        }
        super::test_recommended_default!(Counterexample);
    }


    struct TestTargetType<const IS_OK: bool>;
    impl<const IS_OK: bool> TestTargetType<IS_OK> {
        const IS_OK: bool = IS_OK;
    }
    type OKType = TestTargetType<true>;
    type NGType = TestTargetType<false>;
    macro_rules! test {
        ($ty: ty) => {
            // Passing `NGType` will cause an assertion failure.
            assert!(<$ty>::IS_OK);
        };
    }

    #[test]
    fn test_for_each_type() {
        super::test_for_each_type!(test, []);
        super::test_for_each_type!(test, [ OKType ]);
        super::test_for_each_type!(test, [ OKType, ]);
        super::test_for_each_type!(test, [ OKType, OKType ]);
        super::test_for_each_type!(test, [ OKType, OKType, ]);
        super::test_for_each_type!(test, [ OKType, OKType, OKType ]);
        super::test_for_each_type!(test, [ OKType, OKType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_01() {
        super::test_for_each_type!(test, [ NGType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_02() {
        super::test_for_each_type!(test, [ NGType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_03() {
        super::test_for_each_type!(test, [ NGType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_04() {
        super::test_for_each_type!(test, [ NGType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_05() {
        super::test_for_each_type!(test, [ OKType, NGType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_06() {
        super::test_for_each_type!(test, [ OKType, NGType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_07() {
        super::test_for_each_type!(test, [ NGType, OKType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_08() {
        super::test_for_each_type!(test, [ NGType, OKType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_09() {
        super::test_for_each_type!(test, [ OKType, NGType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_10() {
        super::test_for_each_type!(test, [ OKType, NGType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_11() {
        super::test_for_each_type!(test, [ OKType, OKType, NGType ]);
    }
    #[test]
    #[should_panic]
    fn test_for_each_type_counterexample_12() {
        super::test_for_each_type!(test, [ OKType, OKType, NGType, ]);
    }


    #[test]
    fn test_assert_fits_in() {
        // u8: 0..=255
        super::assert_fits_in!(  0i32, u8);
        super::assert_fits_in!(255u16, u8);
        super::assert_fits_in!(255i16, u8);
        super::assert_fits_in!(255u32, u8);
        super::assert_fits_in!(255i32, u8);
        super::assert_fits_in!(255u64, u8);
        super::assert_fits_in!(255i64, u8);
        // i8: (-128)..=127
        super::assert_fits_in!( 127i32, i8);
        super::assert_fits_in!(   0i32, i8);
        super::assert_fits_in!(-128i32, i8);
    }

    #[test]
    #[should_panic]
    fn test_assert_fits_in_counterexample_1() {
        super::assert_fits_in!(256i32, u8);
    }
    #[test]
    #[should_panic]
    fn test_assert_fits_in_counterexample_2() {
        super::assert_fits_in!(-1i32, u8);
    }
    #[test]
    #[should_panic]
    fn test_assert_fits_in_counterexample_3() {
        super::assert_fits_in!(-129i32, i8);
    }
    #[test]
    #[should_panic]
    fn test_assert_fits_in_counterexample_4() {
        super::assert_fits_in!(128i32, i8);
    }
}
// grcov-excl-br-end
