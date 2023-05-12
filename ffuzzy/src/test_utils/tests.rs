// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use crate::test_utils::{
    assert_fits_in,
    cover_auto_debug,
    test_auto_clone,
    test_for_each_type,
    test_recommended_default,
};
#[cfg(feature = "alloc")]
use crate::test_utils::test_auto_debug_for_enum;

#[test]
fn auto_clone_valid() {
    #[derive(PartialEq, Eq, Clone, Debug)]
    struct Example(u8);
    test_auto_clone(&Example(1));
    cover_auto_debug(&Example(2));
}

#[test]
#[should_panic]
fn auto_clone_counterexample() {
    #[derive(PartialEq, Eq, Debug)]
    struct Counterexample(u8);
    impl Clone for Counterexample {
        // BROKEN: returns fixed value rather than itself.
        fn clone(&self) -> Self { Self(0) }
    }
    test_auto_clone(&Counterexample(1));
}


#[cfg(feature = "alloc")]
mod test_auto_debug_for_enum {
    use super::*;

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
    fn valid_examples() {
        test_auto_debug_for_enum!(AutoEnumExample, []);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1 ]);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1, ]);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2 ]);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, ]);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, OK3 ]);
        test_auto_debug_for_enum!(AutoEnumExample, [ OK1, OK2, OK3, ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, []);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1 ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2 ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, OK3 ]);
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, OK3, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_01() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_02() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_03() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1 ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_04() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_05() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_06() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_07() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, OK2 ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_08() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ Broken, OK1, OK2, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_09() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, OK2 ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_10() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, Broken, OK2, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_11() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, Broken ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_12() {
        test_auto_debug_for_enum!(DebugImplEnumExample, [ OK1, OK2, Broken, ]);
    }
}


#[test]
fn recommended_default_example() {
    #[derive(PartialEq, Eq, Debug)]
    struct Example(u8);
    impl Example {
        fn new() -> Self { Self(0) }
    }
    impl Default for Example {
        fn default() -> Self { Self::new() }
    }
    test_recommended_default!(Example);
    cover_auto_debug(&Example(1));
}

#[test]
#[should_panic]
fn recommended_default_counterexample() {
    #[derive(PartialEq, Eq, Debug)]
    struct Counterexample(u8);
    impl Counterexample {
        fn new() -> Self { Self(0) }
    }
    impl Default for Counterexample {
        // BROKEN: intentionally different from the result of `new()`.
        fn default() -> Self { Self(1) }
    }
    test_recommended_default!(Counterexample);
}


mod test_for_each_type {
    use super::*;

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
    fn valid_examples() {
        test_for_each_type!(test, []);
        test_for_each_type!(test, [ OKType ]);
        test_for_each_type!(test, [ OKType, ]);
        test_for_each_type!(test, [ OKType, OKType ]);
        test_for_each_type!(test, [ OKType, OKType, ]);
        test_for_each_type!(test, [ OKType, OKType, OKType ]);
        test_for_each_type!(test, [ OKType, OKType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_01() {
        test_for_each_type!(test, [ NGType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_02() {
        test_for_each_type!(test, [ NGType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_03() {
        test_for_each_type!(test, [ NGType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_04() {
        test_for_each_type!(test, [ NGType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_05() {
        test_for_each_type!(test, [ OKType, NGType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_06() {
        test_for_each_type!(test, [ OKType, NGType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_07() {
        test_for_each_type!(test, [ NGType, OKType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_08() {
        test_for_each_type!(test, [ NGType, OKType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_09() {
        test_for_each_type!(test, [ OKType, NGType, OKType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_10() {
        test_for_each_type!(test, [ OKType, NGType, OKType, ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_11() {
        test_for_each_type!(test, [ OKType, OKType, NGType ]);
    }
    #[test]
    #[should_panic]
    fn counterexample_12() {
        test_for_each_type!(test, [ OKType, OKType, NGType, ]);
    }
}


#[test]
fn assert_fits_in_examples() {
    // u8: 0..=255
    assert_fits_in!(  0i32, u8);
    assert_fits_in!(255u16, u8);
    assert_fits_in!(255i16, u8);
    assert_fits_in!(255u32, u8);
    assert_fits_in!(255i32, u8);
    assert_fits_in!(255u64, u8);
    assert_fits_in!(255i64, u8);
    // i8: (-128)..=127
    assert_fits_in!( 127i32, i8);
    assert_fits_in!(   0i32, i8);
    assert_fits_in!(-128i32, i8);
}

#[test]
#[should_panic]
fn assert_fits_in_counterexample_1() {
    assert_fits_in!(256i32, u8);
}
#[test]
#[should_panic]
fn assert_fits_in_counterexample_2() {
    assert_fits_in!(-1i32, u8);
}
#[test]
#[should_panic]
fn assert_fits_in_counterexample_3() {
    assert_fits_in!(-129i32, i8);
}
#[test]
#[should_panic]
fn assert_fits_in_counterexample_4() {
    assert_fits_in!(128i32, i8);
}
