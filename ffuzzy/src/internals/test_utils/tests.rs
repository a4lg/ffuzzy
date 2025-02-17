// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::internals::test_utils`].

#![cfg(test)]

use super::{eq_slice_buf, test_recommended_default};

#[test]
fn test_eq_slice_buf_not_eq() {
    const A: &[u8] = b"@ABCDEF@";
    const B: &[u8] = b"_ABCDEF_";
    assert_eq!(&A[1..7], b"ABCDEF");
    // Even the contents are the same (b"ABCDEF"),
    // they don't point to the same memory location.
    assert_eq!(&A[1..7], &B[1..7]);
    assert!(!eq_slice_buf(&A[1..7], &B[1..7]));
}

#[test]
fn recommended_default_example() {
    #[derive(PartialEq, Eq, Debug)]
    struct Example(u8);
    impl Example {
        fn new() -> Self {
            Self(0)
        }
    }
    impl Default for Example {
        fn default() -> Self {
            Self::new()
        }
    }
    test_recommended_default!(Example);
}

#[test]
#[should_panic]
fn recommended_default_counterexample() {
    #[derive(PartialEq, Eq, Debug)]
    struct Counterexample(u8);
    impl Counterexample {
        fn new() -> Self {
            Self(0)
        }
    }
    impl Default for Counterexample {
        // BROKEN: intentionally different from the result of `new()`.
        fn default() -> Self {
            Self(1)
        }
    }
    test_recommended_default!(Counterexample);
}

mod test_for_each_type {
    use crate::internals::test_utils::test_for_each_type;

    struct TestTargetType<const IS_OK: bool>;
    impl<const IS_OK: bool> TestTargetType<IS_OK> {
        const IS_OK: bool = IS_OK;
    }
    type OkayType = TestTargetType<true>;
    type FailType = TestTargetType<false>;
    macro_rules! test {
        ($ty: ty) => {
            // Passing `NGType` will cause an assertion failure.
            assert!(<$ty>::IS_OK);
        };
    }

    #[test]
    fn valid_examples() {
        test_for_each_type!(test, []);
        test_for_each_type!(test, [OkayType]);
        test_for_each_type!(test, [OkayType,]);
        test_for_each_type!(test, [OkayType, OkayType]);
        test_for_each_type!(test, [OkayType, OkayType,]);
        test_for_each_type!(test, [OkayType, OkayType, OkayType]);
        test_for_each_type!(test, [OkayType, OkayType, OkayType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_01() {
        test_for_each_type!(test, [FailType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_02() {
        test_for_each_type!(test, [FailType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_03() {
        test_for_each_type!(test, [FailType, OkayType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_04() {
        test_for_each_type!(test, [FailType, OkayType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_05() {
        test_for_each_type!(test, [OkayType, FailType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_06() {
        test_for_each_type!(test, [OkayType, FailType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_07() {
        test_for_each_type!(test, [FailType, OkayType, OkayType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_08() {
        test_for_each_type!(test, [FailType, OkayType, OkayType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_09() {
        test_for_each_type!(test, [OkayType, FailType, OkayType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_10() {
        test_for_each_type!(test, [OkayType, FailType, OkayType,]);
    }
    #[test]
    #[should_panic]
    fn counterexample_11() {
        test_for_each_type!(test, [OkayType, OkayType, FailType]);
    }
    #[test]
    #[should_panic]
    fn counterexample_12() {
        test_for_each_type!(test, [OkayType, OkayType, FailType,]);
    }
}

mod assert_fits_in {
    use crate::internals::test_utils::assert_fits_in;

    #[rustfmt::skip]
    #[test]
    fn examples() {
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
    fn counterexample_1() {
        assert_fits_in!(256i32, u8);
    }
    #[test]
    #[should_panic]
    fn counterexample_2() {
        assert_fits_in!(-1i32, u8);
    }
    #[test]
    #[should_panic]
    fn counterexample_3() {
        assert_fits_in!(-129i32, i8);
    }
    #[test]
    #[should_panic]
    fn counterexample_4() {
        assert_fits_in!(128i32, i8);
    }

    #[test]
    fn example_with_msg() {
        // u8: 0..=255
        assert_fits_in!(255i32, u8);
        assert_fits_in!(255i32, u8, "should not fail here!");
    }

    #[test]
    #[should_panic(expected = "255i32 + 1 does not fit into u8")]
    fn counterexample_with_msg_1() {
        assert_fits_in!(255i32 + 1, u8);
    }
    #[test]
    #[should_panic(expected = "test failed with code=256")]
    fn counterexample_with_msg_2() {
        assert_fits_in!(255i32 + 1, u8, "test failed with code={}", 255i32 + 1);
    }
}
