// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

#[cfg(feature = "alloc")]
use alloc::format;
use crate::compare_easy::{compare, ParseErrorSide, ParseErrorEither};
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin, ParseErrorInfo};
use crate::test_utils::test_auto_clone;


#[test]
fn parse_error_side_impls() {
    // Test Clone
    test_auto_clone::<ParseErrorSide>(&ParseErrorSide::Left);
    #[cfg(feature = "alloc")]
    {
        // Test Debug
        crate::test_utils::test_auto_debug_for_enum!(
            ParseErrorSide,
            [
                Left,
                Right,
            ]
        );
    }
}

#[test]
fn parse_error_either_basic_and_impls() {
    // Internal values
    const SIDE: ParseErrorSide     = ParseErrorSide::Left;
    const KIND: ParseErrorKind     = ParseErrorKind::UnexpectedEndOfString;
    const ORIGIN: ParseErrorOrigin = ParseErrorOrigin::BlockHash1;
    const OFFSET: usize = 2;
    // Construct an error object.
    let err = ParseErrorEither(SIDE, ParseError(KIND, ORIGIN, OFFSET));
    // Test Clone
    test_auto_clone::<ParseErrorEither>(&err);
    // Check internal values.
    assert_eq!(err.side(), SIDE);
    assert_eq!(err.kind(), KIND);
    assert_eq!(err.origin(), ORIGIN);
    assert_eq!(err.offset(), OFFSET);
    #[cfg(feature = "alloc")]
    {
        // Test Debug
        assert_eq!(
            format!("{:?}", err),
            "ParseErrorEither(\
                Left, \
                ParseError(\
                    UnexpectedEndOfString, \
                    BlockHash1, \
                    2\
                )\
            )"
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn parse_error_either_impls_display_and_debug_with_side() {
    for (err, err_str_display, err_str_debug) in crate::hash::parser_state::tests::PARSE_ERROR_CASES {
        // Test Display
        assert_eq!(
            format!("{}", ParseErrorEither(ParseErrorSide::Left, err)),
            format!("error occurred while parsing fuzzy hash 1 {}", err_str_display),
            "failed on err={:?}", err
        );
        assert_eq!(
            format!("{}", ParseErrorEither(ParseErrorSide::Right, err)),
            format!("error occurred while parsing fuzzy hash 2 {}", err_str_display),
            "failed on err={:?}", err
        );
        // Test Debug
        assert_eq!(
            format!("{:?}", ParseErrorEither(ParseErrorSide::Left, err)),
            format!("ParseErrorEither(Left, {})", err_str_debug),
            "failed on err={:?}", err
        );
        assert_eq!(
            format!("{:?}", ParseErrorEither(ParseErrorSide::Right, err)),
            format!("ParseErrorEither(Right, {})", err_str_debug),
            "failed on err={:?}", err
        );
    }
}

#[test]
fn compare_example() {
    assert_eq!(
        compare(
            "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW",
            "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n"
        ).unwrap(),
        46
    );
}

#[test]
fn compare_errors() {
    const STR_VALID: &str = "3::";
    const ERROR_CASES: [(&str, ParseError); 3] = [
        ("",    ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize,  0)),
        ("3:",  ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockHash1, 2)),
        ("4::", ParseError(ParseErrorKind::BlockSizeIsInvalid,    ParseErrorOrigin::BlockSize,  0)),
    ];
    for (hash_str_invalid, err) in ERROR_CASES {
        // Left side has an error.
        assert_eq!(compare(hash_str_invalid, STR_VALID), Err(ParseErrorEither(ParseErrorSide::Left, err)),
            "failed on hash_str_invalid={:?} (left)", hash_str_invalid);
        // Right side has an error.
        assert_eq!(compare(STR_VALID, hash_str_invalid), Err(ParseErrorEither(ParseErrorSide::Right, err)),
            "failed on hash_str_invalid={:?} (right)", hash_str_invalid);
    }
    /*
        If both sides are invalid, an error with ParseErrorSide::Left is
        generated on the current implementation but this property is not
        guaranteed by any version.
        It just make sures that this is an actual error generated in an
        consistent manner (X side + parse error on the X side).
    */
    for (hash_str_invalid_l, err_l) in ERROR_CASES {
        for (hash_str_invalid_r, err_r) in ERROR_CASES {
            let err = compare(hash_str_invalid_l, hash_str_invalid_r);
            // grcov-excl-start: Not very relevant to the true coverage.
            assert!(
                err == Err(ParseErrorEither(ParseErrorSide::Left,  err_l)) ||
                err == Err(ParseErrorEither(ParseErrorSide::Right, err_r)),
                "failed on hash_str_invalid_l={:?}, hash_str_invalid_r={:?}",
                hash_str_invalid_l, hash_str_invalid_r
            );
            // grcov-excl-end
        }
    }
}
