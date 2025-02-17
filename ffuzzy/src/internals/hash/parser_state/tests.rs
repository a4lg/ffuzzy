// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::internals::hash::parser_state`].

#![cfg(test)]

use alloc::format;

use super::{ParseError, ParseErrorInfo, ParseErrorKind, ParseErrorOrigin};

#[rustfmt::skip]
#[test]
fn parse_error_kind_impls() {
    // Test Display
    assert_eq!(format!("{}", ParseErrorKind::BlockHashIsTooLong),      "block hash is too long");
    assert_eq!(format!("{}", ParseErrorKind::BlockSizeIsEmpty),        "block size field is empty");
    assert_eq!(format!("{}", ParseErrorKind::BlockSizeStartsWithZero), "block size starts with '0'");
    assert_eq!(format!("{}", ParseErrorKind::BlockSizeIsInvalid),      "block size is not valid");
    assert_eq!(format!("{}", ParseErrorKind::BlockSizeIsTooLarge),     "block size is too large");
    assert_eq!(format!("{}", ParseErrorKind::UnexpectedCharacter),     "an unexpected character is encountered");
    assert_eq!(format!("{}", ParseErrorKind::UnexpectedEndOfString),   "end-of-string is not expected");
}

#[test]
fn parse_error_origin_impls() {
    // Test Display
    assert_eq!(format!("{}", ParseErrorOrigin::BlockSize), "block size");
    assert_eq!(format!("{}", ParseErrorOrigin::BlockHash1), "block hash 1");
    assert_eq!(format!("{}", ParseErrorOrigin::BlockHash2), "block hash 2");
}

#[test]
fn parse_error_basic_and_impls() {
    // Internal values
    const KIND: ParseErrorKind = ParseErrorKind::UnexpectedEndOfString;
    const ORIGIN: ParseErrorOrigin = ParseErrorOrigin::BlockHash1;
    const OFFSET: usize = 2;
    // Construct an error object.
    let err = ParseError(KIND, ORIGIN, OFFSET);
    // Check internal values.
    assert_eq!(err.kind(), KIND);
    assert_eq!(err.origin(), ORIGIN);
    assert_eq!(err.offset(), OFFSET);
}

pub(crate) const PARSE_ERROR_CASES: &[(ParseError, &str)] = &[
    (
        ParseError(
            ParseErrorKind::UnexpectedEndOfString,
            ParseErrorOrigin::BlockSize,
            0,
        ),
        "(block size, at byte offset 0): end-of-string is not expected",
    ),
    (
        ParseError(
            ParseErrorKind::UnexpectedEndOfString,
            ParseErrorOrigin::BlockHash1,
            2,
        ),
        "(block hash 1, at byte offset 2): end-of-string is not expected",
    ),
    (
        ParseError(
            ParseErrorKind::BlockSizeIsInvalid,
            ParseErrorOrigin::BlockSize,
            0,
        ),
        "(block size, at byte offset 0): block size is not valid",
    ),
];

#[test]
fn parse_error_impls_display_and_debug() {
    for &(err, err_str_display) in PARSE_ERROR_CASES {
        // Test Display
        assert_eq!(
            format!("{}", err),
            format!(
                "error occurred while parsing a fuzzy hash {}",
                err_str_display
            )
        );
    }
}
