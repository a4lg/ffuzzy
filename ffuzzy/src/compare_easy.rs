// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#![cfg(feature = "easy-functions")]

use core::str::FromStr;

use crate::hash::LongFuzzyHash;
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin, ParseErrorInfo
};


/// The operand (side) which caused a parse error.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorSide {
    /// The left hand side.
    Left,
    /// The right hand side.
    Right,
}

/// The error type representing a parse error for one of the operands
/// specified to the [`compare()`] function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseErrorEither(ParseErrorSide, ParseError);

impl ParseErrorEither {
    /// Returns which operand caused a parse error.
    pub fn side(&self) -> ParseErrorSide { self.0 }
}

impl ParseErrorInfo for ParseErrorEither {
    fn kind(&self)   -> ParseErrorKind { self.1.kind() }
    fn origin(&self) -> ParseErrorOrigin { self.1.origin() }
    fn offset(&self) -> usize { self.1.offset() }
}

impl core::fmt::Display for ParseErrorEither {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error occurred while parsing fuzzy hash {3} ({1}, at byte offset {2}): {0}",
            self.kind(),
            self.origin(),
            self.offset(),
            match self.side() {
                ParseErrorSide::Left  => 1,
                ParseErrorSide::Right => 2,
            }
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseErrorEither {}

/// Compare two fuzzy hashes.
///
/// If a parse error occurs, [`Err`] containing
/// [a parse error](ParseErrorEither) is returned.
/// Otherwise, [`Ok`] containing the similarity score (`0..=100`) is returned.
///
/// # Example
///
/// ```
/// assert_eq!(
///     ssdeep::compare(
///         "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW",
///         "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n"
///     ).unwrap(),
///     46
/// );
/// ```
pub fn compare(lhs: &str, rhs: &str) -> Result<u32, ParseErrorEither> {
    let lhs = match LongFuzzyHash::from_str(lhs) {
        Ok(value) => { value }
        Err(err)  => { return Err(ParseErrorEither(ParseErrorSide::Left, err)); }
    };
    let rhs = match LongFuzzyHash::from_str(rhs) {
        Ok(value) => { value }
        Err(err)  => { return Err(ParseErrorEither(ParseErrorSide::Right, err)); }
    };
    Ok(lhs.compare(rhs.as_ref()))
}





// grcov-excl-br-start
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::format;
    use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
    use crate::test_utils::test_auto_clone;

    #[test]
    fn test_parse_error_side_basic() {
        test_auto_clone::<ParseErrorSide>(&ParseErrorSide::Left);
        #[cfg(feature = "alloc")]
        {
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
    fn test_parse_error_either_basic() {
        let err = ParseErrorEither(
            ParseErrorSide::Left,
            ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockHash1, 2)
        );
        test_auto_clone::<ParseErrorEither>(&err);
        assert_eq!(err.side(), ParseErrorSide::Left);
        assert_eq!(err.kind(), ParseErrorKind::UnexpectedEndOfString);
        assert_eq!(err.origin(), ParseErrorOrigin::BlockHash1);
        assert_eq!(err.offset(), 2);
        #[cfg(feature = "alloc")]
        {
            assert_eq!(
                format!("{:?}", err),
                "ParseErrorEither(Left, ParseError(UnexpectedEndOfString, BlockHash1, 2))"
            );
        }
    }

    #[test]
    fn test_compare_ok() {
        assert_eq!(
            compare(
                "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW",
                "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n"
            ).unwrap(),
            46
        );
    }

    #[test]
    fn test_compare_err() {
        // Valid:   "3::"
        // Invalid: "3,::"
        // Invalid: "4::"
        assert_eq!(compare("3,::", "3::"), Err(ParseErrorEither(
            ParseErrorSide::Left,
            ParseError(ParseErrorKind::UnexpectedCharacter, ParseErrorOrigin::BlockSize, 1))
        ));
        assert_eq!(compare("3::", "4::"), Err(ParseErrorEither(
            ParseErrorSide::Right,
            ParseError(ParseErrorKind::BlockSizeIsInvalid, ParseErrorOrigin::BlockSize, 0))
        ));
        // An error with ParseErrorSide::Left on the current implementation
        // but this property is not guaranteed
        // (just make sure that this is an error).
        assert!(compare("3,::", "4::").is_err());
    }

    #[test]
    fn test_compare_error_side() {
        let hstr_valid = "3::";
        let hstr_err_empty = "";
        let hstr_err_eos_bh1 = "3:";
        let hstr_err_bs_invalid = "4::";
        let err_empty = ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize, 0);
        let err_eos_bh1 = ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockHash1, 2);
        let err_bs_invalid = ParseError(ParseErrorKind::BlockSizeIsInvalid, ParseErrorOrigin::BlockSize, 0);
        // Left side has an error.
        assert_eq!(compare(hstr_err_empty,      hstr_valid), Err(ParseErrorEither(ParseErrorSide::Left, err_empty)));
        assert_eq!(compare(hstr_err_eos_bh1,    hstr_valid), Err(ParseErrorEither(ParseErrorSide::Left, err_eos_bh1)));
        assert_eq!(compare(hstr_err_bs_invalid, hstr_valid), Err(ParseErrorEither(ParseErrorSide::Left, err_bs_invalid)));
        // Right side has an error.
        assert_eq!(compare(hstr_valid, hstr_err_empty),      Err(ParseErrorEither(ParseErrorSide::Right, err_empty)));
        assert_eq!(compare(hstr_valid, hstr_err_eos_bh1),    Err(ParseErrorEither(ParseErrorSide::Right, err_eos_bh1)));
        assert_eq!(compare(hstr_valid, hstr_err_bs_invalid), Err(ParseErrorEither(ParseErrorSide::Right, err_bs_invalid)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compare_error_str() {
        let err_empty = ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize, 0);
        let err_eos_bh1 = ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockHash1, 2);
        let err_bs_invalid = ParseError(ParseErrorKind::BlockSizeIsInvalid, ParseErrorOrigin::BlockSize, 0);
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Left, err_empty)),
            "error occurred while parsing fuzzy hash 1 (block size, at byte offset 0): end-of-string is not expected");
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Right, err_empty)),
            "error occurred while parsing fuzzy hash 2 (block size, at byte offset 0): end-of-string is not expected");
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Left, err_eos_bh1)),
            "error occurred while parsing fuzzy hash 1 (block hash 1, at byte offset 2): end-of-string is not expected");
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Right, err_eos_bh1)),
            "error occurred while parsing fuzzy hash 2 (block hash 1, at byte offset 2): end-of-string is not expected");
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Left, err_bs_invalid)),
            "error occurred while parsing fuzzy hash 1 (block size, at byte offset 0): block size is not valid");
        assert_eq!(format!("{}", ParseErrorEither(ParseErrorSide::Right, err_bs_invalid)),
            "error occurred while parsing fuzzy hash 2 (block size, at byte offset 0): block size is not valid");
    }
}
// grcov-excl-br-end
