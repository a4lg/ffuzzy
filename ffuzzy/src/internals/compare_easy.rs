// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Easy comparison functions and related error reporting utilities.

#![cfg(feature = "easy-functions")]

#[cfg(all(not(feature = "std"), ffuzzy_error_in_core = "stable"))]
use core::error::Error;
#[cfg(feature = "std")]
use std::error::Error;

use crate::internals::hash::parser_state::{
    ParseError, ParseErrorInfo, ParseErrorKind, ParseErrorOrigin,
};
use crate::internals::hash::LongFuzzyHash;

/// The operand (side) which caused a parse error.
///
/// # Compatibility Note
///
/// Since the version 0.3, the representation of this enum is no longer
/// specified as specific representation of this enum is not important.
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
pub struct ParseErrorEither(ParseErrorSide, ParseError); // grcov-excl-br-line:STRUCT_MEMBER

impl ParseErrorEither {
    /// Returns which operand caused a parse error.
    pub fn side(&self) -> ParseErrorSide {
        self.0
    }
}

impl ParseErrorInfo for ParseErrorEither {
    fn kind(&self) -> ParseErrorKind {
        self.1.kind()
    }
    fn origin(&self) -> ParseErrorOrigin {
        self.1.origin()
    }
    fn offset(&self) -> usize {
        self.1.offset()
    }
}

impl core::fmt::Display for ParseErrorEither {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "error occurred while parsing fuzzy hash {3} ({1}, at byte offset {2}): {0}",
            self.kind(),
            self.origin(),
            self.offset(),
            match self.side() {
                ParseErrorSide::Left => 1,
                ParseErrorSide::Right => 2,
            }
        )
    }
}

crate::internals::macros::impl_error!(ParseErrorEither {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.1)
    }
});

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
    let lhs: LongFuzzyHash = match str::parse(lhs) {
        Ok(value) => value,
        Err(err) => {
            return Err(ParseErrorEither(ParseErrorSide::Left, err));
        }
    };
    let rhs: LongFuzzyHash = match str::parse(rhs) {
        Ok(value) => value,
        Err(err) => {
            return Err(ParseErrorEither(ParseErrorSide::Right, err));
        }
    };
    Ok(lhs.compare(rhs.as_ref()))
}

mod tests;
