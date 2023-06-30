// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#![cfg(feature = "easy-functions")]

use crate::hash::LongFuzzyHash;
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin, ParseErrorInfo
};


#[cfg(test)]
mod tests;


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
impl std::error::Error for ParseErrorEither {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.1)
    }
}
#[cfg(all(not(feature = "std"), feature = "nightly"))]
impl core::error::Error for ParseErrorEither {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.1)
    }
}

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
        Ok(value) => { value }
        Err(err)  => { return Err(ParseErrorEither(ParseErrorSide::Left, err)); }
    };
    let rhs: LongFuzzyHash = match str::parse(rhs) {
        Ok(value) => { value }
        Err(err)  => { return Err(ParseErrorEither(ParseErrorSide::Right, err)); }
    };
    Ok(lhs.compare(rhs.as_ref()))
}
