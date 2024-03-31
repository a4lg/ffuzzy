// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.


/// An enumeration representing a cause of
/// a [fuzzy hash](crate::hash::FuzzyHashData) parse error.
///
/// # Compatibility Note
///
/// Since the version 0.3, the representation of this enum is no longer
/// specified as specific representation of this enum is not important.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// Block size: is empty.
    BlockSizeIsEmpty,
    /// Block size: starts with the digit zero (`'0'`).
    BlockSizeStartsWithZero,
    /// Block size: is not valid.
    BlockSizeIsInvalid,
    /// Block size: is too large to parse.
    BlockSizeIsTooLarge,
    /// Block hash (either 1 or 2): block hash is too long.
    BlockHashIsTooLong,
    /// Any: an unexpected character is encountered.
    UnexpectedCharacter,
    /// Any: an unexpected end-of-string is encountered.
    UnexpectedEndOfString,
}

impl core::fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self { // grcov-excl-br-line:MATCH_ENUM
            ParseErrorKind::BlockHashIsTooLong      => "block hash is too long",
            ParseErrorKind::BlockSizeIsEmpty        => "block size field is empty",
            ParseErrorKind::BlockSizeStartsWithZero => "block size starts with '0'",
            ParseErrorKind::BlockSizeIsInvalid      => "block size is not valid",
            ParseErrorKind::BlockSizeIsTooLarge     => "block size is too large",
            ParseErrorKind::UnexpectedCharacter     => "an unexpected character is encountered",
            ParseErrorKind::UnexpectedEndOfString   => "end-of-string is not expected",
        })
    }
}


/// A part which (possibly) caused a
/// [fuzzy hash](crate::hash::FuzzyHashData) parse error.
///
/// See [`FuzzyHashData`](crate::hash::FuzzyHashData) for corresponding parts.
///
/// Since the parser ignores the file name part,
/// this part is not in this enumeration.
///
/// # Compatibility Note
///
/// On the next major release, the `FileName` variant will be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorOrigin {
    /// Block size.
    BlockSize,
    /// Block hash 1.
    BlockHash1,
    /// Block hash 2.
    BlockHash2,
}

impl core::fmt::Display for ParseErrorOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self { // grcov-excl-br-line:MATCH_ENUM
            ParseErrorOrigin::BlockSize  => "block size",
            ParseErrorOrigin::BlockHash1 => "block hash 1",
            ParseErrorOrigin::BlockHash2 => "block hash 2",
        })
    }
}


// grcov-excl-br-start:STRUCT_MEMBER

/// The error type for parse operations of
/// [`FuzzyHashData`](crate::hash::FuzzyHashData).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(
    pub(crate) ParseErrorKind,
    pub(crate) ParseErrorOrigin,
    pub(crate) usize
);

// grcov-excl-br-end

/// The trait implementing a [`FuzzyHashData`](crate::hash::FuzzyHashData)
/// parse error.
pub trait ParseErrorInfo {
    /// Returns the cause of the error.
    fn kind(&self) -> ParseErrorKind;
    /// Returns the part which (possibly) caused the error.
    fn origin(&self) -> ParseErrorOrigin;
    /// Returns the offset which (possibly) caused the error.
    ///
    /// Note that this offset may not be exact but may be usable as a hint.
    fn offset(&self) -> usize;
}

impl ParseErrorInfo for ParseError {
    fn kind(&self) -> ParseErrorKind { self.0 }
    fn origin(&self) -> ParseErrorOrigin { self.1 }
    fn offset(&self) -> usize { self.2 }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error occurred while parsing a fuzzy hash ({1}, at byte offset {2}): {0}",
            self.kind(),
            self.origin(),
            self.offset()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}
#[cfg(all(not(feature = "std"), feature = "unstable"))]
impl core::error::Error for ParseError {}


/// A type which represents a state after parsing a block hash.
///
/// Note that while some of them always represent one of error conditions,
/// some are valid depending on the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockHashParseState {
    /// The end of the string is encountered.
    MetEndOfString,
    /// A comma character (`,`) is encountered.
    MetComma,
    /// A colon character (`:`) is encountered.
    MetColon,
    /// A block hash is too long so that would cause an overflow.
    OverflowError,
    /// An invalid Base64 alphabet (or just an unexpected character) is encountered.
    Base64Error,
}





// grcov-excl-br-start
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
        #[cfg(feature = "alloc")]
        {
            // Test Display
            assert_eq!(format!("{}", ParseErrorOrigin::BlockSize),  "block size");
            assert_eq!(format!("{}", ParseErrorOrigin::BlockHash1), "block hash 1");
            assert_eq!(format!("{}", ParseErrorOrigin::BlockHash2), "block hash 2");
        }
    }

    #[test]
    fn parse_error_basic_and_impls() {
        // Internal values
        const KIND:   ParseErrorKind   = ParseErrorKind::UnexpectedEndOfString;
        const ORIGIN: ParseErrorOrigin = ParseErrorOrigin::BlockHash1;
        const OFFSET: usize = 2;
        // Construct an error object.
        let err = ParseError(KIND, ORIGIN, OFFSET);
        // Check internal values.
        assert_eq!(err.kind(),   KIND);
        assert_eq!(err.origin(), ORIGIN);
        assert_eq!(err.offset(), OFFSET);
    }

    pub(crate) const PARSE_ERROR_CASES: &[(ParseError, &str)] = &[
        (ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize,  0), "(block size, at byte offset 0): end-of-string is not expected"),
        (ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockHash1, 2), "(block hash 1, at byte offset 2): end-of-string is not expected"),
        (ParseError(ParseErrorKind::BlockSizeIsInvalid,    ParseErrorOrigin::BlockSize,  0), "(block size, at byte offset 0): block size is not valid"),
    ];

    #[test]
    fn parse_error_impls_display_and_debug() {
        for &(err, err_str_display) in PARSE_ERROR_CASES {
            // Test Display
            assert_eq!(
                format!("{}", err),
                format!("error occurred while parsing a fuzzy hash {}", err_str_display)
            );
        }
    }
}
// grcov-excl-br-stop
