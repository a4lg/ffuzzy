// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

// Separate from README.md to use rustdoc-specific features in docs/readme.md.
#![doc = include_str!("_docs/readme.md")]
// no_std by default (import alloc and std if necessary)
#![no_std]
// Regular nightly features
#![cfg_attr(
    feature = "unstable",
    feature(
        core_intrinsics,
        coverage_attribute,
        doc_cfg,
        doc_auto_cfg,
        likely_unlikely,
        trusted_len
    )
)]
// In the code maintenance mode, disallow all warnings.
#![cfg_attr(feature = "maint-code", deny(warnings))]
// unsafe code is *only* allowed on enabling either "unsafe"-like features or
// the "unchecked" feature, or on the tests.  When full "unsafe" feature is not
// enabled and not on the tests, unsafe code requires explicit allow.
#![cfg_attr(
    not(any(
        feature = "unsafe",
        feature = "unsafe-guarantee",
        feature = "unchecked",
        test
    )),
    forbid(unsafe_code)
)]
#![cfg_attr(
    all(
        not(any(feature = "unsafe", test)),
        any(feature = "unchecked", feature = "unsafe-guarantee")
    ),
    deny(unsafe_code)
)]
// Non-test code requires documents
#![cfg_attr(not(test), warn(missing_docs, clippy::missing_docs_in_private_items))]
// Unless in the maintenance mode, allow unknown lints / old lint names.
#![cfg_attr(
    not(feature = "maint-lints"),
    allow(unknown_lints, renamed_and_removed_lints)
)]
// On tests, we allow several types of redundant operations.
#![cfg_attr(
    test,
    allow(
        unused_unsafe,
        clippy::assertions_on_constants,
        clippy::int_plus_one,
        clippy::identity_op,
        clippy::erasing_op,
        clippy::overly_complex_bool_expr,
        clippy::logic_bug, // renamed to clippy::overly_complex_bool_expr
        clippy::nonminimal_bool
    )
)]

// Import alloc and std only when necessary
#[cfg(any(feature = "alloc", test, doc))]
extern crate alloc;
#[cfg(any(feature = "std", test, doc))]
extern crate std;

mod base64;
mod compare;
mod compare_easy;
mod generate;
mod generate_easy;
mod generate_easy_std;
mod hash;
mod hash_dual;
mod intrinsics;
mod macros;
mod test_utils;
mod utils;

#[cfg(doc)]
#[allow(missing_docs)]
pub mod _docs;

pub use compare::FuzzyHashCompareTarget;
#[cfg(feature = "easy-functions")]
pub use compare_easy::{compare, ParseErrorEither, ParseErrorSide};
pub use generate::{Generator, GeneratorError};
#[cfg(feature = "easy-functions")]
pub use generate_easy::hash_buf;
#[cfg(all(feature = "easy-functions", feature = "std"))]
pub use generate_easy_std::{hash_file, hash_stream, GeneratorOrIOError};
pub use hash::block::{block_hash, block_size, BlockSizeRelation};
pub use hash::parser_state::{ParseError, ParseErrorInfo, ParseErrorKind, ParseErrorOrigin};
pub use hash::{
    FuzzyHash, FuzzyHashData, FuzzyHashOperationError, LongFuzzyHash, LongRawFuzzyHash,
    RawFuzzyHash,
};
pub use hash_dual::{DualFuzzyHash, FuzzyHashDualData, LongDualFuzzyHash};

/// Module containing internal hash functions.
///
/// # Compatibility Notice
///
/// This module is going to be completely private on the next major release.
/// If you need to experiment with internal hashing functions, just
/// vendor the source code for your needs.
#[deprecated]
pub mod internal_hashes {
    pub use super::generate::{PartialFNVHash, RollingHash};
}

/// Module containing internal efficient block hash implementation.
///
/// # Compatibility Notice
///
/// This module is going to be completely private on the next major release.
/// If you need to experiment with internal hashing functions, just
/// vendor the source code for your needs.
#[deprecated]
pub mod internal_comparison {
    pub use super::compare::position_array::{
        block_hash_position_array_element, BlockHashPositionArray, BlockHashPositionArrayData,
        BlockHashPositionArrayImpl,
    };

    #[cfg(feature = "unchecked")]
    pub use super::compare::position_array::BlockHashPositionArrayImplUnchecked;
}

/// Module containing certain constraints about fuzzy hash data.
pub mod constraints {
    pub use super::hash::block::{
        BlockHashSize, BlockHashSizes, ConstrainedBlockHashSize, ConstrainedBlockHashSizes,
    };
}

/// Prelude for convenient uses of this crate.
///
/// This module is currently empty but will be heavily used on the next version.
/// Person who use this crate are recommended to import everything in this prelude.
///
/// # Example
///
/// ```
/// use ssdeep::prelude::*;
/// ```
pub mod prelude {}

/// The maximum length of the fuzzy hash's string representation
/// (except optional file name part).
///
/// This is the maximum length of the longest valid fuzzy hash (except
/// optional file name part) when represented in a string.
///
/// Note that again, this value does not count
/// [the file name part of the fuzzy hash](crate::hash::FuzzyHashData#fuzzy-hash-internals)
/// (not even an optional "comma" character separating the file name part)
/// because [`LongRawFuzzyHash::len_in_str()`] does not.
pub const MAX_LEN_IN_STR: usize = LongRawFuzzyHash::MAX_LEN_IN_STR;

/// Constant assertions related to the base requirements.
#[doc(hidden)]
mod const_asserts {
    use static_assertions::const_assert;

    use super::*;

    // Environment: We expect that usize is at least 16 bits in width.
    // Note that, some tests even require that usize is at least 32 bits.
    const_assert!(usize::BITS >= 16);

    // MAX_LEN_IN_STR is sufficient to represent every variant of
    // a fuzzy hash.
    const_assert!(MAX_LEN_IN_STR >= FuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= RawFuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= LongFuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= LongRawFuzzyHash::MAX_LEN_IN_STR);
}

mod tests;
