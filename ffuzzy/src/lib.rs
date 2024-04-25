// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

// Separate from README.md to use rustdoc-specific features in docs/readme.md.
#![doc = include_str!("_docs/readme.md")]
// no_std
#![cfg_attr(not(any(test, doc, feature = "std")), no_std)]
// Allow using internal features when use of Nightly Rust features are allowed.
#![cfg_attr(feature = "unstable", allow(internal_features))]
// Regular nightly features
#![cfg_attr(feature = "unstable", feature(doc_cfg))]
#![cfg_attr(feature = "unstable", feature(doc_auto_cfg))]
#![cfg_attr(feature = "unstable", feature(core_intrinsics))]
#![cfg_attr(feature = "unstable", feature(hint_assert_unchecked))]
#![cfg_attr(feature = "unstable", feature(error_in_core))]
#![cfg_attr(feature = "unstable", feature(coverage_attribute))]
#![cfg_attr(feature = "unstable", feature(trusted_len))]
// int_log feature depending on ilog2 availability
#![cfg_attr(ffuzzy_ilog2 = "unstable", feature(int_log))]
// int_roundings feature depending on div_ceil availability
#![cfg_attr(ffuzzy_div_ceil = "unstable", feature(int_roundings))]
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
#![cfg_attr(not(test), warn(missing_docs))]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]
// Unless in the maintenance mode, allow unknown lints.
#![cfg_attr(not(feature = "maint-lints"), allow(unknown_lints))]
// Unless in the maintenance mode, allow old lint names.
#![cfg_attr(not(feature = "maint-lints"), allow(renamed_and_removed_lints))]
// Tests: allow unused unsafe blocks (invariant! does will not need unsafe
// on tests but others may need this macro).
#![cfg_attr(test, allow(unused_unsafe))]
// Tests: constant (and/or obvious) assertions should be allowed.
#![cfg_attr(test, allow(clippy::assertions_on_constants))]
// Tests: obvious +1 and -1 along with comparison should be allowed.
#![cfg_attr(test, allow(clippy::int_plus_one))]
// Tests: obvious 1 * n like operations should be allowed.
#![cfg_attr(test, allow(clippy::identity_op))]
// Tests: obvious x << 0 like operations should be allowed.
#![cfg_attr(test, allow(clippy::erasing_op))]
// Tests: true || x should be allowed.
#![cfg_attr(test, allow(clippy::overly_complex_bool_expr))]
#![cfg_attr(test, allow(clippy::logic_bug))]
// Tests: false || x should be allowed.
#![cfg_attr(test, allow(clippy::nonminimal_bool))]

// alloc is required when the "alloc" feature is enabled or testing (including doctests).
#[cfg(any(feature = "alloc", test, doc))]
extern crate alloc;

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
pub mod internal_hashes {
    pub use super::generate::{PartialFNVHash, RollingHash};
}

/// Module containing internal efficient block hash implementation.
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

/// The maximum length of the fuzzy hash's string representation
/// (except the file name part).
///
/// This is the maximum length of the longest valid fuzzy hash
/// (except the file name part) when represented in a string.
///
/// Note that again, this value does not count
/// [the file name part of the fuzzy hash](crate::hash::FuzzyHashData#fuzzy-hash-internals)
/// (not even an optional "comma" character separating the file name part)
/// because [`LongRawFuzzyHash::len_in_str()`] does not.
pub const MAX_LEN_IN_STR: usize = LongRawFuzzyHash::MAX_LEN_IN_STR;

/// Constant assertions related to the base requirements.
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::const_assert;

    // We expect that usize is at least 16 bits in width.
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
