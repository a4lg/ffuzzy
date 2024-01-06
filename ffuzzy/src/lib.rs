// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

// Separate from README.md to use rustdoc-specific features in docs/readme.md.
#![doc = include_str!("docs/readme.md")]

// no_std
#![cfg_attr(not(feature = "std"), no_std)]
// Regular nightly features
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(doc_auto_cfg))]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
#![cfg_attr(feature = "nightly", feature(error_in_core))]
#![cfg_attr(feature = "nightly", feature(coverage_attribute))]
// int_log feature depending on ilog2 availability
#![cfg_attr(ffuzzy_ilog2 = "unstable", feature(int_log))]
// int_roundings feature depending on div_ceil availability
#![cfg_attr(ffuzzy_div_ceil = "unstable", feature(int_roundings))]
// unsafe code is *only* allowed on enabling either "unsafe" or "unchecked"
// feature or on the tests.  When only the "unchecked" feature is enabled,
// unsafe code requires explicit allow.
#![cfg_attr(not(any(feature = "unsafe", feature = "unchecked", test)), forbid(unsafe_code))]
#![cfg_attr(all(feature = "unchecked", not(any(feature = "unsafe", test))), deny(unsafe_code))]
// Non-test code requires documents
#![cfg_attr(not(test), warn(missing_docs))]
// Unless in the maintenance mode, allow unknown lints.
#![cfg_attr(not(feature = "maint-lints"), allow(unknown_lints))]
// Unless in the maintenance mode, allow old lint names.
#![cfg_attr(not(feature = "maint-lints"), allow(renamed_and_removed_lints))]

// Tests: constant (and/or obvious) assertions should be allowed.
#![cfg_attr(test, allow(clippy::assertions_on_constants))]
// Tests: obvious +1 and -1 along with comparison should be allowed.
#![cfg_attr(test, allow(clippy::int_plus_one))]
// Tests: obvious 1 * n like operations should be allowed.
#![cfg_attr(test, allow(clippy::identity_op))]
// Tests: currently allowed on Rust 1.69 (stable as of this writing)
//        but not on MSRV (Rust 1.56).
#![cfg_attr(test, allow(clippy::or_fun_call))]

#[cfg(feature = "alloc")]
extern crate alloc;

// std is required when we are testing (including doctests).
#[cfg(any(test, doc))]
#[macro_use]
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
pub mod docs;

pub use compare::FuzzyHashCompareTarget;
#[cfg(feature = "easy-functions")]
pub use compare_easy::{compare, ParseErrorEither, ParseErrorSide};
pub use generate::{Generator, GeneratorError};
#[cfg(feature = "easy-functions")]
pub use generate_easy::hash_buf;
#[cfg(all(feature = "easy-functions", feature = "std"))]
pub use generate_easy_std::{hash_file, hash_stream, GeneratorOrIOError};
pub use hash::{
    FuzzyHashData,
    FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash,
    FuzzyHashOperationError
};
pub use hash::block::{
    block_size,
    block_hash,
    BlockSizeRelation
};
#[deprecated]
pub use hash::block::block_size as BlockSize;
#[deprecated]
pub use hash::block::block_hash as BlockHash;
pub use hash::parser_state::{
    ParseError, ParseErrorInfo, ParseErrorKind, ParseErrorOrigin
};
pub use hash_dual::{
    FuzzyHashDualData,
    DualFuzzyHash, LongDualFuzzyHash
};

/// Module containing internal hash functions.
pub mod internal_hashes {
    pub use super::generate::{PartialFNVHash, RollingHash};
}

/// Module containing internal efficient block hash implementation.
pub mod internal_comparison {
    pub use super::compare::position_array::{
        BlockHashPositionArray,
        BlockHashPositionArrayData,
        BlockHashPositionArrayImpl,
        block_hash_position_array_element,
    };
    #[deprecated]
    pub use super::compare::position_array::block_hash_position_array_element as BlockHashPositionArrayElement;
    #[cfg(feature = "unchecked")]
    pub use super::compare::position_array::BlockHashPositionArrayImplUnchecked;
    #[cfg(feature = "unchecked")]
    #[deprecated]
    pub use super::compare::position_array::BlockHashPositionArrayImplUnchecked as BlockHashPositionArrayImplUnsafe;
}

/// Module containing certain constraints about fuzzy hash data.
pub mod constraints {
    pub use super::hash::block::{
        BlockHashSize, ConstrainedBlockHashSize,
        BlockHashSizes, ConstrainedBlockHashSizes
    };
}

/// The maximum length of the fuzzy hash's string representation.
///
/// This is the maximum length of the longest valid fuzzy hash
/// when represented in a string.
pub const MAX_LEN_IN_STR: usize = LongRawFuzzyHash::MAX_LEN_IN_STR;





/// Constant assertions related to the base requirements.
#[doc(hidden)]
mod const_asserts {
    use super::*;
    use static_assertions::const_assert;

    // We expect that usize is at least 8 bits in width.
    // For buffer-related operations in this crate except generator_easy,
    // this should be enough.  In reality, generator_easy would require
    // usize of >= 16 bits and in fact some structs in this crate
    // exceeds 256 bytes.  Some tests even require that usize is at least
    // 32 bits.
    const_assert!(usize::BITS >= 8);

    // MAX_LEN_IN_STR is sufficient to represent every variant of
    // a fuzzy hash.
    const_assert!(MAX_LEN_IN_STR >= FuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= RawFuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= LongFuzzyHash::MAX_LEN_IN_STR);
    const_assert!(MAX_LEN_IN_STR >= LongRawFuzzyHash::MAX_LEN_IN_STR);
}
