// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! # ffuzzy: ssdeep-compatible Fuzzy Hashing Library in pure Rust
//!
//! [ssdeep](https://ssdeep-project.github.io/ssdeep/) is a program for computing
//! context triggered piecewise hashes (CTPH).  Also called fuzzy hashes, CTPH
//! can match inputs that have homologies.  Such inputs have sequences of identical
//! bytes in the same order, although bytes in between these sequences may be
//! different in both content and length.
//!
//! You can generate / parse / compare (ssdeep-compatible) fuzzy hashes
//! with this crate.
//!
//! Along with "easy" functions, it provides fuzzy hashing-related structs for
//! high performance / advanced use cases.  If you understand both the property of
//! fuzzy hashes and this crate well, you can cluster the fuzzy hashes over 5 times
//! faster than libfuzzy.
//!
//!
//! ## Usage: Basic
//!
//! ### Hashing a File
//!
//! ```rust
//! # #[cfg(not(all(feature = "std", feature = "easy-functions")))]
//! # fn main() {}
//! // Required Features: "std" and "easy-functions" (default enabled)
//! # #[cfg(all(feature = "std", feature = "easy-functions"))]
//! fn main() -> Result<(), ssdeep::GeneratorOrIOError> {
//!     let fuzzy_hash = ssdeep::hash_file("data/examples/hello.txt")?;
//!     let fuzzy_hash_str = fuzzy_hash.to_string();
//!     assert_eq!(fuzzy_hash_str, "3:aaX8v:aV");
//!     Ok(())
//! }
//! ```
//!
//! ### Comparing Two Fuzzy Hashes
//!
//! ```rust
//! // Required Feature: "easy-functions" (default enabled)
//! # #[cfg(feature = "easy-functions")]
//! # {
//! let score = ssdeep::compare(
//!     "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW",
//!     "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n"
//! ).unwrap();
//! assert_eq!(score, 46);
//! # }
//! ```
//!
//! ## Usage: Advanced
//!
//! ### Hashing a Buffer
//!
//! ```rust
//! // Requires the "alloc" feature to use the `to_string()` method (default enabled).
//! use ssdeep::{Generator, RawFuzzyHash};
//!
//! let mut generator = Generator::new();
//! let buf1: &[u8] = b"Hello, ";
//! let buf2: &[u8] = b"World!";
//!
//! // Optional but supplying the *total* input size first improves the performance.
//! // This is the total size of three update calls below.
//! generator.set_fixed_input_size_in_usize(buf1.len() + buf2.len() + 1).unwrap();
//!
//! // Update the internal state of the generator.
//! // Of course, you can call `update()`-family functions multiple times.
//! generator.update(buf1);
//! generator.update_by_iter(buf2.iter().cloned());
//! generator.update_by_byte(b'\n');
//!
//! // Retrieve the fuzzy hash and convert to the string.
//! let hash: RawFuzzyHash = generator.finalize().unwrap();
//! assert_eq!(hash.to_string(), "3:aaX8v:aV");
//! ```
//!
//! ### Comparing Fuzzy Hashes
//!
//! ```rust
//! // Requires the "alloc" feature to use the `to_string()` method (default enabled).
//! use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};
//!
//! // Those fuzzy hash strings are "normalized" so that easier to compare.
//! let str1 = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
//! let str2 = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK";
//! // FuzzyHash object can be used to avoid parser / normalization overhead
//! // and helps improving the performance.
//! let hash1: FuzzyHash = str::parse(str1).unwrap();
//! let hash2: FuzzyHash = str::parse(str2).unwrap();
//!
//! // Note that converting the (normalized) fuzzy hash object back to the string
//! // may not preserve the original string.  To preserve the original fuzzy hash
//! // string too, consider using dual fuzzy hashes (such like DualFuzzyHash) that
//! // preserves the original string in the compressed format.
//! // *   str1:  "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ"
//! // *   hash1: "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccei:+Klhav84a5sxJ"
//! assert_ne!(hash1.to_string(), str1);
//!
//! // If we have number of fuzzy hashes and a hash is compared more than once,
//! // storing those hashes as FuzzyHash objects is faster.
//! assert_eq!(hash1.compare(&hash2), 88);
//!
//! // But there's another way of comparison.
//! // If you compare "a fuzzy hash" with "other many fuzzy hashes", this method
//! // (using FuzzyHashCompareTarget as "a fuzzy hash") is much, much faster.
//! let target: FuzzyHashCompareTarget = FuzzyHashCompareTarget::from(&hash1);
//! assert_eq!(target.compare(&hash2), 88);
//!
//! // If you reuse the same `target` object repeatedly for multiple fuzzy hashes,
//! // `new` and `init_from` will be helpful.
//! let mut target: FuzzyHashCompareTarget = FuzzyHashCompareTarget::new();
//! target.init_from(&hash1);
//! assert_eq!(target.compare(&hash2), 88);
//! ```
//!
//! ### Introduction to Dual Fuzzy Hashes
//!
//! It only shows a property of the dual fuzzy hash.  Dual fuzzy hash objects will
//! be really useful on much, much complex cases.
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # {
//! // Requires the "alloc" feature to use the `to_string()`-like methods (default enabled).
//! use ssdeep::{FuzzyHash, DualFuzzyHash};
//!
//! // "Normalization" would change the contents.
//! let str1      = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
//! let str2      = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK";
//! let str2_norm = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccex:+glvav84a5sxK";
//! let hash1: FuzzyHash = str::parse(str1).unwrap();
//! let hash2: DualFuzzyHash = str::parse(str2).unwrap();
//!
//! // Note that a dual fuzzy hash object efficiently preserves both raw and
//! // normalized contents of the fuzzy hash.
//! // *   raw:        "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK"
//! // *   normalized: "12288:+yUwldx+C5IxJ845HYV5sxOH/cccex:+glvav84a5sxK"
//! assert_eq!(hash2.to_raw_form_string(),   str2);
//! assert_eq!(hash2.to_normalized_string(), str2_norm);
//!
//! // You can use the dual fuzzy hash object
//! // just like regular fuzzy hashes on some methods.
//! assert_eq!(hash1.compare(&hash2), 88);
//! # }
//! ```
//!
//!
//! ## Crate Features
//!
//! *   `alloc` and `std` (default)  
//!     This crate supports `no_std` (by disabling both of them) and
//!     `alloc` and `std` are built on the minimum `no_std` implementation.
//!     Those features enable implementations that depend on `alloc` and `std`,
//!     respectively.
//! *   `easy-functions` (default)  
//!     It provides easy-to-use high-level functions.
//! *   `unsafe` (**fast but unsafe**)  
//!     This crate is optionally unsafe.  By default, this crate is built with 100%
//!     safe Rust (*this default might change before version 1.0* but safe Rust code
//!     will be preserved).  Enabling this feature enables unsafe Rust code
//!     (although unsafe/safe code share the most using macros).
//! *   `unchecked`  
//!     This feature exposes `unsafe` functions and methods that don't check the
//!     validity of the input.  This is a subset of the `unsafe` feature that
//!     exposes `unsafe` functionalities but does not switch the program to use the
//!     unsafe Rust.
//! *   `nightly`  
//!     This feature enables some features specific to the Nightly Rust.  Note that
//!     this feature heavily depends on the version of `rustc` and should not be
//!     considered stable (don't expect SemVer-compatible semantics).
//! *   `opt-reduce-fnv-table` (not recommended to enable this)  
//!     ssdeep uses partial (the lowest 6 bits of) FNV hash.  While default table
//!     lookup instead of full FNV hash computation is faster on most cases, it will
//!     not affect the performance much on some configurations.
//!     Enabling this option will turn off using precomputed FNV hash table (4KiB).
//!     Note that it's not recommended to enable this feature for memory footprint
//!     since a generator is about 2KiB in size and a temporary object used for
//!     fuzzy hash comparison is about 1KiB in size (so that reducing 4KiB does not
//!     benefit well).
//! *   `tests-slow` and `tests-very-slow`  
//!     They will enable "slow" (may take seconds or even a couple of minutes) and
//!     "very slow" (may take more than that) tests, respectively.
//!
//!
//! ## History and Main Contributors of ssdeep
//!
//! Andrew Tridgell made the program called
//! ["spamsum"](https://www.samba.org/ftp/unpacked/junkcode/spamsum/)
//! to detect a mail similar to a known spam.
//!
//! Jesse Kornblum authored the program
//! ["ssdeep"](https://ssdeep-project.github.io/ssdeep/) based on spamsum by adding
//! solid engine to Andrew's work.
//! Jesse continued working to improve ssdeep for years.
//!
//! Helmut Grohne authored his re-written and optimized, streaming fuzzy hashing
//! engine that enabled multi-threaded runs and a capability to process files
//! without seeking.
//!
//! Tsukasa OI, first helped resolving the license issue on the edit distance code
//! (which was not open source), further optimized the engine and introduced
//! bit-parallel string processing functions.  He wrote ssdeep compatible engines
//! multiple times, including [ffuzzy++](https://github.com/a4lg/ffuzzypp).
//!
//!
//! ## License (GNU GPL v2 or later)
//!
//! This crate (as a whole library) is licensed under the terms of the GNU General
//! Public License as published by the Free Software Foundation; either version 2
//! of the License, or (at your option) any later version.
//!
//! However, some portions are licensed under more permissive licenses (see the
//! source code for details).
//!
//!
//! ## References
//!
//! *   Jesse Kornblum (2006)
//!     "Identifying almost identical files using context triggered piecewise hashing"
//!     ([doi:10.1016/j.diin.2006.06.015](https://doi.org/10.1016/j.diin.2006.06.015))
//!
//!
//! ## For Developers
//!
//! *   [Compatibility Policy](crate::docs::compat_policy)
//! *   [Implementation Notes](crate::docs::internals::impl_notes)

// no_std
#![cfg_attr(not(feature = "std"), no_std)]
// Regular nightly features
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(doc_auto_cfg))]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
#![cfg_attr(feature = "nightly", feature(error_in_core))]
#![cfg_attr(feature = "nightly", feature(no_coverage))]
// int_log feature depending on ilog2 availability
#![cfg_attr(ffuzzy_ilog2 = "unstable", feature(int_log))]
// unsafe code is *only* allowed on enabling either "unsafe" or "unchecked"
// feature or on the tests.  When only the "unchecked" feature is enabled,
// unsafe code requires explicit allow.
#![cfg_attr(not(any(feature = "unsafe", feature = "unchecked", test)), forbid(unsafe_code))]
#![cfg_attr(all(feature = "unchecked", not(any(feature = "unsafe", test))), deny(unsafe_code))]
// Non-test code requires documents
#![cfg_attr(not(test), warn(missing_docs))]
// Unless in the maintainance mode, allow unknown lints.
#![cfg_attr(not(feature = "maint-lints"), allow(unknown_lints))]
// Unless in the maintainance mode, allow old lint names.
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
#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate rand_xoshiro;

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
