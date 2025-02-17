// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Easy generator functions.

#![cfg(feature = "easy-functions")]

use crate::internals::generate::{Generator, GeneratorError};
use crate::internals::hash::RawFuzzyHash;

/// Generates a fuzzy hash from a given buffer.
///
/// # Example
///
/// ```
/// // Requires either the "alloc" feature or std environment
/// // on your crate to use `to_string()` method (default enabled).
/// assert_eq!(
///     ssdeep::hash_buf(b"Hello, World!\n").unwrap().to_string(),
///     "3:aaX8v:aV"
/// );
/// ```
pub fn hash_buf(buffer: &[u8]) -> Result<RawFuzzyHash, GeneratorError> {
    let mut generator = Generator::new();
    generator.set_fixed_input_size_in_usize(buffer.len())?;
    generator.update(buffer);
    Ok(generator.finalize().unwrap()) // grcov-excl-br-line:UNREACHABLE ERROR
}

mod tests;
