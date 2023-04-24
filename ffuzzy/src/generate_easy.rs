// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#![cfg(feature = "easy-functions")]

use crate::generate::{Generator, GeneratorError};
use crate::hash::RawFuzzyHash;


/// Generates a fuzzy hash from a given buffer.
///
/// # Example (requires the `alloc` feature)
///
/// ```
/// # #[cfg(feature = "alloc")]
/// assert_eq!(
///     ssdeep::hash_buf(b"Hello, World!\n").unwrap().to_string(),
///     "3:aaX8v:aV"
/// );
/// ```
pub fn hash_buf(buffer: &[u8]) -> Result<RawFuzzyHash, GeneratorError> {
    let mut generator = Generator::new();
    generator.set_fixed_input_size_in_usize(buffer.len())?;
    generator.update(buffer);
    let hash = generator.finalize()?; // grcov-excl-br-line:UNREACHABLE ERROR
    Ok(hash)
}





// grcov-excl-br-start
#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_buf_usage() {
        assert_eq!(
            hash_buf(b"Hello, World!\n").unwrap().to_string(),
            "3:aaX8v:aV"
        );
    }
}
// grcov-excl-br-stop
