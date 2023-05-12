// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#![cfg(feature = "easy-functions")]

use crate::generate::{Generator, GeneratorError};
use crate::hash::RawFuzzyHash;


/// Generates a fuzzy hash from a given buffer.
///
/// # Example
///
/// ```
/// // Requires the "alloc" feature to use `to_string` method (default enabled).
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
#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    #[test]
    fn hash_buf_usage() {
        use crate::generate_easy::hash_buf;
        assert_eq!(
            hash_buf(b"Hello, World!\n").unwrap().to_string(),
            "3:aaX8v:aV"
        );
    }

    // TODO: Once existence of an 128-bit machine is realistic, change #[cfg] below.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn hash_buf_input_too_large() {
        use crate::generate::{Generator, GeneratorError};
        use crate::generate_easy::hash_buf;
        unsafe {
            // Supply (most likely invalid) too large buffer and expect an error happens
            // before an actual access happens (GeneratorError::FixedSizeTooLarge).
            let too_large_size = (Generator::MAX_INPUT_SIZE + 1) as usize;
            let buf = core::slice::from_raw_parts(core::ptr::NonNull::dangling().as_ptr(), too_large_size);
            assert_eq!(hash_buf(buf), Err(GeneratorError::FixedSizeTooLarge));
        }
    }
}
// grcov-excl-br-stop
