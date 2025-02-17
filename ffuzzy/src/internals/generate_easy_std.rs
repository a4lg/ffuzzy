// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Easy generator functions depending on the standard I/O.

#![cfg(all(feature = "std", feature = "easy-functions"))]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::internals::generate::{Generator, GeneratorError};
use crate::internals::hash::RawFuzzyHash;
use crate::internals::macros::invariant;

/// The error type describing either a generator error or an I/O error.
///
/// This type contains either:
/// *   A fuzzy hash generator error ([`GeneratorError`]) or
/// *   An I/O error ([`std::io::Error`]).
#[derive(Debug)]
pub enum GeneratorOrIOError {
    /// An error caused by the fuzzy hash generator.
    GeneratorError(GeneratorError),

    /// An error caused by an internal I/O operation.
    IOError(std::io::Error),
}

impl core::fmt::Display for GeneratorOrIOError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GeneratorOrIOError::GeneratorError(err) => err.fmt(f),
            GeneratorOrIOError::IOError(err) => err.fmt(f),
        }
    }
}

impl From<GeneratorError> for GeneratorOrIOError {
    // For wrapping with the '?' operator
    fn from(value: GeneratorError) -> Self {
        GeneratorOrIOError::GeneratorError(value)
    }
}

impl From<std::io::Error> for GeneratorOrIOError {
    // For wrapping with the '?' operator
    fn from(value: std::io::Error) -> Self {
        GeneratorOrIOError::IOError(value)
    }
}

impl std::error::Error for GeneratorOrIOError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GeneratorOrIOError::GeneratorError(err) => Some(err),
            GeneratorOrIOError::IOError(err) => Some(err),
        }
    }
}

/// Constant temporary buffer size for "easy" functions.
const BUFFER_SIZE: usize = 32768;

/// Generates a fuzzy hash from a given reader stream.
///
/// This is an internal function to allow other functions to
/// prepare a [`Generator`] object.
///
/// # Performance Consideration
///
/// It doesn't use [`BufReader`](std::io::BufReader) because the internal buffer
/// is large enough.  Note that the default buffer size of `BufReader` is
/// normally 8KiB (while [buffer size](BUFFER_SIZE) here has 32KiB).
#[inline]
fn hash_stream_common<R: Read>(
    generator: &mut Generator,
    reader: &mut R,
) -> Result<RawFuzzyHash, GeneratorOrIOError> {
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let len = reader.read(&mut buffer)?; // grcov-excl-br-line:IO
        if len == 0 {
            break;
        }
        invariant!(len <= buffer.len());
        generator.update(&buffer[0..len]);
    }
    Ok(generator.finalize()?)
}

/// Generates a fuzzy hash from a given reader stream.
///
/// # Example
///
/// ```
/// use std::error::Error;
/// use std::fs::File;
///
/// fn main() -> Result<(), ssdeep::GeneratorOrIOError> {
///     let mut stream = File::open("data/examples/hello.txt")?;
///     let fuzzy_hash = ssdeep::hash_stream(&mut stream)?;
///     let fuzzy_hash_str = fuzzy_hash.to_string();
///     assert_eq!(fuzzy_hash_str, "3:aaX8v:aV");
///     Ok(())
/// }
/// ```
pub fn hash_stream<R: Read>(reader: &mut R) -> Result<RawFuzzyHash, GeneratorOrIOError> {
    let mut generator = Generator::new();
    hash_stream_common(&mut generator, reader)
}

/// Generates a fuzzy hash from a given file.
///
/// # Example
///
/// ```
/// use std::error::Error;
///
/// fn main() -> Result<(), ssdeep::GeneratorOrIOError> {
///     let fuzzy_hash = ssdeep::hash_file("data/examples/hello.txt")?;
///     let fuzzy_hash_str = fuzzy_hash.to_string();
///     assert_eq!(fuzzy_hash_str, "3:aaX8v:aV");
///     Ok(())
/// }
/// ```
///
/// # Note
///
/// This function expects that the file size does not change while
/// generating.  On normal use cases, you hash a fixed file to generate
/// a fuzzy hash to interchange information about the file with others.
/// So, this assumption should be safe for most users.
///
/// Also, failing to meet this requirement only causes this function to
/// return an error (incorrect result will not be produced).
/// So, this function is always safe.
///
/// If the file size could change while generating a fuzzy hash,
/// use [`hash_stream()`] instead.
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<RawFuzzyHash, GeneratorOrIOError> {
    let mut file = File::open(path)?;
    let mut generator = Generator::new();
    generator.set_fixed_input_size(file.metadata()?.len())?; // grcov-excl-br-line:IO
    hash_stream_common(&mut generator, &mut file)
}

mod tests;
