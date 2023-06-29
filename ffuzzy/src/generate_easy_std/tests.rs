// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use std::error::Error;
use std::io::Read;
use std::fs::File;

use crate::generate::{Generator, GeneratorError};
use crate::generate_easy_std::{
    GeneratorOrIOError,
    hash_file,
    hash_stream,
    hash_stream_common,
};


#[test]
fn hash_file_usage() {
    let hash = hash_file("data/examples/hello.txt");
    assert!(hash.is_ok());
    assert_eq!(hash.unwrap().to_string(), "3:aaX8v:aV");
}

#[test]
fn hash_file_not_exist() {
    let err = hash_file("data/examples/nonexistent.bin");
    if let Err(GeneratorOrIOError::IOError(err)) = err {
        let str_display_bare = format!("{}", err);
        let str_debug_bare = format!("{:?}", err);
        // This error is the "file not found" error.
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        // Recover the original GeneratorOrIoError::IOError.
        let orig_error = GeneratorOrIOError::IOError(err);
        // Display: GeneratorOrIoError displays the same message as the underlying error.
        assert_eq!(
            format!("{}", orig_error),
            str_display_bare
        );
        // Debug: default implementation for IOError
        assert_eq!(
            format!("{:?}", orig_error),
            format!("IOError({})", str_debug_bare)
        );
        // Display+Debug: GeneratorOrIoError::source() returns the underlying std::io::Error object.
        assert_eq!(
            format!("{}", orig_error.source().unwrap().downcast_ref::<std::io::Error>().unwrap()),
            str_display_bare
        );
        assert_eq!(
            format!("{:?}", orig_error.source().unwrap().downcast_ref::<std::io::Error>().unwrap()),
            str_debug_bare
        );
    }
    else {
        // grcov-excl-start
        panic!("the error must be an IOError");
        // grcov-excl-stop
    }
}

#[test]
fn hash_stream_common_usage() {
    let mut file = File::open("data/examples/hello.txt").unwrap();
    let hash = hash_stream(&mut file);
    assert!(hash.is_ok());
    assert_eq!(hash.unwrap().to_string(), "3:aaX8v:aV");
}

#[test]
fn hash_stream_common_size_inconsistency() {
    let mut file = File::open("data/examples/hello.txt").unwrap();
    let mut generator = Generator::new();
    // Give wrong size to cause a GeneratorError::FixedSizeMismatch error.
    generator.set_fixed_input_size(0).unwrap();
    // Get an error.
    let err = hash_stream_common(&mut generator, &mut file);
    if let Err(GeneratorOrIOError::GeneratorError(err)) = err {
        let str_display_bare = format!("{}", err);
        let str_debug_bare = format!("{:?}", err);
        // This error is the "fixed size mismatch" error.
        assert_eq!(err, GeneratorError::FixedSizeMismatch);
        // Recover the original GeneratorOrIoError::GeneratorError.
        let orig_error = GeneratorOrIOError::GeneratorError(err);
        // Display: GeneratorOrIoError displays the same message as the underlying error.
        assert_eq!(
            format!("{}", orig_error),
            str_display_bare
        );
        // Debug: default implementation for GeneratorError
        assert_eq!(
            format!("{:?}", orig_error),
            format!("GeneratorError({})", str_debug_bare)
        );
        // Display+Debug: GeneratorOrIoError::source() returns the underlying GeneratorError object.
        assert_eq!(
            format!("{}", orig_error.source().unwrap().downcast_ref::<GeneratorError>().unwrap()),
            str_display_bare
        );
        assert_eq!(
            format!("{:?}", orig_error.source().unwrap().downcast_ref::<GeneratorError>().unwrap()),
            str_debug_bare
        );
    }
    else {
        // grcov-excl-start
        panic!("the error must be a GeneratorError");
        // grcov-excl-stop
    }
}

#[test]
fn hash_stream_common_io_fail() {
    // Custom Read implementation (which always fails)
    struct IOFail;
    impl Read for IOFail {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::Other))
        }
    }
    // Get an error.
    let mut generator = Generator::new();
    let err = hash_stream_common(&mut generator, &mut IOFail);
    if let Err(GeneratorOrIOError::IOError(err)) = err {
        let str_display_bare = format!("{}", err);
        let str_debug_bare = format!("{:?}", err);
        // This error is the "other" error.
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        // Recover the original GeneratorOrIoError::IOError.
        let orig_error = GeneratorOrIOError::IOError(err);
        // Display: GeneratorOrIoError displays the same message as the underlying error.
        assert_eq!(
            format!("{}", orig_error),
            str_display_bare
        );
        // Debug: default implementation for IOError
        assert_eq!(
            format!("{:?}", orig_error),
            format!("IOError({})", str_debug_bare)
        );
        // Display+Debug: GeneratorOrIoError::source() returns the underlying std::io::Error object.
        assert_eq!(
            format!("{}", orig_error.source().unwrap().downcast_ref::<std::io::Error>().unwrap()),
            str_display_bare
        );
        assert_eq!(
            format!("{:?}", orig_error.source().unwrap().downcast_ref::<std::io::Error>().unwrap()),
            str_debug_bare
        );
    }
    else {
        // grcov-excl-start
        panic!("the error must be an IOError");
        // grcov-excl-stop
    }
}
