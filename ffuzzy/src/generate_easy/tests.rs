// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::generate_easy`].

#![cfg(test)]

use super::hash_buf;

#[test]
fn hash_buf_usage() {
    #[cfg(not(feature = "alloc"))]
    use std::string::ToString;
    assert_eq!(
        hash_buf(b"Hello, World!\n").unwrap().to_string(),
        "3:aaX8v:aV"
    );
}

// TODO: Once existence of an 128-bit machine is realistic, change #[cfg] below.
#[cfg(not(miri))]
#[cfg(target_pointer_width = "64")]
#[test]
fn hash_buf_input_too_large() {
    use crate::generate::{Generator, GeneratorError};
    unsafe {
        // Supply (most likely invalid) too large buffer and expect an error happens
        // before an actual access happens (GeneratorError::FixedSizeTooLarge).
        // Because this test contains an "unsound" operation detected by Miri
        // (although no real invalid dereference occurs), this test case is
        // disabled on Miri.
        let too_large_size = (Generator::MAX_INPUT_SIZE + 1) as usize;
        let buf =
            core::slice::from_raw_parts(core::ptr::NonNull::dangling().as_ptr(), too_large_size);
        assert_eq!(hash_buf(buf), Err(GeneratorError::FixedSizeTooLarge));
    }
}
