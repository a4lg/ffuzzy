// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// SPDX-FileCopyrightText: FNV-1 test vectors are based on a PD work by Landon Curt Noll, authored in 2013.

//! Tests: [`crate::generate`].

#![cfg(test)]

use alloc::format;
use alloc::vec::Vec;
use std::println;

use super::{Generator, GeneratorError};

use crate::hash::block::{
    block_hash, block_size, BlockHashSize as BHS, BlockHashSizes as BHSs,
    ConstrainedBlockHashSize as CBHS, ConstrainedBlockHashSizes as CBHSs,
};
use crate::hash::{FuzzyHashData, LongRawFuzzyHash, RawFuzzyHash};

macro_rules! call_for_generator_finalization {
    { $test: ident ($($tokens: tt)*) ; } => {
        $test::<false, {block_hash::FULL_SIZE}, {block_hash::HALF_SIZE}>($($tokens)*);
        $test::<true,  {block_hash::FULL_SIZE}, {block_hash::HALF_SIZE}>($($tokens)*);
        $test::<false, {block_hash::FULL_SIZE}, {block_hash::FULL_SIZE}>($($tokens)*);
        $test::<true,  {block_hash::FULL_SIZE}, {block_hash::FULL_SIZE}>($($tokens)*);
    }
}

#[rustfmt::skip]
#[test]
fn generator_error_impl_display() {
    assert_eq!(format!("{}", GeneratorError::FixedSizeMismatch), "current state mismatches to the fixed size previously set");
    assert_eq!(format!("{}", GeneratorError::FixedSizeTooLarge), "fixed size is too large to generate a fuzzy hash");
    assert_eq!(format!("{}", GeneratorError::InputSizeTooLarge), "input size is too large to generate a fuzzy hash");
    assert_eq!(format!("{}", GeneratorError::OutputOverflow),    "output is too large for specific fuzzy hash variant");
}

#[test]
fn generator_error_is_size_too_large_error() {
    assert!(!GeneratorError::FixedSizeMismatch.is_size_too_large_error());
    assert!(!GeneratorError::OutputOverflow.is_size_too_large_error());
    assert!(GeneratorError::FixedSizeTooLarge.is_size_too_large_error());
    assert!(GeneratorError::InputSizeTooLarge.is_size_too_large_error());
}

#[test]
fn cover_generator_basic() {
    // For coverage
    let _ = Generator::default();
}

#[test]
fn empty_data() {
    let mut generator = Generator::new();
    generator.set_fixed_input_size(0).unwrap();
    assert!(generator.may_warn_about_small_input_size());
    fn test_body<const TRUNC: bool, const S1: usize, const S2: usize>(generator: &Generator)
    where
        BHS<S1>: CBHS,
        BHS<S2>: CBHS,
        BHSs<S1, S2>: CBHSs,
    {
        let (typename, truncate) = (
            core::any::type_name::<FuzzyHashData<S1, S2, false>>(),
            TRUNC,
        );
        let hash = generator.finalize_raw::<TRUNC, S1, S2>().unwrap();
        assert_eq!(
            hash.block_size(),
            block_size::MIN,
            "failed on typename={:?}, truncate={}",
            typename,
            truncate
        );
        assert!(
            hash.block_hash_1().is_empty(),
            "failed on typename={:?}, truncate={}",
            typename,
            truncate
        );
        assert!(
            hash.block_hash_2().is_empty(),
            "failed on typename={:?}, truncate={}",
            typename,
            truncate
        );
    }
    call_for_generator_finalization! { test_body(&generator); }
}

#[test]
fn usage() {
    const STR: &[u8] = b"Hello, World!\n";
    let expected_hash: RawFuzzyHash = str::parse("3:aaX8v:aV").unwrap();

    // Usage: Single function call or series of calls
    // Update function 1: update_by_byte
    let mut generator = Generator::new();
    for &ch in STR.iter() {
        generator.update_by_byte(ch);
    }
    assert_eq!(generator.finalize().unwrap(), expected_hash);
    // Update function 2: update_by_iter
    let mut generator = Generator::new();
    generator.update_by_iter(STR.iter().cloned());
    assert_eq!(generator.finalize().unwrap(), expected_hash);
    // Update function 3: update
    let mut generator = Generator::new();
    generator.update(STR);
    assert_eq!(generator.finalize().unwrap(), expected_hash);

    // Usage: Chaining (update_by_byte and folding)
    let mut generator = Generator::new();
    let p1 = &generator as *const Generator;
    let generator_out = STR
        .iter()
        .fold(&mut generator, |hash, &ch| hash.update_by_byte(ch));
    let p2 = generator_out as *const Generator;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(generator.finalize().unwrap(), expected_hash);

    // Usage: Chaining (all update functions)
    let mut generator = Generator::new();
    let p1 = &generator as *const Generator;
    let generator_out = generator
        .update(b"Hello, ")
        .update_by_iter(b"World!".iter().cloned())
        .update_by_byte(b'\n');
    let p2 = generator_out as *const Generator;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(generator.finalize().unwrap(), expected_hash);

    // Usage: Add-assign operator
    const STR_1: &[u8] = b"Hello, "; // slice
    const STR_2: &[u8; 6] = b"World!"; // array
    let mut generator = Generator::new();
    generator += STR_1;
    generator += STR_2;
    generator += b'\n';
    assert_eq!(generator.finalize().unwrap(), expected_hash);
}

#[test]
fn verify_get_log_block_size_from_input_size() {
    // Compare behavior with the naïve implementation.
    fn get_log_block_size_from_input_size_naive(size: u64, start: usize) -> usize {
        let mut log_block_size = start;
        let mut max_guessed_size =
            Generator::guessed_preferred_max_input_size_at(log_block_size as u8);
        while max_guessed_size < size {
            log_block_size += 1;
            max_guessed_size *= 2;
        }
        log_block_size
    }
    for index in block_size::RANGE_LOG_VALID {
        let size = Generator::guessed_preferred_max_input_size_at(index);
        for start in block_size::RANGE_LOG_VALID.map(|x| x as usize) {
            assert_eq!(
                get_log_block_size_from_input_size_naive(size - 2, start),
                Generator::get_log_block_size_from_input_size(size - 2, start),
                "failed on index={}, start={}",
                index,
                start
            );
            assert_eq!(
                get_log_block_size_from_input_size_naive(size - 1, start),
                Generator::get_log_block_size_from_input_size(size - 1, start),
                "failed on index={}, start={}",
                index,
                start
            );
            assert_eq!(
                get_log_block_size_from_input_size_naive(size, start),
                Generator::get_log_block_size_from_input_size(size, start),
                "failed on index={}, start={}",
                index,
                start
            );
            if size + 1 <= Generator::MAX_INPUT_SIZE {
                assert_eq!(
                    get_log_block_size_from_input_size_naive(size + 1, start),
                    Generator::get_log_block_size_from_input_size(size + 1, start),
                    "failed on index={}, start={}",
                    index,
                    start
                );
            }
            if size + 2 <= Generator::MAX_INPUT_SIZE {
                assert_eq!(
                    get_log_block_size_from_input_size_naive(size + 2, start),
                    Generator::get_log_block_size_from_input_size(size + 2, start),
                    "failed on index={}, start={}",
                    index,
                    start
                );
            }
        }
    }
}

#[test]
fn usage_fixed_size() {
    let mut generator = Generator::new();
    // Set the fixed size.
    assert_eq!(generator.set_fixed_input_size(100), Ok(()));
    // Set the same fixed size.
    assert_eq!(generator.set_fixed_input_size(100), Ok(()));
    // Setting the different size will result in the error.
    assert_eq!(
        generator.set_fixed_input_size(999),
        Err(GeneratorError::FixedSizeMismatch)
    );
    // Generator::MAX_INPUT_SIZE is inclusive (but MAX_INPUT_SIZE+1 is not valid).
    let mut generator = Generator::new();
    assert_eq!(
        generator.set_fixed_input_size(Generator::MAX_INPUT_SIZE),
        Ok(())
    );
    let mut generator = Generator::new();
    assert_eq!(
        generator.set_fixed_input_size(Generator::MAX_INPUT_SIZE + 1),
        Err(GeneratorError::FixedSizeTooLarge)
    );
}

#[test]
fn length_mismatches() {
    const STR: &[u8] = b"Hello, World!";
    let mut generator = Generator::new();

    fn test_generator_fixed_size_mismatch<const TRUNC: bool, const S1: usize, const S2: usize>(
        generator: &Generator,
    ) where
        BHS<S1>: CBHS,
        BHS<S2>: CBHS,
        BHSs<S1, S2>: CBHSs,
    {
        let (typename, truncate) = (
            core::any::type_name::<FuzzyHashData<S1, S2, false>>(),
            TRUNC,
        );
        assert_eq!(
            generator.finalize_raw::<TRUNC, S1, S2>(),
            Err(GeneratorError::FixedSizeMismatch),
            "failed on typename={:?}, truncate={}",
            typename,
            truncate
        );
    }

    // Use update
    // Intentionally give a wrong size (this operation itself should succeed).
    assert_eq!(
        generator.set_fixed_input_size_in_usize(STR.len() - 1),
        Ok(())
    );
    generator.update(STR);
    assert_eq!(generator.input_size(), STR.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // Error occurs on finalization.
    assert_eq!(generator.finalize(), Err(GeneratorError::FixedSizeMismatch));
    call_for_generator_finalization! { test_generator_fixed_size_mismatch(&generator); }

    // Use update (and use the correct size)
    generator.reset();
    assert_eq!(generator.set_fixed_input_size_in_usize(STR.len()), Ok(()));
    generator.update(STR);
    assert_eq!(generator.input_size(), STR.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // No errors occur on finalization.
    assert!(generator.finalize().is_ok());

    // Use update_by_iter
    // Intentionally give a wrong size (this operation itself should succeed).
    generator.reset();
    assert_eq!(
        generator.set_fixed_input_size_in_usize(STR.len() - 1),
        Ok(())
    );
    generator.update_by_iter(STR.iter().cloned());
    assert_eq!(generator.input_size(), STR.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // Error occurs on finalization.
    assert_eq!(generator.finalize(), Err(GeneratorError::FixedSizeMismatch));
    call_for_generator_finalization! { test_generator_fixed_size_mismatch(&generator); }

    // Use update_by_iter (and use the correct size)
    generator.reset();
    assert_eq!(generator.set_fixed_input_size_in_usize(STR.len()), Ok(()));
    generator.update_by_iter(STR.iter().cloned());
    assert_eq!(generator.input_size(), STR.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // No errors occur on finalization.
    assert!(generator.finalize().is_ok());
}

// Internal function to generate a Generator object which virtually consumed
// specific count of zero bytes.
fn make_generator_with_prefix_zeroes(size: u64) -> Generator {
    use super::hashes::{partial_fnv, rolling_hash};
    let mut generator = Generator::new();
    generator.0.input_size = size;
    generator.0.roll_hash = rolling_hash::test_utils::new_hash_with_prefix_zeroes(size);
    generator.0.bh_context[0].h_full = partial_fnv::test_utils::new_hash_with_prefix_zeroes(size);
    generator.0.bh_context[0].h_half = partial_fnv::test_utils::new_hash_with_prefix_zeroes(size);
    generator
}

#[cfg(not(feature = "opt-reduce-fnv-table"))]
#[test]
fn test_make_generator_with_prefix_zeroes() {
    use super::hashes::partial_fnv::test_utils::ZERO_DATA_PERIOD;
    use super::RollingHash;
    let max_dense_check_size = ZERO_DATA_PERIOD * (RollingHash::WINDOW_SIZE as u64) * 2;
    // Check 0..=max_dense_check_size and sizes 2^n (between 1KiB..1MiB inclusive).
    for prefix_size in (0..=max_dense_check_size).chain((10..=20u32).map(|x| 1u64 << x)) {
        if prefix_size > Generator::MAX_INPUT_SIZE {
            continue;
        }
        let mut generator1 = Generator::new();
        for _ in 0..prefix_size {
            generator1.update_by_byte(0);
        }
        let generator2 = make_generator_with_prefix_zeroes(prefix_size);
        // Because the Generator object intentionally lacks the implementation
        // of PartialEq, we'll need to format using the Debug trait.
        //
        // Also, we need to disable this test when the feature
        // `opt-reduce-fnv-table` is enabled because it will have different
        // internal representation inside PartialFNVHash (masked by low 8 bits,
        // not 6 bits as expected in this test).
        assert_eq!(
            generator1.0, generator2.0,
            "failed on prefix_size={}",
            prefix_size
        );
    }
}

#[test]
fn large_data_triggers_1() {
    const LAST_USED_METHODS: &[&str] = &["update", "update_by_iter", "update_by_byte"];
    /*
        This test triggers "last hash" (FNV-based) output on the generator.

        Input size:
        96GiB + 1B

        SHA-256 of the generator input:
        08a6cdc1cdca3b173becd2c27f82588e36e41fe988f678100ca96a0952fe6de4

        Equivalent Tar+Zstd compressed archived file (GNU format) is available at:
        `ffuzzy/data/testsuite/generate/large_trigger_last_hash.bin.tar.zst`

        Be careful!  This Zstandard-compressed file can be zip bomb!
    */
    let mut last_bytes: [u8; 7 * 64 + 1] = [0u8; 7 * 64 + 1];
    for dest in last_bytes.chunks_exact_mut(7) {
        dest.clone_from_slice(b"`]]]_CT");
    }
    last_bytes[7 * 64] = 1;
    let generator_base = make_generator_with_prefix_zeroes(96 * 1024 * 1024 * 1024 - 7 * 64);
    // Append 7 bytes pattern 64 times **except** one 0x01.
    // Use update
    let mut generator1 = generator_base.clone();
    generator1.update(&last_bytes[0..(7 * 64)]);
    // Use update_by_iter
    let mut generator2 = generator_base.clone();
    generator2.update_by_iter(last_bytes[0..(7 * 64)].iter().cloned());
    // Use update_by_byte
    let mut generator3 = generator_base.clone();
    for &ch in last_bytes[0..(7 * 64)].iter() {
        generator3.update_by_byte(ch);
    }
    // Check all generators (for comparison; without the last byte)
    for (i, &generator) in [&generator1, &generator2, &generator3].iter().enumerate() {
        let last_method = LAST_USED_METHODS[i];
        assert_eq!(
            generator.0.input_size,
            96 * (1024 * 1024 * 1024),
            "failed on last_method={}",
            last_method
        );
        let hash_expected_long: LongRawFuzzyHash = str::parse("1610612736:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii").unwrap();
        let hash_expected_short: RawFuzzyHash = str::parse("1610612736:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiC").unwrap();
        let hash_expected_short_as_long = hash_expected_short.to_long_form();
        assert_eq!(
            generator
                .finalize_raw::<false, { block_hash::FULL_SIZE }, { block_hash::FULL_SIZE }>()
                .unwrap(),
            hash_expected_long,
            "failed on last_method={}",
            last_method
        );
        assert_eq!(
            generator.finalize_raw::<false, { block_hash::FULL_SIZE }, { block_hash::HALF_SIZE }>(),
            Err(GeneratorError::OutputOverflow),
            "failed on last_method={}",
            last_method
        );
        assert_eq!(
            generator
                .finalize_raw::<true, { block_hash::FULL_SIZE }, { block_hash::FULL_SIZE }>()
                .unwrap(),
            hash_expected_short_as_long,
            "failed on last_method={}",
            last_method
        );
        assert_eq!(
            generator
                .finalize_raw::<true, { block_hash::FULL_SIZE }, { block_hash::HALF_SIZE }>()
                .unwrap(),
            hash_expected_short,
            "failed on last_method={}",
            last_method
        );
    }

    // Append 7 bytes pattern 64 times **and** one 0x01.
    // Use update
    let mut generator1 = generator_base.clone();
    generator1.update(&last_bytes[..]);
    // Use update_by_iter
    let mut generator2 = generator_base.clone();
    generator2.update_by_iter(last_bytes.iter().cloned());
    // Use update_by_byte
    let mut generator3 = generator_base;
    for &ch in last_bytes.iter() {
        generator3.update_by_byte(ch);
    }
    // Check all generators
    for (i, &generator) in [&generator1, &generator2, &generator3].iter().enumerate() {
        let last_method = LAST_USED_METHODS[i];
        assert_eq!(
            generator.0.input_size,
            96 * (1024 * 1024 * 1024) + 1,
            "failed on last_method={}",
            last_method
        );
        assert!(
            !generator.may_warn_about_small_input_size(),
            "failed on last_method={}",
            last_method
        );
        fn test_body<const TRUNC: bool, const S1: usize, const S2: usize>(
            generator: &Generator,
            last_method: &str,
        ) where
            BHS<S1>: CBHS,
            BHS<S2>: CBHS,
            BHSs<S1, S2>: CBHSs,
        {
            let (typename, truncate) = (
                core::any::type_name::<FuzzyHashData<S1, S2, false>>(),
                TRUNC,
            );
            let hash_expected = str::parse::<FuzzyHashData<S1, S2, false>>(
                "3221225472:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiH:k",
            )
            .unwrap();
            assert_eq!(
                generator.finalize_raw::<TRUNC, S1, S2>(),
                Ok(hash_expected),
                "failed on typename={:?}, truncate={}, last_method={}",
                typename,
                truncate,
                last_method
            );
        }
        call_for_generator_finalization! { test_body(generator, last_method); }
    }
}

#[test]
fn large_data_triggers_2() {
    const LAST_USED_METHODS: &[&str] = &["update", "update_by_iter", "update_by_byte"];
    /*
        This test triggers "input too large error" by all-zero bytes.

        Input size:
        192GiB + 1B

        SHA-256 of the generator input:
        e613117320077150ddb32b33c2e8aaeaa63e9590a656c5aba04a91fa47d1c1b5
    */
    // Feed zero bytes until it reaches 192GiB-1B.
    let generator_base = make_generator_with_prefix_zeroes(192 * 1024 * 1024 * 1024 - 1);
    // Append two zero bytes:
    // Use update
    let mut generator1 = generator_base.clone();
    generator1.update(&[0, 0]);
    // Use update_by_iter
    let mut generator2 = generator_base.clone();
    generator2.update_by_iter([0, 0].iter().cloned());
    // Use update_by_byte
    let mut generator3 = generator_base;
    generator3.update_by_byte(0);
    generator3.update_by_byte(0);
    // Check all generators
    for (i, &generator) in [&generator1, &generator2, &generator3].iter().enumerate() {
        let last_method = LAST_USED_METHODS[i];
        assert!(
            generator.0.input_size > Generator::MAX_INPUT_SIZE,
            "failed on last_method={}",
            last_method
        );
        fn test_body<const TRUNC: bool, const S1: usize, const S2: usize>(
            generator: &Generator,
            last_method: &str,
        ) where
            BHS<S1>: CBHS,
            BHS<S2>: CBHS,
            BHSs<S1, S2>: CBHSs,
        {
            let (typename, truncate) = (
                core::any::type_name::<FuzzyHashData<S1, S2, false>>(),
                TRUNC,
            );
            assert_eq!(
                generator.finalize_raw::<TRUNC, S1, S2>(),
                Err(GeneratorError::InputSizeTooLarge),
                "failed on typename={:?}, truncate={}, last_method={}",
                typename,
                truncate,
                last_method
            );
        }
        call_for_generator_finalization! { test_body(generator, last_method); }
    }
}

#[test]
fn verify_with_small_precomputed_vectors() {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    #[cfg(not(feature = "alloc"))]
    use std::string::ToString;

    let index = BufReader::new(File::open("data/testsuite/generate-small.ssdeep.txt").unwrap());
    let mut generator = Generator::new();
    for index_ln in index.lines() {
        /*
            Read a line from the index file.
        */
        let index_ln = index_ln.unwrap();
        if index_ln.is_empty() || index_ln.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = index_ln.split_whitespace().collect();
        assert!(
            tokens.len() == 3,
            "failed while processing the test index file with line {:?}",
            index_ln
        );
        // $1: filename
        let filename = tokens[0];
        // $2: flags (truncated or non-truncated, or check both)
        const TEST_TRUNC_1: u8 = 1;
        const TEST_TRUNC_0: u8 = 2;
        const TEST_ELIMSEQ: u8 = 4; // Do the normalization.
        const TEST_WASLONG: u8 = 8; // Long fuzzy hash before normalization.
        let flags = str::parse::<u8>(tokens[1]).unwrap();
        // $3: expected fuzzy hash
        let fuzzy_str = tokens[2];
        let fuzzy_expected: LongRawFuzzyHash = str::parse(fuzzy_str).unwrap();
        /*
            Read the corresponding file.
        */
        let mut contents = Vec::<u8>::new();
        File::open(filename)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        /*
            Test fuzzy hash generator as follows:
        */
        println!("Testing: {}...", filename);
        // Note:
        // Some explicit type annotation (including following two lines) is
        // to make sure that the result of finalize_raw method matches the
        // expected type,
        if (flags & TEST_TRUNC_1) != 0 {
            /*
                Test the generator with truncation.
            */
            let mut fuzzy_expected_trunc: RawFuzzyHash = RawFuzzyHash::new();
            fuzzy_expected
                .try_into_mut_short(&mut fuzzy_expected_trunc)
                .unwrap();
            // Test three ways to generate fuzzy hashes
            {
                fn check_results(
                    filename: &str,
                    generator: &Generator,
                    flags: u8,
                    fuzzy_str: &str,
                    fuzzy_expected: &LongRawFuzzyHash,
                    fuzzy_expected_trunc: &RawFuzzyHash,
                ) {
                    let mut fuzzy_generated: LongRawFuzzyHash = generator
                        .finalize_raw::<true, { block_hash::FULL_SIZE }, { block_hash::FULL_SIZE }>(
                        )
                        .unwrap();
                    let mut fuzzy_generated_trunc: RawFuzzyHash = generator
                        .finalize_raw::<true, { block_hash::FULL_SIZE }, { block_hash::HALF_SIZE }>(
                        )
                        .unwrap();
                    if (flags & TEST_ELIMSEQ) != 0 {
                        fuzzy_generated.normalize_in_place();
                        fuzzy_generated_trunc.normalize_in_place();
                    }
                    assert_eq!(
                        *fuzzy_expected, fuzzy_generated,
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename, flags, fuzzy_str
                    );
                    assert_eq!(
                        *fuzzy_expected_trunc, fuzzy_generated_trunc,
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename, flags, fuzzy_str
                    );
                    assert_eq!(
                        fuzzy_str,
                        fuzzy_generated.to_string(),
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename,
                        flags,
                        fuzzy_str
                    );
                    assert_eq!(
                        fuzzy_str,
                        fuzzy_generated_trunc.to_string(),
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename,
                        flags,
                        fuzzy_str
                    );
                }
                generator.reset();
                generator.update(contents.as_slice());
                check_results(
                    filename,
                    &generator,
                    flags,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
                generator.reset();
                generator.update_by_iter(contents.iter().cloned());
                check_results(
                    filename,
                    &generator,
                    flags,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
                generator.reset();
                for &b in contents.iter() {
                    generator.update_by_byte(b);
                }
                check_results(
                    filename,
                    &generator,
                    flags,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
            }
        }
        if (flags & TEST_TRUNC_0) != 0 {
            /*
                Test the generator without truncation.
            */
            let is_long = fuzzy_expected.block_hash_2().len() > block_hash::HALF_SIZE;
            let mut fuzzy_expected_trunc: RawFuzzyHash = RawFuzzyHash::new();
            match fuzzy_expected.try_into_mut_short(&mut fuzzy_expected_trunc) {
                Ok(_) => assert!(
                    !is_long,
                    "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                    filename, flags, fuzzy_str
                ),
                Err(_) => assert!(
                    is_long,
                    "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                    filename, flags, fuzzy_str
                ), // Consider truncation error.
            }
            // Test three ways to generate fuzzy hashes
            {
                fn check_results(
                    filename: &str,
                    generator: &Generator,
                    flags: u8,
                    is_long: bool,
                    fuzzy_str: &str,
                    fuzzy_expected: &LongRawFuzzyHash,
                    fuzzy_expected_trunc: &RawFuzzyHash,
                ) {
                    let mut fuzzy_generated: LongRawFuzzyHash =
                        generator.finalize_without_truncation().unwrap();
                    let mut fuzzy_generated_trunc: RawFuzzyHash = match generator.finalize_raw::<false, {block_hash::FULL_SIZE}, {block_hash::HALF_SIZE}>() {
                        Ok(h) => {
                            assert!(!is_long, "failed on filename={:?}, flags={}, fuzzy_str={:?}", filename, flags, fuzzy_str);
                            h
                        },
                        Err(_) => {
                            // Consider truncation error.
                            assert!(is_long || (flags & TEST_WASLONG) != 0, "failed on filename={:?}, flags={}, fuzzy_str={:?}", filename, flags, fuzzy_str);
                            if is_long {
                                RawFuzzyHash::new()
                            }
                            else {
                                RawFuzzyHash::try_from(fuzzy_generated.clone_normalized()).unwrap()
                            }
                        }
                    };
                    if (flags & TEST_ELIMSEQ) != 0 {
                        fuzzy_generated.normalize_in_place();
                        fuzzy_generated_trunc.normalize_in_place();
                    }
                    assert_eq!(
                        *fuzzy_expected, fuzzy_generated,
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename, flags, fuzzy_str
                    );
                    assert_eq!(
                        *fuzzy_expected_trunc, fuzzy_generated_trunc,
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename, flags, fuzzy_str
                    );
                    assert_eq!(
                        fuzzy_str,
                        fuzzy_generated.to_string(),
                        "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                        filename,
                        flags,
                        fuzzy_str
                    );
                    if !is_long {
                        assert_eq!(
                            fuzzy_str,
                            fuzzy_generated_trunc.to_string(),
                            "failed on filename={:?}, flags={}, fuzzy_str={:?}",
                            filename,
                            flags,
                            fuzzy_str
                        );
                    }
                }
                generator.reset();
                generator.update(contents.as_slice());
                check_results(
                    filename,
                    &generator,
                    flags,
                    is_long,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
                generator.reset();
                generator.update_by_iter(contents.iter().cloned());
                check_results(
                    filename,
                    &generator,
                    flags,
                    is_long,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
                generator.reset();
                for &b in contents.iter() {
                    generator.update_by_byte(b);
                }
                check_results(
                    filename,
                    &generator,
                    flags,
                    is_long,
                    fuzzy_str,
                    &fuzzy_expected,
                    &fuzzy_expected_trunc,
                );
            }
        }
    }
}
