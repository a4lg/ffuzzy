// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::cmp::Ordering;
use collect_slice::CollectSlice;

use crate::base64::BASE64_INVALID;
use crate::hash::{
    FuzzyHashData,
    FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash,
    FuzzyHashOperationError
};
use crate::hash::block::{block_size, block_hash};
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin
};
use crate::hash::test_utils::{
    test_blockhash_contents_all,
    test_blockhash_contents_no_sequences
};
use crate::test_utils::{assert_fits_in, test_auto_clone, test_for_each_type};
use crate::test_utils::test_auto_debug_for_enum;


#[test]
fn fuzzy_hash_operation_error_impls() {
    // Test Clone
    test_auto_clone::<FuzzyHashOperationError>(&FuzzyHashOperationError::BlockHashOverflow);
    // Test Display
    assert_eq!(format!("{}", FuzzyHashOperationError::BlockHashOverflow),     "overflow will occur while copying the block hash");
    assert_eq!(format!("{}", FuzzyHashOperationError::StringizationOverflow), "overflow will occur while converting to the string representation");
    // Test Debug
    test_auto_debug_for_enum!(
        FuzzyHashOperationError,
        [
            BlockHashOverflow,
            StringizationOverflow,
        ]
    );
}


macro_rules! test_for_each_block_hash_sizes {
    ($test: ident) => {
        loop { $test!(block_hash::FULL_SIZE, block_hash::FULL_SIZE); break; }
        loop { $test!(block_hash::FULL_SIZE, block_hash::HALF_SIZE); break; }
    };
}


#[test]
fn data_model_new() {
    // Prerequisites
    assert_eq!(block_size::MIN, 3);
    // Test constructs
    macro_rules! test {
        ($ty: ty) => {
            let typename = stringify!($ty);
            let hash_new: $ty = <$ty>::new();
            let hash_default: $ty = <$ty>::default();
            let hash_cloned: $ty = hash_new.clone();
            let hash_from_str: $ty = str::parse::<$ty>("3::").unwrap();
            let hash_from_bytes: $ty = <$ty>::from_bytes(b"3::").unwrap();
            // Test validity of the empty value.
            assert!(hash_new.is_valid(),     "failed (1-1) on typename={}", typename);
            assert!(hash_default.is_valid(), "failed (1-2) on typename={}", typename);
            assert!(hash_cloned.is_valid(),  "failed (1-3) on typename={}", typename);
            // Test validity of fuzzy hashes converted from "empty" fuzzy hash string.
            assert!(hash_from_str.is_valid(),   "failed (2-1) on typename={}", typename);
            assert!(hash_from_bytes.is_valid(), "failed (2-2) on typename={}", typename);
            // Compare two values.
            assert_eq!(hash_new, hash_default,    "failed (3-1) on typename={}", typename);
            assert_eq!(hash_new, hash_cloned,     "failed (3-2) on typename={}", typename);
            assert_eq!(hash_new, hash_from_str,   "failed (3-3) on typename={}", typename);
            assert_eq!(hash_new, hash_from_bytes, "failed (3-4) on typename={}", typename);
            assert!(hash_new.full_eq(&hash_default),    "failed (4-1) on typename={}", typename);
            assert!(hash_new.full_eq(&hash_cloned),     "failed (4-2) on typename={}", typename);
            assert!(hash_new.full_eq(&hash_from_str),   "failed (4-3) on typename={}", typename);
            assert!(hash_new.full_eq(&hash_from_bytes), "failed (4-4) on typename={}", typename);
        };
    }
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn data_model_init_and_basic() {
    /*
        1. Initialization from Internal Data (only valid cases)
            *   init_from_internals_raw
            *   init_from_internals_raw_internal
            *   init_from_internals_raw_unchecked
            *   new_from_internals_raw
            *   new_from_internals_raw_internal
            *   new_from_internals_raw_unchecked
            *   new_from_internals
            *   new_from_internals_internal
            *   new_from_internals_unchecked
            *   new_from_internals_near_raw
            *   new_from_internals_near_raw_internal
            *   new_from_internals_near_raw_unchecked
        2. Direct Mapping to the Internal Data
            *   block_hash_1
            *   block_hash_2
            *   block_hash_1_as_array
            *   block_hash_2_as_array
            *   block_hash_1_len
            *   block_hash_2_len
            *   log_block_size
            *   block_size
        3. Plain Copy of the Internal Data
            *   clone
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
            let log_block_size_raw = log_block_size as u8;
            let block_size = block_size::from_log(log_block_size_raw).unwrap();
            macro_rules! test {
                ($bh1sz: expr, $bh2sz: expr) => {
                    let bh1sz = $bh1sz;
                    let bh2sz = $bh2sz;
                    type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, false>;
                    macro_rules! init_hash {
                        (
                            $test_num: literal,
                            $ty: ty,
                            $bh1: expr, $bh2: expr
                        ) => {{
                            let test_num = $test_num;
                            let bh1 = $bh1;
                            let bh2 = $bh2;
                            // Initialize raw block hash representations
                            // (remaining bytes are zero-filled)
                            let mut blockhash1 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1];
                            let mut blockhash2 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2];
                            blockhash1[..bh1.len()].copy_from_slice(bh1);
                            blockhash2[..bh2.len()].copy_from_slice(bh2);
                            // Prepare raw lengths
                            let len_bh1_raw = u8::try_from(bh1.len()).unwrap();
                            let len_bh2_raw = u8::try_from(bh2.len()).unwrap();
                            // Create fuzzy hashes in various ways and make sure that they are all the same.
                            let mut hash1: $ty = <$ty>::new();
                            hash1.init_from_internals_raw_internal(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                            let hash2: $ty =
                                <$ty>::new_from_internals_raw_internal(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                            let mut hash3: $ty = <$ty>::new();
                            hash3.init_from_internals_raw(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                            let hash4: $ty =
                                <$ty>::new_from_internals_raw(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                            let hash5: $ty =
                                <$ty>::new_from_internals_internal(block_size, bh1, bh2);
                            let hash6: $ty =
                                <$ty>::new_from_internals(block_size, bh1, bh2);
                            let hash7: $ty = hash1.clone();
                            let hash8: $ty = <$ty>::new_from_internals_near_raw_internal(log_block_size_raw, bh1, bh2);
                            let hash9: $ty = <$ty>::new_from_internals_near_raw(log_block_size_raw, bh1, bh2);
                            assert_eq!(hash1, hash2, "failed ({}-1-1-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash3, "failed ({}-1-1-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash4, "failed ({}-1-1-3) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash5, "failed ({}-1-1-4) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash6, "failed ({}-1-1-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash7, "failed ({}-1-1-6) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash8, "failed ({}-1-1-7) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash1, hash9, "failed ({}-1-1-8) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash2), "failed ({}-1-2-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash3), "failed ({}-1-2-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash4), "failed ({}-1-2-3) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash5), "failed ({}-1-2-4) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash6), "failed ({}-1-2-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash7), "failed ({}-1-2-6) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash8), "failed ({}-1-2-7) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert!(hash1.full_eq(&hash9), "failed ({}-1-2-8) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            #[cfg(feature = "unchecked")]
                            unsafe {
                                let mut hash_u1: $ty = <$ty>::new();
                                hash_u1.init_from_internals_raw_unchecked(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                                let hash_u2: $ty =
                                    <$ty>::new_from_internals_raw_unchecked(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                                let hash_u5: $ty = <$ty>::new_from_internals_unchecked(block_size, bh1, bh2);
                                let hash_u8: $ty = <$ty>::new_from_internals_near_raw_unchecked(log_block_size_raw, bh1, bh2);
                                assert_eq!(hash1, hash_u1, "failed ({}-2-1-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert_eq!(hash1, hash_u2, "failed ({}-2-1-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert_eq!(hash1, hash_u5, "failed ({}-2-1-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert_eq!(hash1, hash_u8, "failed ({}-2-1-8) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert!(hash1.full_eq(&hash_u1), "failed ({}-2-2-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert!(hash1.full_eq(&hash_u2), "failed ({}-2-2-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert!(hash1.full_eq(&hash_u5), "failed ({}-2-2-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                                assert!(hash1.full_eq(&hash_u8), "failed ({}-2-2-8) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            }
                            let hash: $ty = hash1;
                            // Check raw values
                            assert_eq!(hash.blockhash1, blockhash1, "failed ({}-3-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.blockhash2, blockhash2, "failed ({}-3-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.len_blockhash1, len_bh1_raw, "failed ({}-3-3) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.len_blockhash2, len_bh2_raw, "failed ({}-3-4) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.log_blocksize, log_block_size_raw, "failed ({}-3-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            // Check direct correspondence to raw values
                            assert_eq!(hash.block_hash_1(), bh1, "failed ({}-4-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_hash_2(), bh2, "failed ({}-4-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_hash_1_as_array(), &blockhash1, "failed ({}-4-3) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_hash_2_as_array(), &blockhash2, "failed ({}-4-4) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_hash_1_len(), bh1.len(), "failed ({}-4-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_hash_2_len(), bh2.len(), "failed ({}-4-6) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.log_block_size(), log_block_size_raw, "failed ({}-4-7) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            assert_eq!(hash.block_size(), block_size, "failed ({}-4-8) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, bh1sz, bh2sz, log_block_size, bh1, bh2);
                            hash
                        }};
                    }
                    // Initialize from both forms of block hashes
                    // However, initialization methods tested here requires block hashes to be normalized.
                    let hash_norm: Option<FuzzyHashType> =
                        (bh2_norm.len() <= FuzzyHashType::MAX_BLOCK_HASH_SIZE_2 && is_normalized)
                            .then(|| init_hash!(1, FuzzyHashType, bh1_norm, bh2_norm));
                    let hash_raw: Option<RawFuzzyHashType> =
                        (bh2.len() <= FuzzyHashType::MAX_BLOCK_HASH_SIZE_2)
                            .then(|| init_hash!(2, RawFuzzyHashType, bh1, bh2));
                    if let Some(hash_norm) = hash_norm {
                        assert!(hash_norm.is_valid(), "failed (3-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, log_block_size, bh1_norm, bh2_norm);
                        assert!(hash_norm.is_normalized(), "failed (3-2) on bh1sz={}, bh2sz={}, log_block_size={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, log_block_size, bh1_norm, bh2_norm);
                    }
                    if let Some(hash_raw) = hash_raw {
                        assert!(hash_raw.is_valid(), "failed (3-3) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, log_block_size, bh1, bh2);
                        assert_eq!(
                            is_normalized,
                            hash_raw.is_normalized(),
                            "failed (3-4) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, log_block_size, bh1, bh2
                        );
                        // Because of length constraints, there must be a normalized fuzzy hash
                        // when the block hashes are already normalized (this is a requirement of the normalized form).
                        assert_eq!(
                            is_normalized,
                            hash_norm.is_some(),
                            "failed (3-5) on bh1sz={}, bh2sz={}, log_block_size={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, log_block_size, bh1_norm, bh2_norm
                        );
                        if let Some(hash_norm) = hash_norm {
                            // Transplant the data and compare (equals only if the input block hashes are already normalized)
                            let mut hash_norm_transplanted: RawFuzzyHashType = RawFuzzyHashType::new();
                            hash_norm_transplanted.blockhash1 = hash_norm.blockhash1;
                            hash_norm_transplanted.blockhash2 = hash_norm.blockhash2;
                            hash_norm_transplanted.len_blockhash1 = hash_norm.len_blockhash1;
                            hash_norm_transplanted.len_blockhash2 = hash_norm.len_blockhash2;
                            hash_norm_transplanted.log_blocksize = hash_norm.log_blocksize;
                            assert_eq!(
                                is_normalized,
                                hash_raw.full_eq(&hash_norm_transplanted),
                                "failed (4-1) on bh1sz={}, bh2sz={}, log_block_size={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, log_block_size, bh1, bh2
                            );
                        }
                    }
                };
            }
            test_for_each_block_hash_sizes!(test);
        }
    });
}

fn make_fuzzy_hash_bytes(
    out: &mut [u8; crate::MAX_LEN_IN_STR],
    log_block_size: u8,
    block_hash_1: &[u8],
    block_hash_2: &[u8]
) -> usize
{
    use crate::hash::algorithms::insert_block_hash_into_bytes;
    let mut bh1_raw = [0u8; block_hash::FULL_SIZE];
    let mut bh2_raw = [0u8; block_hash::FULL_SIZE];
    bh1_raw[..block_hash_1.len()].copy_from_slice(block_hash_1);
    bh2_raw[..block_hash_2.len()].copy_from_slice(block_hash_2);
    let bh1_len = u8::try_from(block_hash_1.len()).unwrap();
    let bh2_len = u8::try_from(block_hash_2.len()).unwrap();
    let mut p = 0;
    let bs_str = block_size::BLOCK_SIZES_STR[log_block_size as usize].as_bytes();
    out.fill(0);
    out[p..p+bs_str.len()].copy_from_slice(bs_str);
    p += bs_str.len();
    out[p] = b':';
    p += 1;
    insert_block_hash_into_bytes(&mut out[p..p+block_hash_1.len()], &bh1_raw, bh1_len);
    p += block_hash_1.len();
    out[p] = b':';
    p += 1;
    insert_block_hash_into_bytes(&mut out[p..p+block_hash_2.len()], &bh2_raw, bh2_len);
    p += block_hash_2.len();
    p
}

pub(crate) struct FuzzyHashStringBytes {
    buffer: [u8; crate::MAX_LEN_IN_STR],
    len: usize
}
impl FuzzyHashStringBytes {
    #[inline(always)]
    pub fn new(log_block_size: u8, block_hash_1: &[u8], block_hash_2: &[u8]) -> Self {
        let mut obj = Self { buffer: [0u8; crate::MAX_LEN_IN_STR], len: 0 };
        obj.len = make_fuzzy_hash_bytes(&mut obj.buffer, log_block_size, block_hash_1, block_hash_2);
        obj
    }
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

#[test]
fn make_fuzzy_hash_bytes_examples() {
    // Prerequisites
    assert_eq!(block_size::MIN, 3);
    assert!(block_size::NUM_VALID >= 12);
    assert!(block_hash::MAX_SEQUENCE_SIZE < 8);
    // Simple examples.
    assert_eq!(
        FuzzyHashStringBytes::new(0, &[], &[]).as_bytes(),
        b"3::"
    );
    assert_eq!(
        FuzzyHashStringBytes::new(1, &[0, 1, 2, 3, 4, 5, 6], &[26, 27, 28, 29, 30, 31, 32]).as_bytes(),
        b"6:ABCDEFG:abcdefg"
    );
    // Half empty.
    assert_eq!(
        FuzzyHashStringBytes::new(2, &[0, 1, 2, 3, 4, 5, 6], &[]).as_bytes(),
        b"12:ABCDEFG:"
    );
    assert_eq!(
        FuzzyHashStringBytes::new(2, &[], &[26, 27, 28, 29, 30, 31, 32]).as_bytes(),
        b"12::abcdefg"
    );
    // No normalization occurs (repeats the same character "8" times which makes the prerequisite above).
    assert_eq!(
        FuzzyHashStringBytes::new(3, &[0, 0, 0, 0, 0, 0, 0, 0], &[1, 1, 1, 1, 1, 1, 1, 1]).as_bytes(),
        b"24:AAAAAAAA:BBBBBBBB"
    );
    // Excerpts from BLOCK_HASH_SAMPLE_DATA inside
    // crate::compare::tests::comparison_with_block_size_pairs ([0] and [1] are used).
    assert_eq!(
        FuzzyHashStringBytes::new(10, &[59, 12, 10, 19, 21, 28, 60, 56, 61, 42, 56, 18, 19, 16, 17, 45, 34, 50, 57, 13], &[62]).as_bytes(),
        b"3072:7MKTVc849q4STQRtiy5N:+"
    );
    assert_eq!(
        FuzzyHashStringBytes::new(11, &[63], &[45, 12, 10, 19, 21, 28, 60, 56, 22, 22, 27, 56, 18, 16, 39, 14, 14, 34, 60, 57]).as_bytes(),
        b"6144:/:tMKTVc84WWb4SQnOOi85"
    );
}

#[test]
fn data_model_block_hash_contents_basic() {
    /*
        1. Initialization from Byte String
            *   from_bytes
        2. Direct Mapping to the Internal Data (again, more complete)
            *   block_hash_1
            *   block_hash_2
            *   block_hash_1_as_array
            *   block_hash_2_as_array
            *   block_hash_1_len
            *   block_hash_2_len
            *   log_block_size
            *   block_size
        3. Normalization (partial; related to the input normalization)
            *   is_normalized
    */
    // Test block hash contents.
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let block_size = block_size::from_log(log_block_size_raw).unwrap();
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($bh1sz: expr, $bh2sz: expr) => {
                    let bh1sz = $bh1sz;
                    let bh2sz = $bh2sz;
                    type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, false>;
                    assert_eq!(is_normalized, bytes_norm == bytes_raw, "failed (1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    // Initialize and Check fuzzy hashes
                    macro_rules! init_and_check_hash {
                        (
                            $test_num: literal,
                            $is_input_norm: expr,
                            $ty: ty,
                            $bytes: expr
                        ) => {{
                            let test_num = $test_num;
                            let hash_opt: Option<$ty> = <$ty>::from_bytes($bytes).ok();
                            if let Some(hash) = hash_opt {
                                let bytes_str = core::str::from_utf8($bytes).unwrap();
                                let hash_is_normalized = <$ty>::IS_NORMALIZED_FORM || is_normalized || $is_input_norm;
                                let bh1_expected = if hash_is_normalized { bh1_norm } else { bh1 };
                                let bh2_expected = if hash_is_normalized { bh2_norm } else { bh2 };
                                let mut bh1_expected_raw = [0u8; $bh1sz];
                                let mut bh2_expected_raw = [0u8; $bh2sz];
                                bh1_expected_raw[..bh1_expected.len()].copy_from_slice(bh1_expected);
                                bh2_expected_raw[..bh2_expected.len()].copy_from_slice(bh2_expected);
                                assert!(hash.is_valid(), "failed ({}-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.is_normalized(), hash_is_normalized,
                                    "failed ({}-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Check raw values
                                assert_eq!(hash.blockhash1, bh1_expected_raw, "failed ({}-2-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.blockhash2, bh2_expected_raw, "failed ({}-2-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.len_blockhash1, u8::try_from(bh1_expected.len()).unwrap(), "failed ({}-2-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.len_blockhash2, u8::try_from(bh2_expected.len()).unwrap(), "failed ({}-2-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.log_blocksize, log_block_size_raw, "failed ({}-2-5) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Check direct correspondence to raw values
                                assert_eq!(hash.block_hash_1(), bh1_expected, "failed ({}-3-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_hash_2(), bh2_expected, "failed ({}-3-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_hash_1_as_array(), &bh1_expected_raw, "failed ({}-3-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_hash_2_as_array(), &bh2_expected_raw, "failed ({}-3-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_hash_1_len(), bh1_expected.len(), "failed ({}-3-5) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_hash_2_len(), bh2_expected.len(), "failed ({}-3-6) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.log_block_size(), log_block_size_raw, "failed ({}-3-7) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(hash.block_size(), block_size, "failed ({}-3-8) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                            }
                            hash_opt
                        }};
                    }
                    let opt_hash_norm          : Option<FuzzyHashType>    = init_and_check_hash!(2,  true, FuzzyHashType, bytes_norm);
                    let opt_hash_norm_from_raw : Option<FuzzyHashType>    = init_and_check_hash!(3, false, FuzzyHashType, bytes_raw);
                    let opt_hash_raw           : Option<RawFuzzyHashType> = init_and_check_hash!(4, false, RawFuzzyHashType, bytes_raw);
                    let opt_hash_raw_from_norm : Option<RawFuzzyHashType> = init_and_check_hash!(5,  true, RawFuzzyHashType, bytes_norm);
                    /*
                        Implication Chart (guaranteed by this crate):
                            raw           -> (raw_from_norm, norm, norm_from_raw) [6-1, 6-2, 6-3]
                            norm          -> raw_from_norm                        [6-1]
                            raw_from_norm -> norm  (or norm <-> raw_from_norm)    [6-1]
                            norm_from_raw -> norm                                 [6-4]
                        Implication Chart (current implementation, not tested here):
                            norm          -> norm_from_raw  (or norm <-> norm_from_raw)
                    */
                    assert_eq!(opt_hash_raw_from_norm.is_some(), opt_hash_norm.is_some(),
                        "failed (6-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    if opt_hash_raw.is_some() {
                        assert!(opt_hash_norm.is_some(), "failed (6-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(opt_hash_norm_from_raw.is_some(), "failed (6-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // opt_hash_raw_from_norm.is_some() is checked by 6-1 and 6-2.
                    }
                    /*
                        Note:
                        opt_hash_norm and opt_hash_norm_from_raw are always the same in the current implementation
                        but this is not guaranteed (if opt_hash_norm_from_raw is None, opt_hash_norm is not necessarily None).
                        However, if opt_hash_norm_from_raw is Some, opt_hash_norm is also always Some.
                    */
                    if opt_hash_norm_from_raw.is_some() {
                        assert!(opt_hash_norm.is_some(), "failed (6-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                };
            }
            test_for_each_block_hash_sizes!(test);
        }
    });
}

#[test]
fn data_model_block_hash_contents_and_lossless_conversion() {
    /*
        1. Lossless conversion
            *   from
            *   to_raw_form
            *   from_normalized
            *   to_long_form
            *   from_short_form
            *   into_mut_raw_form
            *   into_mut_long_form
            *   clone
        2. Mostly lossless conversion (except normalization)
            *   from
            *   from_raw_form
        3. Lossless conversion (with possible failure)
            *   try_from (long -> short)
            *   try_into_mut_short
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            // Make fuzzy hashes
            let opt_hash_s_n: Option<FuzzyHash> = FuzzyHash::from_bytes(bytes_raw).ok()
                .or(FuzzyHash::from_bytes(bytes_norm).ok());
            let opt_hash_s_r: Option<RawFuzzyHash> = RawFuzzyHash::from_bytes(bytes_raw).ok();
            let opt_hash_l_n: Option<LongFuzzyHash> = LongFuzzyHash::from_bytes(bytes_raw).ok()
                .or(LongFuzzyHash::from_bytes(bytes_norm).ok());
            let opt_hash_l_r: Option<LongRawFuzzyHash> = LongRawFuzzyHash::from_bytes(bytes_raw).ok();
            macro_rules! test_lossless_conversion {
                ($hash_target: ident, $hash_cvt: ident) => {
                    assert!($hash_cvt.is_valid(), "failed (1) on bytes_str={:?}", bytes_str);
                    // Check equality
                    assert_eq!($hash_cvt.log_block_size(), $hash_target.log_block_size(), "failed (2) on bytes_str={:?}", bytes_str);
                    assert_eq!($hash_cvt.block_hash_1(), $hash_target.block_hash_1(), "failed (3) on bytes_str={:?}", bytes_str);
                    assert_eq!($hash_cvt.block_hash_2(), $hash_target.block_hash_2(), "failed (4) on bytes_str={:?}", bytes_str);
                };
            }
            // Short fuzzy hash (1)
            if let Some(hash_s_n) = opt_hash_s_n {
                // `from`
                let hash_s_r: RawFuzzyHash = RawFuzzyHash::from(hash_s_n);
                let hash_l_n: LongFuzzyHash = LongFuzzyHash::from(hash_s_n);
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from(hash_l_n);
                let hash_l_c: LongRawFuzzyHash = LongRawFuzzyHash::from(hash_s_n); // complex conversion
                test_lossless_conversion!(hash_s_n, hash_s_r);
                test_lossless_conversion!(hash_s_n, hash_l_n);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                test_lossless_conversion!(hash_s_n, hash_l_c);
                // `to_raw_form`
                let hash_s_r: RawFuzzyHash = hash_s_n.to_raw_form();
                let hash_l_r: LongRawFuzzyHash = hash_l_n.to_raw_form();
                test_lossless_conversion!(hash_s_n, hash_s_r);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `from_normalized`
                let hash_s_r: RawFuzzyHash = RawFuzzyHash::from_normalized(&hash_s_n);
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from_normalized(&hash_l_n);
                test_lossless_conversion!(hash_s_n, hash_s_r);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `to_long_form`
                let hash_l_n: LongFuzzyHash = hash_s_n.to_long_form();
                let hash_l_r: LongRawFuzzyHash = hash_s_r.to_long_form();
                test_lossless_conversion!(hash_s_n, hash_l_n);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `from_short_form`
                let hash_l_n: LongFuzzyHash = LongFuzzyHash::from_short_form(&hash_s_n);
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from_short_form(&hash_s_r);
                test_lossless_conversion!(hash_s_n, hash_l_n);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `into_mut_raw_form`
                let mut hash_s_r: RawFuzzyHash = RawFuzzyHash::new();
                let mut hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::new();
                hash_s_n.into_mut_raw_form(&mut hash_s_r);
                hash_l_n.into_mut_raw_form(&mut hash_l_r);
                test_lossless_conversion!(hash_s_n, hash_s_r);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `into_mut_long_form`
                let mut hash_l_n: LongFuzzyHash = LongFuzzyHash::new();
                let mut hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::new();
                hash_s_n.into_mut_long_form(&mut hash_l_n);
                hash_s_r.into_mut_long_form(&mut hash_l_r);
                test_lossless_conversion!(hash_s_n, hash_l_n);
                test_lossless_conversion!(hash_s_n, hash_l_r);
                // `clone`
                #[allow(clippy::clone_on_copy)]
                {
                    let cloned_hash_s_r: RawFuzzyHash = hash_s_r.clone();
                    let cloned_hash_s_n: FuzzyHash = hash_s_n.clone();
                    let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
                    let cloned_hash_l_n: LongFuzzyHash = hash_l_n.clone();
                    test_lossless_conversion!(hash_s_n, cloned_hash_s_n);
                    test_lossless_conversion!(hash_s_r, cloned_hash_s_r);
                    test_lossless_conversion!(hash_l_n, cloned_hash_l_n);
                    test_lossless_conversion!(hash_l_r, cloned_hash_l_r);
                }
            }
            // Short fuzzy hash (2)
            if let Some(hash_s_r) = opt_hash_s_r {
                // raw -> norm
                let orig_hash_s_n: FuzzyHash = opt_hash_s_n.unwrap();
                // Lossless (raw form; sometimes normalized):
                // `from`
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from(hash_s_r);
                let hash_s_n: FuzzyHash = FuzzyHash::from(hash_s_r);
                let hash_l_n: LongFuzzyHash = LongFuzzyHash::from(hash_l_r);
                test_lossless_conversion!(hash_s_r, hash_l_r);
                test_lossless_conversion!(orig_hash_s_n, hash_s_n); // Normalization occurs
                test_lossless_conversion!(orig_hash_s_n, hash_l_n); // Normalization occurs
                // `from_raw_form`
                let hash_s_n: FuzzyHash = FuzzyHash::from_raw_form(&hash_s_r);
                let hash_l_n: LongFuzzyHash = LongFuzzyHash::from_raw_form(&hash_l_r);
                test_lossless_conversion!(orig_hash_s_n, hash_s_n); // Normalization occurs
                test_lossless_conversion!(orig_hash_s_n, hash_l_n); // Normalization occurs
                // `to_long_form`
                let hash_l_r: LongRawFuzzyHash = hash_s_r.to_long_form();
                test_lossless_conversion!(hash_s_r, hash_l_r);
                // `from_short_form`
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from_short_form(&hash_s_r);
                test_lossless_conversion!(hash_s_r, hash_l_r);
                // `clone`
                #[allow(clippy::clone_on_copy)]
                {
                    let cloned_hash_s_r: RawFuzzyHash = hash_s_r.clone();
                    let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
                    test_lossless_conversion!(hash_s_r, cloned_hash_s_r);
                    test_lossless_conversion!(hash_l_r, cloned_hash_l_r);
                }
                // Lossless (short and long forms; succeeds in this case):
                let hash_s_n: FuzzyHash = FuzzyHash::try_from(hash_l_n).unwrap();
                let hash_s_r: RawFuzzyHash = RawFuzzyHash::try_from(hash_l_r).unwrap();
                assert_eq!(hash_s_n, orig_hash_s_n, "failed on bytes_str={:?}", bytes_str);
                assert!(hash_s_n.full_eq(&orig_hash_s_n), "failed on bytes_str={:?}", bytes_str);
                test_lossless_conversion!(hash_s_n, hash_l_n);
                test_lossless_conversion!(hash_s_r, hash_l_r);
            }
            // Long fuzzy hash
            {
                let orig_hash_l_n: LongFuzzyHash = opt_hash_l_n.unwrap();
                // True Lossless (normalized):
                // preparation
                let hash_l_n: LongFuzzyHash = orig_hash_l_n;
                // `from`
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from(hash_l_n);
                test_lossless_conversion!(hash_l_n, hash_l_r);
                // `to_raw_form`
                let hash_l_r: LongRawFuzzyHash = hash_l_n.to_raw_form();
                test_lossless_conversion!(hash_l_n, hash_l_r);
                // `from_normalized`
                let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from_normalized(&hash_l_n);
                test_lossless_conversion!(hash_l_n, hash_l_r);
                // `into_mut_raw_form`
                let mut hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::new();
                hash_l_n.into_mut_raw_form(&mut hash_l_r);
                test_lossless_conversion!(hash_l_n, hash_l_r);
                // `clone`
                #[allow(clippy::clone_on_copy)]
                {
                    let cloned_hash_l_n: LongFuzzyHash = hash_l_n.clone();
                    let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
                    test_lossless_conversion!(hash_l_n, cloned_hash_l_n);
                    test_lossless_conversion!(hash_l_r, cloned_hash_l_r);
                }
                // Lossless (raw, short and long forms; fails sometimes):
                // preparation
                let hash_l_r: LongRawFuzzyHash = opt_hash_l_r.unwrap();
                // `try_from`
                let result_hash_s_r = RawFuzzyHash::try_from(hash_l_r);
                if result_hash_s_r == Err(FuzzyHashOperationError::BlockHashOverflow) {
                    assert!(bh2.len() > block_hash::HALF_SIZE, "failed on bytes_str={:?}", bytes_str);
                }
                else {
                    let hash_s_r = result_hash_s_r.unwrap();
                    test_lossless_conversion!(hash_l_r, hash_s_r);
                }
                // `try_into_mut_short`
                let mut hash_s_r: RawFuzzyHash = RawFuzzyHash::new();
                let result = hash_l_r.try_into_mut_short(&mut hash_s_r);
                if result == Err(FuzzyHashOperationError::BlockHashOverflow) {
                    assert!(bh2.len() > block_hash::HALF_SIZE, "failed on bytes_str={:?}", bytes_str);
                }
                else {
                    assert!(result.is_ok(), "failed on bytes_str={:?}", bytes_str);
                    test_lossless_conversion!(hash_l_r, hash_s_r);
                }
                // Lossless (normalized, short and long forms; failes sometimes):
                // preparation
                let hash_l_n: LongFuzzyHash = orig_hash_l_n;
                assert_eq!(hash_l_n, orig_hash_l_n, "failed on bytes_str={:?}", bytes_str);
                assert!(hash_l_n.full_eq(&orig_hash_l_n), "failed on bytes_str={:?}", bytes_str);
                // `try_from`
                let result_hash_s_n = FuzzyHash::try_from(hash_l_n);
                if result_hash_s_n == Err(FuzzyHashOperationError::BlockHashOverflow) {
                    assert!(bh2_norm.len() > block_hash::HALF_SIZE, "failed on bytes_str={:?}", bytes_str);
                }
                else {
                    let hash_s_n = result_hash_s_n.unwrap();
                    test_lossless_conversion!(hash_l_n, hash_s_n);
                }
                // `try_into_mut_short`
                let mut hash_s_n: FuzzyHash = FuzzyHash::new();
                let result = hash_l_n.try_into_mut_short(&mut hash_s_n);
                if result == Err(FuzzyHashOperationError::BlockHashOverflow) {
                    assert!(bh2_norm.len() > block_hash::HALF_SIZE, "failed on bytes_str={:?}", bytes_str);
                }
                else {
                    assert!(result.is_ok(), "failed on bytes_str={:?}", bytes_str);
                    test_lossless_conversion!(hash_l_n, hash_s_n);
                }
            }
        }
    });
}

#[test]
fn data_model_block_hash_contents_and_normalization() {
    /*
        1. Normalization
            *   normalize
            *   normalize_in_place
            *   clone_normalized
        2. Conversion involving normalization and non-normalization
            *   from (normalized -> raw)
            *   from (raw -> normalized)
            *   to_raw_form
            *   from_raw_form
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($bh1sz: expr, $bh2sz: expr) => {
                    let bh1sz = $bh1sz;
                    let bh2sz = $bh2sz;
                    type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, false>;
                    // Initialize fuzzy hashes (all valid if Some)
                    let opt_hash_norm:          Option<FuzzyHashType>    = FuzzyHashType::from_bytes(bytes_norm).ok();
                    let opt_hash_norm_from_raw: Option<FuzzyHashType>    = FuzzyHashType::from_bytes(bytes_raw).ok();
                    let opt_hash_raw:           Option<RawFuzzyHashType> = RawFuzzyHashType::from_bytes(bytes_raw).ok();
                    let opt_hash_raw_from_norm: Option<RawFuzzyHashType> = RawFuzzyHashType::from_bytes(bytes_norm).ok();
                    // Check normalization
                    if let Some(hash_norm) = opt_hash_norm {
                        assert!(hash_norm.is_normalized(), "failed (1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    if let Some(hash_norm_from_raw) = opt_hash_norm_from_raw {
                        assert!(hash_norm_from_raw.is_normalized(), "failed (1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    if let Some(hash_raw) = opt_hash_raw {
                        assert_eq!(hash_raw.is_normalized(), is_normalized, "failed (1-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    if let Some(hash_raw_from_norm) = opt_hash_raw_from_norm {
                        assert!(hash_raw_from_norm.is_normalized(), "failed (1-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    // Equivalence with other normalized hashes.
                    if let Some(hash_norm_from_raw) = opt_hash_norm_from_raw {
                        // norm_from_raw -> norm
                        let hash_norm = opt_hash_norm.unwrap();
                        assert_eq!(hash_norm, hash_norm_from_raw, "failed (2-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_norm.full_eq(&hash_norm_from_raw), "failed (2-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    if let Some(hash_norm) = opt_hash_norm {
                        // norm -> raw_from_norm
                        // Transplant the data and check.
                        let hash_raw_from_norm: RawFuzzyHashType = opt_hash_raw_from_norm.unwrap();
                        let mut hash_raw_transplanted: RawFuzzyHashType = RawFuzzyHashType::new();
                        hash_raw_transplanted.blockhash1 = hash_norm.blockhash1;
                        hash_raw_transplanted.blockhash2 = hash_norm.blockhash2;
                        hash_raw_transplanted.len_blockhash1 = hash_norm.len_blockhash1;
                        hash_raw_transplanted.len_blockhash2 = hash_norm.len_blockhash2;
                        hash_raw_transplanted.log_blocksize = hash_norm.log_blocksize;
                        assert_eq!(hash_raw_from_norm, hash_raw_transplanted, "failed (2-2-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_raw_from_norm.full_eq(&hash_raw_transplanted), "failed (2-2-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                    // Explicit Normalization and Conversion between Normalized and Raw Forms
                    if let Some(hash_raw) = opt_hash_raw {
                        // raw -> (raw_from_norm, norm[, norm_from_raw])
                        let hash_raw_from_norm: RawFuzzyHashType = opt_hash_raw_from_norm.unwrap();
                        let hash_norm: FuzzyHashType = opt_hash_norm.unwrap();
                        // normalize_in_place (raw)
                        let mut hash_raw_normalized_in_place: RawFuzzyHashType = hash_raw;
                        hash_raw_normalized_in_place.normalize_in_place();
                        assert!(hash_raw_normalized_in_place.is_valid(), "failed (3-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_raw_normalized_in_place, hash_raw_from_norm, "failed (3-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_raw_normalized_in_place.full_eq(&hash_raw_from_norm), "failed (3-1-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // normalize_in_place (normalized) - just no-op
                        let mut hash_norm_normalized_in_place: FuzzyHashType = hash_norm;
                        hash_norm_normalized_in_place.normalize_in_place();
                        assert!(hash_norm_normalized_in_place.is_valid(), "failed (3-2-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_norm_normalized_in_place, hash_norm, "failed (3-2-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_norm_normalized_in_place.full_eq(&hash_norm), "failed (3-2-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // normalize (raw)
                        let hash_normalized_from_raw: FuzzyHashType = hash_raw.normalize();
                        assert!(hash_normalized_from_raw.is_valid(), "failed (3-3-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_normalized_from_raw, hash_norm, "failed (3-3-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_normalized_from_raw.full_eq(&hash_norm), "failed (3-3-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // normalize (normalized) - just clone
                        let hash_normalized_from_norm: FuzzyHashType = hash_norm.normalize();
                        assert!(hash_normalized_from_norm.is_valid(), "failed (3-4-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_normalized_from_norm, hash_norm, "failed (3-4-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_normalized_from_norm.full_eq(&hash_norm), "failed (3-4-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // clone_normalized (raw)
                        let hash_raw_clone_normalized: RawFuzzyHashType = hash_raw.clone_normalized();
                        assert!(hash_raw_clone_normalized.is_valid(), "failed (3-5-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_raw_clone_normalized, hash_raw_from_norm, "failed (3-5-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_raw_clone_normalized.full_eq(&hash_raw_from_norm), "failed (3-5-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // clone_normalized (normalized) - just clone
                        let hash_norm_clone_normalized: FuzzyHashType = hash_norm.clone_normalized();
                        assert!(hash_norm_clone_normalized.is_valid(), "failed (3-6-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_norm_clone_normalized, hash_norm, "failed (3-6-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_norm_clone_normalized.full_eq(&hash_norm), "failed (3-6-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // from (normalized -> raw) - no change
                        let hash_raw_cvt_from: RawFuzzyHashType = RawFuzzyHashType::from(hash_norm);
                        assert!(hash_raw_cvt_from.is_valid(), "failed (4-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_raw_cvt_from, hash_raw_from_norm, "failed (4-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_raw_cvt_from.full_eq(&hash_raw_from_norm), "failed (4-1-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // from (raw -> normalized) - with normalization
                        let hash_norm_cvt_from: FuzzyHashType = FuzzyHashType::from(hash_raw);
                        assert!(hash_norm_cvt_from.is_valid(), "failed (4-3-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_norm_cvt_from, hash_norm, "failed (4-3-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_norm_cvt_from.full_eq(&hash_norm), "failed (4-3-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // to_raw_form - no change
                        let hash_raw_cvt_to_raw_form: RawFuzzyHashType = hash_norm.to_raw_form();
                        assert!(hash_raw_cvt_to_raw_form.is_valid(), "failed (4-2-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_raw_cvt_to_raw_form, hash_raw_from_norm, "failed (4-2-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_raw_cvt_to_raw_form.full_eq(&hash_raw_from_norm), "failed (4-2-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        // from_raw_form - with normalization
                        let hash_norm_cvt_from_raw_form: FuzzyHashType = FuzzyHashType::from_raw_form(&hash_raw);
                        assert!(hash_norm_cvt_from_raw_form.is_valid(), "failed (4-4-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert_eq!(hash_norm_cvt_from_raw_form, hash_norm, "failed (4-4-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                        assert!(hash_norm_cvt_from_raw_form.full_eq(&hash_norm), "failed (4-4-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    }
                };
            }
            test_for_each_block_hash_sizes!(test);
        }
    });
}

#[test]
fn data_model_block_hash_contents_and_string_conversion() {
    /*
        1. String Parser (for fuzzy hash initialization from given block hashes)
            *   from_bytes
            *   from_str
                *   str::parse is used
        2. String Conversion
            *   len_in_str
            *   MAX_LEN_IN_STR
            *   store_into_bytes (including involution)
            *   to_string        (including involution)
    */
    // Output byte checker and terminator.
    #[inline(always)]
    fn is_ch_okay_for_output_byte(ch: u8) -> bool {
        // We expect *here* that the character is an ASCII-printable except ','.
        ch.is_ascii() && !ch.is_ascii_control() && ch != b','
    }
    const NULL_CH: u8 = 0xa9; // Latin-1 copyright mark, not a valid character in the fuzzy hash.
    assert!(!is_ch_okay_for_output_byte(NULL_CH));
    // Test block hash contents.
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($bh1sz: expr, $bh2sz: expr) => {
                    let bh1sz = $bh1sz;
                    let bh2sz = $bh2sz;
                    type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, false>;
                    assert_eq!(is_normalized, bytes_norm == bytes_raw, "failed (1) on bh1sz={}, bh2sz={}, bytes_str={:?}", bh1sz, bh2sz, bytes_str);
                    // Initialize and Check fuzzy hashes
                    macro_rules! init_and_check_hash {
                        (
                            $test_num: literal,
                            $is_input_norm: expr,
                            $ty: ty,
                            $bytes: expr
                        ) => {{
                            let test_num = $test_num;
                            let hash_opt: Option<$ty> = <$ty>::from_bytes($bytes).ok();
                            if let Some(hash) = hash_opt {
                                let bytes_str = core::str::from_utf8($bytes).unwrap();
                                let hash_is_normalized = <$ty>::IS_NORMALIZED_FORM || is_normalized || $is_input_norm;
                                let bh1_expected = if hash_is_normalized { bh1_norm } else { bh1 };
                                let bh2_expected = if hash_is_normalized { bh2_norm } else { bh2 };
                                // Maximum length in the string representation
                                assert!(hash.len_in_str() <= <$ty>::MAX_LEN_IN_STR, "failed ({}-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                if  hash.log_blocksize as usize == block_size::NUM_VALID - 1 &&
                                    bh1_expected.len() == <$ty>::MAX_BLOCK_HASH_SIZE_1 &&
                                    bh2_expected.len() == <$ty>::MAX_BLOCK_HASH_SIZE_2
                                {
                                    assert!(hash.len_in_str() == <$ty>::MAX_LEN_IN_STR, "failed ({}-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                }
                                // Check store_into_bytes
                                // 1.  Less than len_in_str (would cause StringizationOverflow)
                                // 2.  Exactly   len_in_str
                                // 3.  More than len_in_str (exactly the same result to 2. is expected)
                                let mut str_buffer = [NULL_CH; <$ty>::MAX_LEN_IN_STR + 1];
                                let mut str_buffer_2 = [NULL_CH; <$ty>::MAX_LEN_IN_STR + 1];
                                assert_eq!(hash.store_into_bytes(&mut str_buffer[..hash.len_in_str() - 1]), Err(FuzzyHashOperationError::StringizationOverflow),
                                    "failed ({}-2-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(str_buffer, [NULL_CH; <$ty>::MAX_LEN_IN_STR + 1],
                                    "failed ({}-2-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                hash.store_into_bytes(&mut str_buffer[..hash.len_in_str()]).unwrap();
                                assert!(str_buffer[hash.len_in_str()..].iter().all(|&x| x == NULL_CH),
                                    "failed ({}-2-2-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                hash.store_into_bytes(&mut str_buffer_2).unwrap();
                                assert!(str_buffer_2[hash.len_in_str()..].iter().all(|&x| x == NULL_CH),
                                    "failed ({}-2-2-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert_eq!(str_buffer, str_buffer_2, "failed ({}-2-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Check store_into_bytes and len_in_str:
                                // len_in_str is the exact length of the output.
                                let len_in_str = str_buffer.iter().position(|&x| x == NULL_CH).unwrap();
                                assert_eq!(hash.len_in_str(), len_in_str, "failed ({}-2-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                let stored_bytes = &str_buffer[..len_in_str];
                                // Outside the output string: must be untouched.
                                assert!(str_buffer[len_in_str..].iter().all(|&x| x == NULL_CH),
                                    "failed ({}-2-5) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Check minimum string requirements
                                assert!(stored_bytes.iter().all(|&x| is_ch_okay_for_output_byte(x)),
                                    "failed ({}-2-6) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Converting back to the original hash preserves the value.
                                let hash_back: $ty = <$ty>::from_bytes(stored_bytes).unwrap();
                                assert_eq!(hash, hash_back, "failed ({}-2-7-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                assert!(hash.full_eq(&hash_back), "failed ({}-2-7-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                // Check String
                                #[cfg(feature = "alloc")]
                                {
                                    let bytes_expected = if hash_is_normalized { bytes_norm } else { bytes_raw };
                                    // from_bytes and from_str are equivalent.
                                    let hash_alt: $ty = str::parse::<$ty>(bytes_str).unwrap();
                                    assert_eq!(hash, hash_alt, "failed ({}-3-1-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    assert!(hash.full_eq(&hash_alt), "failed ({}-3-1-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    // to_string and String::from matches.
                                    let s1 = hash.to_string();
                                    let s2 = alloc::string::String::from(hash);
                                    assert_eq!(s1, s2, "failed ({}-3-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    let s = s1;
                                    // String matches to the bytes expected.
                                    assert_eq!(s.len(), hash.len_in_str(), "failed ({}-3-3) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    assert_eq!(bytes_expected, s.as_bytes(), "failed ({}-3-4) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    // Converting back to the original hash preserves the value (bytes).
                                    let hash_back: $ty = <$ty>::from_bytes(s.as_bytes()).unwrap();
                                    assert_eq!(hash, hash_back, "failed ({}-3-5-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    assert!(hash.full_eq(&hash_back), "failed ({}-3-5-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    // Converting back to the original hash preserves the value (str).
                                    let hash_back: $ty = str::parse::<$ty>(s.as_str()).unwrap();
                                    assert_eq!(hash, hash_back, "failed ({}-3-6-1) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                    assert!(hash.full_eq(&hash_back), "failed ({}-3-6-2) on bh1sz={}, bh2sz={}, bytes_str={:?}", test_num, bh1sz, bh2sz, bytes_str);
                                }
                            }
                            hash_opt
                        }};
                    }
                    let _ = init_and_check_hash!(2,  true, FuzzyHashType, bytes_norm);
                    let _ = init_and_check_hash!(3, false, FuzzyHashType, bytes_raw);
                    let _ = init_and_check_hash!(4, false, RawFuzzyHashType, bytes_raw);
                    let _ = init_and_check_hash!(5,  true, RawFuzzyHashType, bytes_norm);
                };
            }
            test_for_each_block_hash_sizes!(test);
        }
    });
}


#[test]
fn data_model_block_size() {
    /*
        Block Size related Tests:
        1. Ordering
            *   cmp_by_block_size
        2. Generic Comparison
            *   compare_block_sizes
        3. Specific Comparison
            *   is_block_sizes_near
            *   is_block_sizes_near_lt
            *   is_block_sizes_near_eq
            *   is_block_sizes_near_gt
    */
    use crate::hash::block::BlockSizeRelation;
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        for bs1 in 0..block_size::NUM_VALID as u8 {
            // [BS1]:A:
            let lhs = <$ty>::new_from_internals(
                block_size::from_log(bs1).unwrap(), &[0], &[]);
            assert!(lhs.is_valid(), "failed (1-1) on typename={}, bs1={}", typename, bs1);
            for bs2 in 0..block_size::NUM_VALID as u8 {
                // [BS2]::A
                let rhs = <$ty>::new_from_internals(
                    block_size::from_log(bs2).unwrap(), &[], &[0]);
                assert!(rhs.is_valid(), "failed (1-2) on typename={}, bs2={}", typename, bs2);
                assert_ne!(lhs, rhs, "failed (1-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                // Use cmp_by_block_size (call with two different conventions).
                let ord = <$ty>::cmp_by_block_size(&lhs, &rhs);
                match ord {
                    Ordering::Equal => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Equal, "failed (2-1-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert!(bs1 == bs2, "failed (2-1-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        // [BS]:A: > [BS]::A
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Greater, "failed (2-1-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Less,    "failed (2-1-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    Ordering::Less => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Greater, "failed (2-2-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert!(bs1 < bs2, "failed (2-2-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Less,    "failed (2-2-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Greater, "failed (2-2-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    Ordering::Greater => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Less, "failed (2-3-1) on typename={}, bs1={}, typename, bs2={}", typename, bs1, bs2);
                        assert!(bs1 > bs2, "failed (2-3-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Greater, "failed (2-3-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Less,    "failed (2-3-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                }
                assert_eq!(ord, lhs.cmp_by_block_size(&rhs), "failed (3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                // Use compare_block_sizes.
                let rel = <$ty>::compare_block_sizes(&lhs, &rhs);
                assert_eq!(rel, block_size::compare_sizes(lhs.log_blocksize, rhs.log_blocksize), "failed (4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                // Test consistency between logical expressions and the BlockSizeRelation value.
                assert_eq!(bs1 == bs2, rel == BlockSizeRelation::NearEq, "failed (5-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(bs1 == bs2 + 1, rel == BlockSizeRelation::NearGt, "failed (5-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(bs1 + 1 == bs2, rel == BlockSizeRelation::NearLt, "failed (5-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(((bs1 as i32) - (bs2 as i32)).abs() > 1, rel == BlockSizeRelation::Far, "failed (5-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                // Test consistency between the result of other functions and the BlockSizeRelation value.
                #[allow(clippy::bool_assert_comparison)]
                match rel {
                    BlockSizeRelation::Far => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), false, "failed (6-1-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false, "failed (6-1-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false, "failed (6-1-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false, "failed (6-1-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_ne!(ord, Ordering::Equal, "failed (6-1-5) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    BlockSizeRelation::NearLt => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true, "failed (6-2-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), true,  "failed (6-2-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false, "failed (6-2-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false, "failed (6-2-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(ord, Ordering::Less, "failed (6-2-5) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    BlockSizeRelation::NearEq => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true, "failed (6-3-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false, "failed (6-3-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), true,  "failed (6-3-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false, "failed (6-3-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(ord, Ordering::Equal, "failed (6-3-5) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    BlockSizeRelation::NearGt => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true, "failed (6-4-1) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false, "failed (6-4-2) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false, "failed (6-4-3) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), true,  "failed (6-4-4) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(ord, Ordering::Greater, "failed (6-4-5) on typename={}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                }
            }
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn data_model_corruption() {
    // Prerequisites
    assert_fits_in!(block_hash::MAX_SEQUENCE_SIZE, u8);
    assert_fits_in!(block_hash::MAX_SEQUENCE_SIZE + 1, u8);
    macro_rules! test_prereq {($ty: ty) => {
        let typename = stringify!($ty);
        assert!(block_hash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_1, "failed (1) on typename={}", typename);
        assert!(block_hash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_2, "failed (2) on typename={}", typename);
        assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_1 + 1, u8, "failed (3) on typename={}", typename);
        assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_2 + 1, u8, "failed (4) on typename={}", typename);
    }}
    /*
        1. Validity
            *   is_valid
            *   is_valid
        2. Debug output (when invalid)
            *   fmt (Debug)
    */
    const EXPECTED_ILL_FORMED_PREFIX: &str = "FuzzyHashData { ILL_FORMED: true,";
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let hash: $ty = <$ty>::new();
        assert!(hash.is_valid(), "failed (1) on typename={}", typename);
        // Invalid block size
        {
            let mut hash = hash;
            for log_block_size in u8::MIN..=u8::MAX {
                hash.log_blocksize = log_block_size;
                assert_eq!(hash.is_valid(), block_size::is_log_valid(log_block_size),
                    "failed (2-1) on typename={}, log_block_size={}", typename, log_block_size);
                if !block_size::is_log_valid(log_block_size) {
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (2-2) on typename={}, log_block_size={}", typename, log_block_size);
                }
            }
        }
        // Corrupt block hash 1 length
        {
            for len_blockhash in u8::MIN..=u8::MAX {
                let mut hash = hash;
                hash.len_blockhash1 = len_blockhash;
                // Fill with valid values first
                (0..len_blockhash).collect_slice(&mut hash.blockhash1);
                // Validness depends on the block hash length we set
                assert_eq!(hash.is_valid(), len_blockhash <= <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8,
                    "failed (3-1-1) on typename={}, len_blockhash={}", typename, len_blockhash);
                if !(len_blockhash <= <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8) {
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (3-1-2) on typename={}, len_blockhash={}", typename, len_blockhash);
                }
            }
        }
        // Corrupt block hash 2 length
        {
            for len_blockhash in u8::MIN..=u8::MAX {
                let mut hash = hash;
                hash.len_blockhash2 = len_blockhash;
                // Fill with valid values first
                (0..len_blockhash).collect_slice(&mut hash.blockhash2);
                // Validness depends on the block hash length we set
                assert_eq!(hash.is_valid(), len_blockhash <= <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8,
                    "failed (3-2-1) on typename={}, len_blockhash={}", typename, len_blockhash);
                if !(len_blockhash <= <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8) {
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (3-2-2) on typename={}, len_blockhash={}", typename, len_blockhash);
                }
            }
        }
        // Corrupt block hash 1 contents (in the block hash)
        {
            for block_hash_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                hash.len_blockhash1 = block_hash_len as u8;
                // Fill with valid values first
                (0..).collect_slice(&mut hash.blockhash1[..block_hash_len]);
                assert!(hash.is_valid(), "failed (4-1-1) on typename={}, block_hash_len={}", typename, block_hash_len);
                // Put an invalid character in the block hash.
                for corrupted_index in 0..block_hash_len {
                    let mut hash = hash;
                    hash.blockhash1[corrupted_index] = BASE64_INVALID;
                    assert!(!hash.is_valid(),
                        "failed (4-1-2) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (4-1-3) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                }
            }
        }
        // Corrupt block hash 2 contents (in the block hash)
        {
            for block_hash_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                hash.len_blockhash2 = block_hash_len as u8;
                // Fill with valid values first
                (0..).collect_slice(&mut hash.blockhash2[..block_hash_len]);
                assert!(hash.is_valid(), "failed (4-2-1) on typename={}, block_hash_len={}", typename, block_hash_len);
                // Put an invalid character in the block hash.
                for corrupted_index in 0..block_hash_len {
                    let mut hash = hash;
                    hash.blockhash2[corrupted_index] = BASE64_INVALID;
                    assert!(!hash.is_valid(),
                        "failed (4-2-2) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (4-2-3) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                }
            }
        }
        // Corrupt block hash 1 contents (out of the block hash)
        {
            for block_hash_len in 1..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                hash.len_blockhash1 = block_hash_len as u8;
                // Fill with valid values first
                (0..).collect_slice(&mut hash.blockhash1[..block_hash_len]);
                assert!(hash.is_valid(), "failed (5-1-1) on typename={}, block_hash_len={}", typename, block_hash_len);
                // Put a non-zero character outside the block hash.
                for corrupted_index in block_hash_len..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                    let mut hash = hash;
                    hash.blockhash1[corrupted_index] = 1;
                    assert!(!hash.is_valid(),
                        "failed (5-1-2) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (5-1-3) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                }
            }
        }
        // Corrupt block hash 2 contents (out of the block hash)
        {
            for block_hash_len in 1..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                hash.len_blockhash2 = block_hash_len as u8;
                // Fill with valid values first
                (0..).collect_slice(&mut hash.blockhash2[..block_hash_len]);
                assert!(hash.is_valid(), "failed (5-2-1) on typename={}, block_hash_len={}", typename, block_hash_len);
                // Put a non-zero character outside the block hash.
                for corrupted_index in block_hash_len..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                    let mut hash = hash;
                    hash.blockhash2[corrupted_index] = 1;
                    assert!(!hash.is_valid(),
                        "failed (5-1-2) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                    assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX),
                        "failed (5-1-3) on typename={}, block_hash_len={}, corrupted_index={}", typename, block_hash_len, corrupted_index);
                }
            }
        }
        // Break block hash 1 normalization
        if <$ty>::IS_NORMALIZED_FORM {
            let mut hash = hash;
            hash.len_blockhash1 = block_hash::MAX_SEQUENCE_SIZE as u8;
            // block hash "AAA" (max sequence size): valid
            assert!(hash.is_valid(), "failed (6-1-1) on typename={}", typename);
            hash.len_blockhash1 = block_hash::MAX_SEQUENCE_SIZE as u8 + 1;
            // block hash "AAAA" (max sequence size + 1): invalid
            assert!(!hash.is_valid(), "failed (6-1-2) on typename={}", typename);
            assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX), "failed (6-1-3) on typename={}", typename);
        }
        // Break block hash 2 normalization
        if <$ty>::IS_NORMALIZED_FORM {
            let mut hash = hash;
            hash.len_blockhash2 = block_hash::MAX_SEQUENCE_SIZE as u8;
            // block hash "AAA" (max sequence size): valid
            assert!(hash.is_valid(), "failed (6-2-1) on typename={}", typename);
            hash.len_blockhash2 = block_hash::MAX_SEQUENCE_SIZE as u8 + 1;
            // block hash "AAAA" (max sequence size + 1): invalid
            assert!(!hash.is_valid(), "failed (6-2-2) on typename={}", typename);
            assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX), "failed (6-2-3) on typename={}", typename);
        }
    }}
    test_for_each_type!(test_prereq, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}

#[test]
fn data_model_eq_and_full_eq() {
    /*
        Equality (when corrupted):
        *   eq
        *   full_eq
    */
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let hash = <$ty>::new();
        assert!(hash.is_valid(), "failed (1) on typename={}", typename);
        // Write a non-zero value to "out of block hash" location.
        let mut hash_corrupted_1 = hash;
        hash_corrupted_1.blockhash1[0] = 1;
        let mut hash_corrupted_2 = hash;
        hash_corrupted_2.blockhash2[0] = 1;
        // Now those two hashes are corrupted.
        assert!(!hash_corrupted_1.is_valid(), "failed (2-1) on typename={}", typename);
        assert!(!hash_corrupted_2.is_valid(), "failed (2-2) on typename={}", typename);
        // But, default comparison results in "equal" because of ignoring
        // certain bytes.
        assert_eq!(hash, hash_corrupted_1, "failed (3-1) on typename={}", typename);
        assert_eq!(hash, hash_corrupted_2, "failed (3-2) on typename={}", typename);
        // Still, full_eq will return false.
        assert!(!hash.full_eq(&hash_corrupted_1), "failed (4-1) on typename={}", typename);
        assert!(!hash.full_eq(&hash_corrupted_2), "failed (4-2) on typename={}", typename);
        assert!(!hash_corrupted_1.full_eq(&hash), "failed (5-1) on typename={}", typename);
        assert!(!hash_corrupted_2.full_eq(&hash), "failed (5-2) on typename={}", typename);
        assert!(!hash_corrupted_1.full_eq(&hash_corrupted_2), "failed (6-1) on typename={}", typename);
        assert!(!hash_corrupted_2.full_eq(&hash_corrupted_1), "failed (6-2) on typename={}", typename);
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn data_model_normalized_windows() {
    test_blockhash_contents_no_sequences(&mut |bh1, bh2, _bh1_norm, _bh2_norm| {
        macro_rules! test {
            ($bh1sz: expr, $bh2sz: expr) => {
                let bh1sz = $bh1sz;
                let bh2sz = $bh2sz;
                type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                if bh2.len() > $bh2sz { break; }
                let hash: FuzzyHashType = FuzzyHashType::new_from_internals(block_size::MIN, bh1, bh2);
                // For each block hash, windows will return nothing as long as
                // the block hash is shorter than block_hash::MIN_LCS_FOR_COMPARISON.
                assert_eq!(
                    hash.block_hash_1_windows().next().is_none(),
                    hash.block_hash_1_len() < block_hash::MIN_LCS_FOR_COMPARISON,
                    "failed (1-1) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, bh1, bh2
                );
                assert_eq!(
                    hash.block_hash_2_windows().next().is_none(),
                    hash.block_hash_2_len() < block_hash::MIN_LCS_FOR_COMPARISON,
                    "failed (1-2) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, bh1, bh2
                );
                // Check window contents (block hash 1)
                if hash.block_hash_1_len() >= block_hash::MIN_LCS_FOR_COMPARISON {
                    let mut windows = hash.block_hash_1_windows();
                    let mut expected_window = [0u8; block_hash::MIN_LCS_FOR_COMPARISON];
                    for offset in 0..=(hash.block_hash_1_len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                        for (i, ch) in expected_window.iter_mut().enumerate() {
                            *ch = (offset + i) as u8;
                        }
                        assert_eq!(
                            windows.next().unwrap(), &expected_window[..],
                            "failed (2-1) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}, offset={}", bh1sz, bh2sz, bh1, bh2, offset
                        );
                    }
                    assert!(windows.next().is_none(),
                        "failed (3-1) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, bh1, bh2);
                }
                // Check window contents (block hash 2)
                if hash.block_hash_2_len() >= block_hash::MIN_LCS_FOR_COMPARISON {
                    let mut windows = hash.block_hash_2_windows();
                    let mut expected_window = [0u8; block_hash::MIN_LCS_FOR_COMPARISON];
                    for offset in 0..=(hash.block_hash_2_len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                        for (i, ch) in expected_window.iter_mut().enumerate() {
                            *ch = (block_hash::FULL_SIZE - 1 - offset - i) as u8;
                        }
                        assert_eq!(
                            windows.next().unwrap(), &expected_window[..],
                            "failed (2-2) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}, offset={}", bh1sz, bh2sz, bh1, bh2, offset
                        );
                    }
                    assert!(windows.next().is_none(),
                        "failed (3-2) on bh1sz={}, bh2sz={}, bh1={:?}, bh2={:?}", bh1sz, bh2sz, bh1, bh2);
                }
            };
        }
        test_for_each_block_hash_sizes!(test);
    });
}

#[test]
fn data_model_normalized_numeric_windows() {
    test_blockhash_contents_all(&mut |_bh1, _bh2, bh1_norm, bh2_norm| {
        macro_rules! test {
            ($bh1sz: expr, $bh2sz: expr) => {
                let bh1sz = $bh1sz;
                let bh2sz = $bh2sz;
                type FuzzyHashType = FuzzyHashData<{$bh1sz}, {$bh2sz}, true>;
                if bh2_norm.len() > $bh2sz { break; }
                let hash: FuzzyHashType = FuzzyHashType::new_from_internals(block_size::MIN, bh1_norm, bh2_norm);
                // For each block hash, windows will return nothing as long as
                // the block hash is shorter than block_hash::MIN_LCS_FOR_COMPARISON.
                assert_eq!(
                    hash.block_hash_1_numeric_windows().next().is_none(),
                    hash.block_hash_1_len() < block_hash::MIN_LCS_FOR_COMPARISON,
                    "failed (1-1) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, bh1_norm, bh2_norm
                );
                assert_eq!(
                    hash.block_hash_2_numeric_windows().next().is_none(),
                    hash.block_hash_2_len() < block_hash::MIN_LCS_FOR_COMPARISON,
                    "failed (1-2) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, bh1_norm, bh2_norm
                );
                // Block hash 1
                for (index, (window, window_as_num)) in itertools::zip_eq(hash.block_hash_1_windows(), hash.block_hash_1_numeric_windows()).enumerate() {
                    // Because NumericWindows reuses the previous numeric window to generate
                    // the next one, we need to compare the result (window_as_num) with
                    // the value created from scratch (calculated_window_as_num).
                    let calculated_window_as_num = window.iter().fold(0u64, |x, &ch| (x << block_hash::NumericWindows::ILOG2_OF_ALPHABETS) + ch as u64);
                    assert_eq!(calculated_window_as_num, window_as_num,
                        "failed (2-1-1) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}, index={}", bh1sz, bh2sz, bh1_norm, bh2_norm, index);
                }
                let len_windows =
                    if hash.block_hash_1_len() < block_hash::MIN_LCS_FOR_COMPARISON { 0 }
                    else { hash.block_hash_1_len() - block_hash::MIN_LCS_FOR_COMPARISON + 1 };
                assert_eq!(hash.block_hash_1_numeric_windows().size_hint(), (len_windows, Some(len_windows)),
                    "failed (2-1-2) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, bh1_norm, bh2_norm);
                // Block hash 2
                for (index, (window, window_as_num)) in itertools::zip_eq(hash.block_hash_2_windows(), hash.block_hash_2_numeric_windows()).enumerate() {
                    let calculated_window_as_num = window.iter().fold(0u64, |x, &ch| (x << block_hash::NumericWindows::ILOG2_OF_ALPHABETS) + ch as u64);
                    assert_eq!(calculated_window_as_num, window_as_num,
                        "failed (2-2-1) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}, index={}", bh1sz, bh2sz, bh1_norm, bh2_norm, index);
                }
                let len_windows =
                    if hash.block_hash_2_len() < block_hash::MIN_LCS_FOR_COMPARISON { 0 }
                    else { hash.block_hash_2_len() - block_hash::MIN_LCS_FOR_COMPARISON + 1 };
                assert_eq!(hash.block_hash_2_numeric_windows().size_hint(), (len_windows, Some(len_windows)),
                    "failed (2-2-2) on bh1sz={}, bh2sz={}, bh1_norm={:?}, bh2_norm={:?}", bh1sz, bh2sz, bh1_norm, bh2_norm);
            };
        }
        test_for_each_block_hash_sizes!(test);
    });
}

#[test]
fn data_model_normalized_windows_example() {
    // Prerequisites
    assert_eq!(block_hash::MIN_LCS_FOR_COMPARISON, 7);
    assert!(block_hash::MAX_SEQUENCE_SIZE <= 3);
    // Test some example "3:mG+XtIWRQX:7mYCCCWdq"
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let bh1 = &[38,  6, 62, 23, 45,  8, 22, 17, 16, 23]; // length 10
        let bh2 = &[59, 38, 24,  2,  2,  2, 22, 29, 42];     // length  9
        let hash = <$ty>::new_from_internals(block_size::MIN, bh1, bh2);
        // Block Hash 1
        {
            let mut windows_1 = hash.block_hash_1_windows();
            for index in 0..=(bh1.len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                assert_eq!(windows_1.next().unwrap(), &bh1[index..index+7],
                    "failed (1-1) on typename={}, index={}", typename, index);
            }
            assert!(windows_1.next().is_none(), "failed (1-2) on typename={}", typename);
        }
        // Block Hash 2
        {
            let mut windows_2 = hash.block_hash_2_windows();
            for index in 0..=(bh2.len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                assert_eq!(windows_2.next().unwrap(), &bh2[index..index+7],
                    "failed (2-1) on typename={}, index={}", typename, index);
            }
            assert!(windows_2.next().is_none(), "failed (2-2) on typename={}", typename);
        }
    }}
    // Normalized variants only
    test_for_each_type!(test, [FuzzyHash, LongFuzzyHash]);
}


macro_rules! parser_err {
    ($err_kind: ident, $err_origin: ident, $err_pos: expr) => {
        Err(ParseError(ParseErrorKind::$err_kind, ParseErrorOrigin::$err_origin, $err_pos))
    };
}
macro_rules! parser_case_fail_both {
    ($str: expr, $err_kind: ident, $err_origin: ident, $err_pos: expr) => {
        ($str, parser_err!($err_kind, $err_origin, $err_pos), parser_err!($err_kind, $err_origin, $err_pos))
    };
}
macro_rules! parser_case_fail_both_diff_offset {
    ($str: expr, $err_kind: ident, $err_origin: ident, $err_pos_short: expr, $err_pos_long: expr) => {
        ($str, parser_err!($err_kind, $err_origin, $err_pos_short), parser_err!($err_kind, $err_origin, $err_pos_long))
    };
}
macro_rules! parser_case_fail_short {
    ($str: expr, $err_kind: ident, $err_origin: ident, $err_pos: expr) => {
        ($str, parser_err!($err_kind, $err_origin, $err_pos), Ok(()))
    };
}
macro_rules! parser_case_okay_both {
    ($str: expr) => {
        ($str, Ok(()), Ok(()))
    };
}

macro_rules! bh_szseq_40 {() => { "1234567890123456789012345678901234567890" }}
macro_rules! bh_str_l_32 {() => { "01234567890123456789012345678901" }}
macro_rules! bh_str_l_33 {() => { "012345678901234567890123456789012" }}
macro_rules! bh_str_l_64 {() => { "0123456789012345678901234567890123456789012345678901234567890123" }}
macro_rules! bh_str_l_65 {() => { "01234567890123456789012345678901234567890123456789012345678901234" }}

#[test]
fn block_hash_const_substring_lengths() {
    assert_eq!(bh_szseq_40!().len(), 40);
    assert_eq!(bh_str_l_32!().len(), 32);
    assert_eq!(bh_str_l_33!().len(), 33);
    assert_eq!(bh_str_l_64!().len(), 64);
    assert_eq!(bh_str_l_65!().len(), 65);
}

#[allow(clippy::type_complexity)]
pub(crate) const PARSER_ERR_CASES: [(&str, Result<(), ParseError>, Result<(), ParseError>); 41] = [
    // Block Size
    parser_case_fail_both!("",     UnexpectedEndOfString, BlockSize, 0),
    parser_case_fail_both!("::",   BlockSizeIsEmpty,      BlockSize, 0),
    parser_case_fail_both!("@::",  UnexpectedCharacter,   BlockSize, 0),
    parser_case_fail_both!("3@::", UnexpectedCharacter,   BlockSize, 1),
    parser_case_fail_both!("3,::", UnexpectedCharacter,   BlockSize, 1),
    parser_case_okay_both!("3::"),
    parser_case_fail_both!("4::",  BlockSizeIsInvalid,    BlockSize, 0),
    parser_case_fail_both!("5::",  BlockSizeIsInvalid,    BlockSize, 0),
    parser_case_okay_both!("6::"),
    parser_case_fail_both!("7::",  BlockSizeIsInvalid,    BlockSize, 0),
    parser_case_fail_both!("16::", BlockSizeIsInvalid,    BlockSize, 0),
    parser_case_fail_both!("03::", BlockSizeStartsWithZero, BlockSize, 0),
    parser_case_fail_both!("04::", BlockSizeStartsWithZero, BlockSize, 0),
    parser_case_fail_both!("4294967295::", BlockSizeIsInvalid,  BlockSize, 0), // u32::MAX
    parser_case_fail_both!("4294967296::", BlockSizeIsTooLarge, BlockSize, 0), // u32::MAX + 1
    parser_case_fail_both!(
        concat!(bh_szseq_40!(), bh_szseq_40!(), "::"),
        BlockSizeIsTooLarge, BlockSize, 0), // 80 digits long (too large), valid terminator
    parser_case_fail_both!(
        concat!(bh_szseq_40!(), bh_szseq_40!(), bh_szseq_40!(), bh_szseq_40!(), "::"),
        BlockSizeIsTooLarge, BlockSize, 0), // 160 digits long (longer than all valid hashes), valid terminator
    // Block Hash 1
    parser_case_fail_both!("3:",    UnexpectedEndOfString, BlockHash1, 2),
    parser_case_fail_both!("3:a",   UnexpectedEndOfString, BlockHash1, 3),
    parser_case_fail_both!("3:a@",  UnexpectedCharacter,   BlockHash1, 3),
    parser_case_fail_both!("3:ab@", UnexpectedCharacter,   BlockHash1, 4),
    parser_case_fail_both!("3:a,",  UnexpectedCharacter,   BlockHash1, 3),
    parser_case_fail_both!("3:ab,", UnexpectedCharacter,   BlockHash1, 4),
    parser_case_okay_both!(
        concat!("3:", bh_str_l_64!(), ":")),
    parser_case_fail_both!(
        concat!("3:", bh_str_l_65!(), ":"),
        BlockHashIsTooLong, BlockHash1, 2 + 64),
    // Block Hash 2
    parser_case_fail_both!("3::a@",  UnexpectedCharacter, BlockHash2, 4),
    parser_case_fail_both!("3::ab@", UnexpectedCharacter, BlockHash2, 5),
    parser_case_fail_both!("3::a:",  UnexpectedCharacter, BlockHash2, 4),
    parser_case_fail_both!("3::ab:", UnexpectedCharacter, BlockHash2, 5),
    parser_case_okay_both!("3::a"),
    parser_case_okay_both!("3::ab"),
    parser_case_okay_both!("3::a,"),
    parser_case_okay_both!("3::ab,"),
    parser_case_okay_both!("3::a,\"sample_file\""),
    parser_case_okay_both!("3::ab,\"sample_file\""),
    parser_case_okay_both!("3::a,\"sample,file\""),
    parser_case_okay_both!("3::ab,\"sample,file\""),
    parser_case_okay_both!(
        concat!("3:", bh_str_l_64!(), ":", bh_str_l_32!())),
    // Short/Long forms (different behavior)
    parser_case_fail_short!(
        concat!("3:", bh_str_l_64!(), ":", bh_str_l_33!()),
        BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 32),
    parser_case_fail_short!(
        concat!("3:", bh_str_l_64!(), ":", bh_str_l_64!()),
        BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 32),
    parser_case_fail_both_diff_offset!(
        concat!("3:", bh_str_l_64!(), ":", bh_str_l_65!()),
        BlockHashIsTooLong, BlockHash2,
        2 + 64 + 1 + 32,
        2 + 64 + 1 + 64),
];

#[test]
fn parser_err_cases_prerequisites() {
    assert!(crate::MAX_LEN_IN_STR < 160);
    assert_eq!(block_size::MIN, 3);
    assert_eq!(FuzzyHash::MAX_BLOCK_HASH_SIZE_2, 32);
    assert_eq!(LongFuzzyHash::MAX_BLOCK_HASH_SIZE_2, 64);
}

#[test]
fn parse_patterns() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        for &(hash_str, result_short, result_long) in &PARSER_ERR_CASES {
            let err = if <$ty>::IS_LONG_FORM { result_long } else { result_short };
            let mut index1 = 0;
            let mut index2 = usize::MAX;
            assert_eq!(
                <$ty>::from_bytes(hash_str.as_bytes()).map(|_| ()), err,
                "failed (1-1) on typename={}, hash_str={:?}", typename, hash_str
            );
            assert_eq!(
                <$ty>::from_bytes_with_last_index(hash_str.as_bytes(), &mut index1).map(|_| ()), err,
                "failed (1-2-1-1-1) on typename={}, hash_str={:?}", typename, hash_str
            );
            assert_eq!(
                <$ty>::from_bytes_with_last_index(hash_str.as_bytes(), &mut index2).map(|_| ()), err,
                "failed (1-2-1-1-2) on typename={}, hash_str={:?}", typename, hash_str
            );
            match err {
                Ok(_) => {
                    assert_eq!(index1, index2,
                        "failed (1-2-1-2) on typename={}, hash_str={:?}", typename, hash_str);
                    // If the index is not that of the end of the string...
                    if index1 != hash_str.len() {
                        // It must point to the character ',' and...
                        assert!(hash_str.as_bytes()[index1] == b',',
                            "failed (1-2-2-1) on typename={}, hash_str={:?}", typename, hash_str);
                        // The index must be the leftmost ',' character.
                        assert_eq!(hash_str.find(','), Some(index1),
                            "failed (1-2-2-2) on typename={}, hash_str={:?}", typename, hash_str);
                    }
                }
                Err(_) => {
                    assert_eq!(index1, 0,
                        "failed (1-2-2-3-1) on typename={}, hash_str={:?}", typename, hash_str);
                    assert_eq!(index2, usize::MAX,
                        "failed (1-2-2-3-2) on typename={}, hash_str={:?}", typename, hash_str);
                }
            }
            assert_eq!(
                str::parse::<$ty>(hash_str).map(|_| ()), err,
                "failed (2) on typename={}, hash_str={:?}", typename, hash_str
            );
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


macro_rules! assert_parse_fail {
    ($ctor: expr, $err_kind: ident, $err_origin: ident, $err_pos: expr) => {
        assert_eq!($ctor, Err(ParseError(
            ParseErrorKind::$err_kind, ParseErrorOrigin::$err_origin, $err_pos)));
    };
}

macro_rules! assert_parse_fail_no_offset {
    ($ctor: expr, $err_kind: ident, $err_origin: ident) => {
        assert!(matches!($ctor, Err(ParseError(
            ParseErrorKind::$err_kind, ParseErrorOrigin::$err_origin, _))));
    };
}

macro_rules! assert_parse_okay {
    ($ctor: expr) => {
        assert!($ctor.is_ok());
    };
}

#[test]
fn parse_block_hash_1_patterns() {
    // Prerequisites
    assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);
    assert_eq!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_1, 64);

    const HASH_NOOVF: &str        = "6:0123456701234567012345670123456701234567012345670123456701234567:";
    const HASH_NOOVF_SEQ1_S: &str = "6:0003456701234567012345670123456701234567012345670123456701234567:";
    const HASH_NOOVF_SEQ1_L: &str = "6:000000003456701234567012345670123456701234567012345670123456701234567:"; // +5bytes
    const HASH_NOOVF_SEQ2_S: &str = "6:0123456701234567012345670123456700034567012345670123456701234567:";
    const HASH_NOOVF_SEQ2_L: &str = "6:012345670123456701234567012345670000000034567012345670123456701234567:"; // +5bytes
    const HASH_NOOVF_SEQ3_S: &str = "6:0123456701234567012345670123456701234567012345670123456701234777:";
    const HASH_NOOVF_SEQ3_L: &str = "6:012345670123456701234567012345670123456701234567012345670123477777777:"; // +5bytes
    // Append '0' to the first block hash to cause overflow
    const HASH_OVF: &str          = "6:01234567012345670123456701234567012345670123456701234567012345670:";
    const HASH_OVF_SEQ_S: &str    = "6:00034567012345670123456701234567012345670123456701234567012345670:";
    const HASH_OVF_SEQ_L: &str    = "6:0000000034567012345670123456701234567012345670123456701234567012345670:";
    const BASE_OFFSET: usize = 2 + RawFuzzyHash::MAX_BLOCK_HASH_SIZE_1;

    // Blockhash with maximum length
    assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF));
    // ... considering sequence elimination by default
    assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ1_S));
    assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ2_S));
    assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ3_S));
    // (commented out since success of those cases are not guaranteed from its semantics)
    // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ1_L));
    // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ2_L));
    // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ3_L));
    // Blockhash exceeds maximum length (no sequences)
    assert_parse_fail!(str::parse::<FuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    // ... even after the normalization
    assert_parse_fail_no_offset!(str::parse::<FuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash1);
    assert_parse_fail_no_offset!(str::parse::<FuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash1);

    // Parse as non-normalized hashes
    assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF));
    assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ1_S));
    assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ2_S));
    assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ3_S));
    // as sequence elimination would not occur, long blockhash immediately causes an error.
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ1_L), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ2_L), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ3_L), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
    assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash1, BASE_OFFSET);
}

#[test]
fn parse_block_hash_2_patterns() {
    // Prerequisites
    assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);
    assert_eq!(RawFuzzyHash::MAX_BLOCK_HASH_SIZE_2, 32);
    assert_eq!(LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_2, 64);
    // Short variants
    {
        const HASH_NOOVF: &str        = "6::01234567012345670123456701234567";
        const HASH_NOOVF_SEQ1_S: &str = "6::00034567012345670123456701234567";
        const HASH_NOOVF_SEQ1_L: &str = "6::0000000034567012345670123456701234567"; // +5bytes
        const HASH_NOOVF_SEQ2_S: &str = "6::01234567012345670003456701234567";
        const HASH_NOOVF_SEQ2_L: &str = "6::0123456701234567000000003456701234567"; // +5bytes
        const HASH_NOOVF_SEQ3_S: &str = "6::01234567012345670123456701234777";
        const HASH_NOOVF_SEQ3_L: &str = "6::0123456701234567012345670123477777777"; // +5bytes
        // Append '0' to the first block hash to cause overflow
        const HASH_OVF: &str          = "6::01234567012345670123456701234567012345670123456701234567012345670";
        const HASH_OVF_SEQ_S: &str    = "6::00034567012345670123456701234567012345670123456701234567012345670";
        const HASH_OVF_SEQ_L: &str    = "6::0000000034567012345670123456701234567012345670123456701234567012345670";
        const BASE_OFFSET: usize = 2 + RawFuzzyHash::MAX_BLOCK_HASH_SIZE_2 + 1;

        // Blockhash with maximum length
        assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF));
        // ... considering sequence elimination by default
        assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ1_S));
        assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ2_S));
        assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ3_S));
        // (commented out since success of those cases are not guaranteed from its semantics)
        // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ1_L));
        // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ2_L));
        // assert_parse_okay!(str::parse::<FuzzyHash>(HASH_NOOVF_SEQ3_L));
        // Blockhash exceeds maximum length (no sequences)
        assert_parse_fail!(str::parse::<FuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        // ... even after the normalization
        assert_parse_fail_no_offset!(str::parse::<FuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash2);
        assert_parse_fail_no_offset!(str::parse::<FuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash2);

        // Parse as non-normalized hashes
        assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF));
        assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ1_S));
        assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ2_S));
        assert_parse_okay!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ3_S));
        // as sequence elimination would not occur, long blockhash immediately causes an error.
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ1_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ2_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_NOOVF_SEQ3_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<RawFuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
    }
    // Long variants
    {
        const HASH_NOOVF: &str        = "6::0123456701234567012345670123456701234567012345670123456701234567";
        const HASH_NOOVF_SEQ1_S: &str = "6::0003456701234567012345670123456701234567012345670123456701234567";
        const HASH_NOOVF_SEQ1_L: &str = "6::000000003456701234567012345670123456701234567012345670123456701234567"; // +5bytes
        const HASH_NOOVF_SEQ2_S: &str = "6::0123456701234567012345670123456700034567012345670123456701234567";
        const HASH_NOOVF_SEQ2_L: &str = "6::012345670123456701234567012345670000000034567012345670123456701234567"; // +5bytes
        const HASH_NOOVF_SEQ3_S: &str = "6::0123456701234567012345670123456701234567012345670123456701234777";
        const HASH_NOOVF_SEQ3_L: &str = "6::012345670123456701234567012345670123456701234567012345670123477777777"; // +5bytes
        // Append '0' to the first block hash to cause overflow
        const HASH_OVF: &str          = "6::01234567012345670123456701234567012345670123456701234567012345670";
        const HASH_OVF_SEQ_S: &str    = "6::00034567012345670123456701234567012345670123456701234567012345670";
        const HASH_OVF_SEQ_L: &str    = "6::0000000034567012345670123456701234567012345670123456701234567012345670";
        const BASE_OFFSET: usize = 2 + LongRawFuzzyHash::MAX_BLOCK_HASH_SIZE_2 + 1;

        // Blockhash with maximum length
        assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF));
        // ... considering sequence elimination by default
        assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ1_S));
        assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ2_S));
        assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ3_S));
        // (commented out since success of those cases are not guaranteed from its semantics)
        // assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ1_L));
        // assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ2_L));
        // assert_parse_okay!(str::parse::<LongFuzzyHash>(HASH_NOOVF_SEQ3_L));
        // Blockhash exceeds maximum length (no sequences)
        assert_parse_fail!(str::parse::<LongFuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        // ... even after the normalization
        assert_parse_fail_no_offset!(str::parse::<LongFuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash2);
        assert_parse_fail_no_offset!(str::parse::<LongFuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash2);

        // Parse as non-normalized hashes
        assert_parse_okay!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF));
        assert_parse_okay!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ1_S));
        assert_parse_okay!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ2_S));
        assert_parse_okay!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ3_S));
        // as sequence elimination would not occur, long blockhash immediately causes an error.
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ1_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ2_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_NOOVF_SEQ3_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_OVF), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_OVF_SEQ_S), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
        assert_parse_fail!(str::parse::<LongRawFuzzyHash>(HASH_OVF_SEQ_L), BlockHashIsTooLong, BlockHash2, BASE_OFFSET);
    }
}


#[test]
fn parsed_block_size() {
    /*
        Tested methods:
        1. String Parser (block size part; only valid cases)
            *   from_bytes
            *   from_str
        2. Block size related functions
            *   log_block_size
            *   block_size
    */
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        for (log_block_size, &str_block_size) in
            block_size::BLOCK_SIZES_STR.iter().enumerate()
        {
            let block_size: u32 = str::parse(str_block_size).unwrap();
            let str_block_size = str_block_size.as_bytes();
            // For each block_size::BLOCK_SIZES_STR entry "[BS]", make "[BS]::"
            // and parse as a fuzzy hash.
            let mut buf = [0u8; <$ty>::MAX_LEN_IN_STR];
            buf[..str_block_size.len()].clone_from_slice(str_block_size);
            buf[str_block_size.len()] = b':';
            buf[str_block_size.len() + 1] = b':';
            // Use from_bytes.
            let hash = <$ty>::from_bytes(&buf[..str_block_size.len() + 2]).unwrap();
            assert!(hash.is_valid(), "failed (1) on typename={}, log_block_size={}", typename, log_block_size);
            // Check log_block_size() and block_size()
            assert_eq!(hash.log_block_size(), log_block_size as u8, "failed (2-1) on typename={}, log_block_size={}", typename, log_block_size);
            assert_eq!(hash.block_size(), block_size, "failed (2-2) on typename={}, log_block_size={}", typename, log_block_size);
            // Use from_str via str::parse.
            let hash = str::parse::<$ty>(
                core::str::from_utf8(&buf[..str_block_size.len() + 2]).unwrap()
            ).unwrap();
            assert!(hash.is_valid(), "failed (3) on typename={}, log_block_size={}", typename, log_block_size);
            // Check log_block_size() and block_size()
            assert_eq!(hash.log_block_size(), log_block_size as u8, "failed (4-1) on typename={}, log_block_size={}", typename, log_block_size);
            assert_eq!(hash.block_size(), block_size, "failed (4-2) on typename={}, log_block_size={}", typename, log_block_size);
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn parsed_data_example() {
    let hash: FuzzyHash = str::parse("3:ABCD:abcde").unwrap();
    assert!(hash.is_valid());
    // Check internal data
    assert_eq!(hash.block_size(), 3);
    assert_eq!(hash.log_block_size(), 0);
    assert_eq!(hash.block_hash_1_len(), 4);
    assert_eq!(hash.block_hash_2_len(), 5);
    // Check its contents
    // 'A': 0, 'a': 26 (on Base64 index)
    assert_eq!(hash.block_hash_1(), [0, 1, 2, 3]);
    assert_eq!(hash.block_hash_2(), [26, 27, 28, 29, 30]);
}


#[test]
fn normalization_examples() {
    #[cfg(not(feature = "alloc"))]
    use std::string::ToString;
    // Prerequisites (partial)
    assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);
    // Target strings
    const NORM0: &str = "3:ABBCCCDDDDEEEEE:555554444333221";
    const NORM1: &str = "3:ABBCCCDDDEEE:555444333221";
    // Test (normalized forms)
    assert_eq!(str::parse::<FuzzyHash>(NORM1).unwrap().to_string(), NORM1);
    assert_eq!(str::parse::<FuzzyHash>(NORM0).unwrap().to_string(), NORM1);
    assert_eq!(str::parse::<LongFuzzyHash>(NORM1).unwrap().to_string(), NORM1);
    assert_eq!(str::parse::<LongFuzzyHash>(NORM0).unwrap().to_string(), NORM1);
    // Test (raw forms)
    assert_eq!(str::parse::<RawFuzzyHash>(NORM1).unwrap().to_string(), NORM1);
    assert_eq!(str::parse::<RawFuzzyHash>(NORM0).unwrap().to_string(), NORM0);
    assert_eq!(str::parse::<LongRawFuzzyHash>(NORM1).unwrap().to_string(), NORM1);
    assert_eq!(str::parse::<LongRawFuzzyHash>(NORM0).unwrap().to_string(), NORM0);
}


#[test]
fn cover_hash() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let mut hashes = std::collections::HashSet::<$ty>::new();
        assert!( hashes.insert(<$ty>::new()), "failed (1) on typename={}", typename);
        assert!(!hashes.insert(<$ty>::new()), "failed (2) on typename={}", typename);
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn ord_and_sorting() {
    use std::vec::Vec;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(not(feature = "alloc"))]
    use std::string::ToString;
    // Sorted by block hash order (Base64 indices and length).
    // Note that 'A' has Base64 index zero and FuzzyHashData zero-fills
    // each tail of block hashes (making the behavior more deterministic).
    const SORTED_DICT: [&str; 12] = [
        "ABBR",
        "ABBRA",
        "ABBRAA",
        "ABBREVIATES",
        "abbr",
        "abbrA",
        "abbrAA",
        "abbreviates",
        "0123",
        "0123A",
        "0123AA",
        "01234567",
    ];
    // Construct sorted hashes list
    let mut hashes: Vec<FuzzyHash> = Vec::new();
    for log_block_size in 0..block_size::NUM_VALID as u8 {
        for bs1 in SORTED_DICT {
            for bs2 in SORTED_DICT {
                let mut s = block_size::from_log(log_block_size).unwrap().to_string();
                s += ":";
                s += bs1;
                s += ":";
                s += bs2;
                hashes.push(str::parse(s.as_str()).unwrap());
            }
        }
    }
    // Test consistency between Vec order and comparison results
    for (i1, h1) in hashes.iter().enumerate() {
        for (i2, h2) in hashes.iter().enumerate() {
            match h1.cmp(h2) {
                Ordering::Equal   => { assert!(i1 == i2, "failed on i1={}, i2={}, h1={:?}, h2={:?}", i1, i2, h1, h2); },
                Ordering::Greater => { assert!(i1 > i2,  "failed on i1={}, i2={}, h1={:?}, h2={:?}", i1, i2, h1, h2); },
                Ordering::Less    => { assert!(i1 < i2,  "failed on i1={}, i2={}, h1={:?}, h2={:?}", i1, i2, h1, h2); },
            }
        }
    }
    // Sorting the list makes the order the same as the original.
    let cloned = hashes.clone();
    hashes.reverse();
    hashes.sort();
    assert_eq!(hashes, cloned);
}

#[test]
fn ord_by_block_size_examples() {
    use std::vec::Vec;
    #[cfg(not(feature = "alloc"))]
    use std::string::ToString;
    const STRS_UNSORTED: [&str; 8] = [
        "12:a:",
        "12:z:",
        "12288:a:",
        "12288:z:",
        "3:z:",
        "3:a:",
        "6144:z:",
        "6144:a:",
    ];
    const STRS_SORTED_ALL: [&str; 8] = [
        "3:a:",
        "3:z:",
        "12:a:",
        "12:z:",
        "6144:a:",
        "6144:z:",
        "12288:a:",
        "12288:z:",
    ];
    // Because Vec::sort_by is stable, it preserves the order
    // if block size is the same.
    const STRS_SORTED_BLOCK_SIZE: [&str; 8] = [
        "3:z:",
        "3:a:",
        "12:a:",
        "12:z:",
        "6144:z:",
        "6144:a:",
        "12288:a:",
        "12288:z:",
    ];
    // Construct sorted hashes list
    let hashes_orig: Vec<FuzzyHash> =
        STRS_UNSORTED.iter().map(|&s| str::parse(s).unwrap()).collect();
    assert!(hashes_orig.iter().all(|x| x.is_valid()));
    // Perform and check sorting by all fields
    let mut hashes = hashes_orig.clone();
    hashes.sort_by(FuzzyHash::cmp);
    for index in 0..hashes.len() {
        assert_eq!(hashes[index].to_string(), STRS_SORTED_ALL[index], "failed on index={}", index);
    }
    // Perform and check sorting only by block size
    let mut hashes = hashes_orig;
    hashes.sort_by(FuzzyHash::cmp_by_block_size);
    for index in 0..hashes.len() {
        assert_eq!(hashes[index].to_string(), STRS_SORTED_BLOCK_SIZE[index], "failed on index={}", index);
    }
}


#[test]
fn impl_debug() {
    // Test empty hashes
    assert_eq!(format!("{:?}", FuzzyHash::new()),
        "FuzzyHashData { \
            LONG: false, \
            NORM: true, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\" \
        }");
    assert_eq!(format!("{:?}", RawFuzzyHash::new()),
        "FuzzyHashData { \
            LONG: false, \
            NORM: false, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\" \
        }");
    assert_eq!(format!("{:?}", LongFuzzyHash::new()),
        "FuzzyHashData { \
            LONG: true, \
            NORM: true, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\" \
        }");
    assert_eq!(format!("{:?}", LongRawFuzzyHash::new()),
        "FuzzyHashData { \
            LONG: true, \
            NORM: false, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\" \
        }");
    // Test an example
    let s = "6\
        :01234567890123456789012345678901234567890123456789012345678901\
        :01234567890123456789012345678901";
    // Test parsed fuzzy hash
    let hash: LongFuzzyHash = str::parse(s).unwrap();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashData { \
            LONG: true, \
            NORM: true, \
            block_size: 6, \
            blockhash1: \"01234567890123456789012345678901234567890123456789012345678901\", \
            blockhash2: \"01234567890123456789012345678901\" \
        }"
    );
}


#[test]
fn compare_fuzzy_hash_data_examples_eq() {
    // Test examples from FuzzyHashData (block sizes are the same)
    {
        const S_A: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
        const S_B: &str = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:H5d+X36WnL5d+X3v5d+X315d+X3+";
        let h_a: FuzzyHash = str::parse(S_A).unwrap();
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        assert!(block_size::is_near_eq(h_a.log_block_size(), h_b.log_block_size()));
        assert_eq!(h_a.compare(h_b), 94);
        assert_eq!(h_b.compare(h_a), 94);
    }
    // ... with only first block hash
    {
        const S_A: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
        const S_B: &str = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:";
        let h_a: FuzzyHash = str::parse(S_A).unwrap();
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        assert_eq!(h_a.compare(h_b), 94);
        assert_eq!(h_b.compare(h_a), 94);
    }
    // ... with only second block hash
    {
        const S_A: &str = "6144::Z5d+X395d+X3X5d+X315d+X3+";
        const S_B: &str = "6144::H5d+X36WnL5d+X3v5d+X315d+X3+";
        let h_a: FuzzyHash = str::parse(S_A).unwrap();
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        assert_eq!(h_a.compare(h_b), 85);
        assert_eq!(h_b.compare(h_a), 85);
    }
}

#[test]
fn compare_fuzzy_hash_data_examples_eq_near_but_not_eq() {
    // Test examples from FuzzyHashData (block sizes near but not equal)
    {
        const S_A: &str = "3072:S+IiyfkMY+BES09JXAnyrZalI+YuyfkMY+BES09JXAnyrZalI+YQ:S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
        const S_B: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
        const S_C: &str = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:1+Jr+d++H+5+e";
        let h_a: FuzzyHash = str::parse(S_A).unwrap();
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        let h_c: FuzzyHash = str::parse(S_C).unwrap();
        assert!(block_size::is_near_lt(h_a.log_block_size(), h_b.log_block_size()));
        assert!(block_size::is_near_lt(h_b.log_block_size(), h_c.log_block_size()));
        assert_eq!(h_a.compare(h_b), 72);
        assert_eq!(h_b.compare(h_c), 88);
        assert_eq!(h_a.compare(h_c),  0);
        assert_eq!(h_b.compare(h_a), 72);
        assert_eq!(h_c.compare(h_b), 88);
        assert_eq!(h_c.compare(h_a),  0);
    }
    // ... with only block hashes compared (A and B)
    {
        const S_A: &str = "3072::S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
        const S_B: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
        let h_a: FuzzyHash = str::parse(S_A).unwrap();
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        assert_eq!(h_a.compare(h_b), 72);
        assert_eq!(h_b.compare(h_a), 72);
    }
    // ... with only block hashes compared (B and C)
    {
        const S_B: &str = "6144::Z5d+X395d+X3X5d+X315d+X3+";
        const S_C: &str = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:";
        let h_b: FuzzyHash = str::parse(S_B).unwrap();
        let h_c: FuzzyHash = str::parse(S_C).unwrap();
        assert_eq!(h_b.compare(h_c), 88);
        assert_eq!(h_c.compare(h_b), 88);
    }
}
