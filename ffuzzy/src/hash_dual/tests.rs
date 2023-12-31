// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use crate::hash::FuzzyHashData;
use crate::hash::block::block_size;
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
use crate::hash::tests::FuzzyHashStringBytes;
use crate::hash::test_utils::test_blockhash_contents_all;
use crate::hash_dual::{DualFuzzyHash, LongDualFuzzyHash, rle_encoding};
use crate::test_utils::test_for_each_type;


#[test]
fn data_model_new() {
    macro_rules! test {
        ($ty: ty) => {
            let typename = stringify!($ty);
            let hash_new: $ty = <$ty>::new();
            let hash_default: $ty = <$ty>::default();
            let hash_cloned: $ty = hash_new.clone();
            let hash_from_str: $ty = str::parse("3::").unwrap();
            // Test validity of the empty value.
            assert!(hash_new.is_valid(),     "failed (1-1) on typename={}", typename);
            assert!(hash_default.is_valid(), "failed (1-2) on typename={}", typename);
            assert!(hash_cloned.is_valid(),  "failed (1-3) on typename={}", typename);
            // Test validity of fuzzy hashes converted from "empty" fuzzy hash string.
            assert!(hash_from_str.is_valid(), "failed (2) on typename={}", typename);
            // Compare two values.
            assert_eq!(hash_new, hash_default,  "failed (3-1) on typename={}", typename);
            assert_eq!(hash_new, hash_cloned,   "failed (3-1) on typename={}", typename);
            assert_eq!(hash_new, hash_from_str, "failed (3-1) on typename={}", typename);
        };
    }
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[allow(deprecated)]
#[test]
fn data_model_internal_ref() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        type NormalizedType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
        let hash = <$ty>::new();
        let norm_hash_1: &NormalizedType = &hash.norm_hash;
        let norm_hash_2: &NormalizedType = hash.as_ref();
        let norm_hash_3: &NormalizedType = hash.as_normalized();
        let norm_hash_4: &NormalizedType = hash.as_ref_normalized(); // deprecated
        let p1 = norm_hash_1 as *const NormalizedType;
        let p2 = norm_hash_2 as *const NormalizedType;
        let p3 = norm_hash_3 as *const NormalizedType;
        let p4 = norm_hash_4 as *const NormalizedType;
        assert_eq!(p1, p2, "failed (1) on typename={}", typename);
        assert_eq!(p1, p3, "failed (2) on typename={}", typename);
        assert_eq!(p1, p4, "failed (3) on typename={}", typename);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn data_model_init_and_basic() {
    /*
        1. Initialization from other data
            *   init_from_raw_form
            *   from_raw_form
            *   from (raw)
            *   from_bytes
            *   from_str
                *   str::parse is used
        2. Initialization from Internal Data (only valid cases)
            *   init_from_raw_form_internals_raw
            *   init_from_raw_form_internals_raw_internal
            *   init_from_raw_form_internals_raw_unchecked
            *   new_from_raw_form_internals_raw
            *   new_from_raw_form_internals_raw_internal
            *   new_from_raw_form_internals_raw_unchecked
        3. Direct Mapping to Internal Fuzzy Hash
            *   log_block_size
            *   block_size
            *   as_normalized
        4. Plain Copy of the Internal Data
            *   clone
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let block_size = block_size::from_log(log_block_size_raw).unwrap();
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($ty: ty) => {
                    let typename = stringify!($ty);
                    type FuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, false>;
                    if (bh2.len() > <$ty>::MAX_BLOCK_HASH_SIZE_2) { break; }
                    // Initialize raw block hash representations
                    // (remaining bytes are zero-filled)
                    let mut blockhash1 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1];
                    let mut blockhash2 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2];
                    let mut blockhash1_norm = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1];
                    let mut blockhash2_norm = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2];
                    blockhash1[..bh1.len()].copy_from_slice(bh1);
                    blockhash2[..bh2.len()].copy_from_slice(bh2);
                    blockhash1_norm[..bh1_norm.len()].copy_from_slice(bh1_norm);
                    blockhash2_norm[..bh2_norm.len()].copy_from_slice(bh2_norm);
                    // Prepare raw lengths
                    let len_bh1_raw = u8::try_from(bh1.len()).unwrap();
                    let len_bh2_raw = u8::try_from(bh2.len()).unwrap();
                    let len_bh1_norm = u8::try_from(bh1_norm.len()).unwrap();
                    let len_bh2_norm = u8::try_from(bh2_norm.len()).unwrap();
                    // Create base fuzzy hashes (to compare)
                    let hash_raw = RawFuzzyHashType::new_from_internals_raw(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                    let hash_norm = FuzzyHashType::new_from_internals_raw(log_block_size_raw, &blockhash1_norm, &blockhash2_norm, len_bh1_norm, len_bh2_norm);
                    // Create fuzzy hashes in various ways and make sure that they are all the same.
                    let mut hash: $ty = <$ty>::new();
                    hash.init_from_raw_form(&hash_raw);
                    let hash1: $ty = <$ty>::from_raw_form(&hash_raw);
                    let hash2: $ty = <$ty>::from(hash_raw);
                    let mut hash3: $ty = <$ty>::new();
                    hash3.init_from_raw_form_internals_raw(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                    let mut hash4: $ty = <$ty>::new();
                    hash4.init_from_raw_form_internals_raw_internal(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                    let hash5: $ty =
                        <$ty>::new_from_raw_form_internals_raw(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                    let hash6: $ty =
                        <$ty>::new_from_raw_form_internals_raw_internal(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                    let hash7: $ty = <$ty>::from_bytes(bytes_raw).unwrap();
                    let hash8: $ty = str::parse::<$ty>(bytes_str).unwrap();
                    let hash9: $ty = hash1.clone();
                    assert_eq!(hash, hash1, "failed (1-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash2, "failed (1-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash3, "failed (1-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash4, "failed (1-4) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash5, "failed (1-5) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash6, "failed (1-6) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash7, "failed (1-7) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash8, "failed (1-8) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash, hash9, "failed (1-9) on typename={}, bytes_str={:?}", typename, bytes_str);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        let mut hash_u4: $ty = <$ty>::new();
                        hash_u4.init_from_raw_form_internals_raw_unchecked(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                        let hash_u6: $ty =
                            <$ty>::new_from_raw_form_internals_raw_unchecked(log_block_size_raw, &blockhash1, &blockhash2, len_bh1_raw, len_bh2_raw);
                        assert_eq!(hash, hash_u4, "failed (1-10) on typename={}, bytes_str={:?}", typename, bytes_str);
                        assert_eq!(hash, hash_u6, "failed (1-11) on typename={}, bytes_str={:?}", typename, bytes_str);
                    }
                    // Validness
                    assert!(hash.is_valid(), "failed (2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check raw values
                    assert_eq!(hash.norm_hash, hash_norm, "failed (3-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.rle_block1 == [0u8; <$ty>::RLE_BLOCK_SIZE_1] && hash.rle_block2 == [0u8; <$ty>::RLE_BLOCK_SIZE_2], is_normalized,
                        "failed (3-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check direct correspondence to raw values
                    assert_eq!(hash.log_block_size(), log_block_size_raw, "failed (4-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.block_size(), block_size, "failed (4-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.as_normalized(), &hash_norm, "failed (4-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                };
            }
            test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
        }
    });
}

#[test]
fn data_model_init_from_normalized() {
    /*
        Initialization from other fuzzy hash (normalized):
        *   from_normalized
        *   from (normalized)
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let block_size = block_size::from_log(log_block_size_raw).unwrap();
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bytes_str = core::str::from_utf8(bobj_raw.as_bytes()).unwrap();
            macro_rules! test {
                ($ty: ty) => {
                    let typename = stringify!($ty);
                    type FuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, false>;
                    if (bh2_norm.len() > <$ty>::MAX_BLOCK_HASH_SIZE_2) { break; }
                    // Initialize raw block hash representations
                    // (remaining bytes are zero-filled)
                    let mut blockhash1_norm = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1];
                    let mut blockhash2_norm = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2];
                    blockhash1_norm[..bh1_norm.len()].copy_from_slice(bh1_norm);
                    blockhash2_norm[..bh2_norm.len()].copy_from_slice(bh2_norm);
                    // Prepare raw lengths
                    let len_bh1_norm = u8::try_from(bh1_norm.len()).unwrap();
                    let len_bh2_norm = u8::try_from(bh2_norm.len()).unwrap();
                    // Create base fuzzy hashes (to compare)
                    // ... changed from data_model_init_and_basic so that the raw fuzzy hash is
                    // initialized from the normalized data.
                    let hash_raw = RawFuzzyHashType::new_from_internals_raw(log_block_size_raw, &blockhash1_norm, &blockhash2_norm, len_bh1_norm, len_bh2_norm);
                    let hash_norm = FuzzyHashType::new_from_internals_raw(log_block_size_raw, &blockhash1_norm, &blockhash2_norm, len_bh1_norm, len_bh2_norm);
                    // Create fuzzy hashes in various ways and make sure that they are all the same.
                    let hash1: $ty = <$ty>::from_normalized(&hash_norm);
                    let hash2: $ty = <$ty>::from(hash_norm);
                    let hash3: $ty =
                        <$ty>::new_from_raw_form_internals_raw(log_block_size_raw, &blockhash1_norm, &blockhash2_norm, len_bh1_norm, len_bh2_norm);
                    assert_eq!(hash1, hash2, "failed (1-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash1, hash3, "failed (1-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    let hash: $ty = hash1;
                    // Validness
                    assert!(hash.is_valid(), "failed (2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check internal data
                    assert_eq!(hash.rle_block1, [0u8; <$ty>::RLE_BLOCK_SIZE_1], "failed (3-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.rle_block2, [0u8; <$ty>::RLE_BLOCK_SIZE_2], "failed (3-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check corresponding fuzzy hashes
                    assert_eq!(hash.norm_hash, hash_norm, "failed (4-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.to_raw_form(), hash_raw, "failed (4-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check direct correspondence to raw values
                    assert_eq!(hash.log_block_size(), log_block_size_raw, "failed (5-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.block_size(), block_size, "failed (5-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.as_normalized(), &hash_norm, "failed (5-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                };
            }
            test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
        }
    });
}

#[test]
fn data_model_corresponding_fuzzy_hashes() {
    /*
        1. Corresponding Fuzzy Hashes
            *   as_normalized
            *   to_normalized
            *   to_raw_form
            *   into_mut_raw_form
        2. Normalization
            *   normalize_in_place
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($ty: ty) => {
                    let typename = stringify!($ty);
                    type FuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, false>;
                    if (bh2.len() > <$ty>::MAX_BLOCK_HASH_SIZE_2) { break; }
                    // Create base fuzzy hashes (to compare)
                    let hash_raw: RawFuzzyHashType = RawFuzzyHashType::from_bytes(bytes_raw).unwrap();
                    let hash_raw_from_norm: RawFuzzyHashType = RawFuzzyHashType::from_bytes(bytes_norm).unwrap();
                    let hash_norm: FuzzyHashType = FuzzyHashType::from_bytes(bytes_norm).unwrap();
                    // Create fuzzy hashes in various ways and make sure that they are all the same.
                    let mut dual_hash_from_raw: $ty = <$ty>::from(hash_raw);
                    let mut dual_hash_from_norm: $ty = <$ty>::from(hash_norm);
                    let dual_hash_norm: $ty = dual_hash_from_norm;
                    // Validness
                    assert!(dual_hash_from_raw.is_valid(), "failed (2-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert!(dual_hash_from_norm.is_valid(), "failed (2-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check raw values
                    assert_eq!(dual_hash_from_raw.norm_hash, hash_norm, "failed (3-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.norm_hash, hash_norm, "failed (3-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check normalization
                    assert_eq!(dual_hash_from_raw.is_normalized(), is_normalized, "failed (3-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert!(dual_hash_from_norm.is_normalized(), "failed (3-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check corresponding hashes (1)
                    assert_eq!(dual_hash_from_raw.as_normalized(), &hash_norm, "failed (4-1-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_raw.to_normalized(), hash_norm, "failed (4-1-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_raw.to_raw_form(), hash_raw, "failed (4-1-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    let mut hash_raw_dest: RawFuzzyHashType = RawFuzzyHashType::new();
                    dual_hash_from_raw.into_mut_raw_form(&mut hash_raw_dest);
                    assert_eq!(hash_raw_dest, hash_raw, "failed (4-1-4) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.as_normalized(), &hash_norm, "failed (4-2-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.to_normalized(), hash_norm, "failed (4-2-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.to_raw_form(), hash_raw_from_norm, "failed (4-2-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    let mut hash_raw_dest: RawFuzzyHashType = RawFuzzyHashType::new();
                    dual_hash_from_norm.into_mut_raw_form(&mut hash_raw_dest);
                    assert_eq!(hash_raw_dest, hash_raw_from_norm, "failed (4-2-4) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Normalize
                    dual_hash_from_raw.normalize_in_place();
                    dual_hash_from_norm.normalize_in_place();
                    assert!(dual_hash_from_raw.is_valid(), "failed (5-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert!(dual_hash_from_norm.is_valid(), "failed (5-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_norm, dual_hash_from_raw, "failed (5-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_norm, dual_hash_from_norm, "failed (5-4) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert!(dual_hash_norm.is_normalized(), "failed (5-5) on typename={}, bytes_str={:?}", typename, bytes_str);
                    // Check corresponding hashes (2)
                    assert_eq!(dual_hash_norm.as_normalized(), &hash_norm, "failed (6-1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_norm.to_normalized(), hash_norm, "failed (6-2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_norm.to_raw_form(), hash_raw_from_norm, "failed (6-3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    let mut hash_raw_dest: RawFuzzyHashType = RawFuzzyHashType::new();
                    dual_hash_norm.into_mut_raw_form(&mut hash_raw_dest);
                    assert_eq!(hash_raw_dest, hash_raw_from_norm, "failed (6-4) on typename={}, bytes_str={:?}", typename, bytes_str);
                };
            }
            test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
        }
    });
}

#[cfg(feature = "alloc")]
#[test]
fn data_model_corresponding_fuzzy_hash_strings() {
    /*
        Corresponding Fuzzy Hash Strings:
        *   to_normalized_string
        *   to_raw_form_string
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size_raw, bh1, bh2);
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size_raw, bh1_norm, bh2_norm);
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            macro_rules! test {
                ($ty: ty) => {
                    let typename = stringify!($ty);
                    type FuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
                    type RawFuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, false>;
                    if (bh2.len() > <$ty>::MAX_BLOCK_HASH_SIZE_2) { break; }
                    // Create base fuzzy hashes (to compare)
                    let hash_raw: RawFuzzyHashType = RawFuzzyHashType::from_bytes(bytes_raw).unwrap();
                    let hash_norm: FuzzyHashType = FuzzyHashType::from_bytes(bytes_norm).unwrap();
                    // Create strings
                    let str_raw = hash_raw.to_string();
                    let str_norm = hash_norm.to_string();
                    // Create fuzzy hashes in various ways and make sure that they are all the same.
                    let dual_hash_from_raw: $ty = <$ty>::from(hash_raw);
                    let dual_hash_from_norm: $ty = <$ty>::from(hash_norm);
                    // Compare strings
                    assert_eq!(dual_hash_from_raw.to_raw_form_string(), str_raw, "failed (1) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_raw.to_normalized_string(), str_norm, "failed (2) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.to_raw_form_string(), str_norm, "failed (3) on typename={}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(dual_hash_from_norm.to_normalized_string(), str_norm, "failed (4) on typename={}, bytes_str={:?}", typename, bytes_str);
                };
            }
            test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
        }
    });
}


#[test]
fn data_model_corruption() {
    /*
        1. Validity
            *   is_valid
        2. Debug output (when invalid)
            *   fmt (Debug)
    */
    // Prerequisites (partial)
    assert_eq!(rle_encoding::BITS_POSITION, 6);
    assert_eq!(rle_encoding::MAX_RUN_LENGTH, 4);
    /*
        Note:
        It assumes that is_valid() depends on norm_hash.is_valid().
        If we don't assume that, we'd need to duplicate most of FuzzyHashData
        corruption tests (that is very complex).

        Quote from hash_dual.rs:
            pub fn is_valid(&self) -> bool {
                self.norm_hash.is_valid() &&
            ...
    */
    macro_rules! hash_is_invalid {
        ($ty: ty, $hash: expr, $fmt: literal) => {
            let typename = stringify!($ty);
            assert!(!$hash.is_valid(), $fmt, 1, typename);
            #[cfg(feature = "alloc")]
            {
                assert!(format!("{:?}", $hash).starts_with("FuzzyHashDualData { ILL_FORMED: true,"),
                    $fmt, 2, typename);
            }
        };
        ($ty: ty, $hash: expr, $fmt: literal, $($arg:tt)+) => {
            let typename = stringify!($ty);
            assert!(!$hash.is_valid(), $fmt, 1, typename, $($arg)+);
            #[cfg(feature = "alloc")]
            {
                assert!(format!("{:?}", $hash).starts_with("FuzzyHashDualData { ILL_FORMED: true,"),
                    $fmt, 2, typename, $($arg)+);
            }
        };
    }
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        /*
            WARNING:
            Following tests HEAVILY depends on current RLE block design
            and ssdeep constants.
        */
        // Make dummy hash
        let mut hash: $ty = <$ty>::new();
        hash.norm_hash.blockhash1[..7].clone_from_slice(&[1, 1, 1, 2, 3, 3, 3]);
        hash.norm_hash.blockhash2[..7].clone_from_slice(&[4, 4, 4, 5, 6, 6, 6]);
        hash.norm_hash.len_blockhash1 = 7;
        hash.norm_hash.len_blockhash2 = 7;
        hash.norm_hash.log_blocksize = 0;
        assert!(hash.is_valid(), "failed (1-1) on typename={}", typename);
        assert!(hash.norm_hash.is_valid(), "failed (1-2) on typename={}", typename);
        for log_block_size in u8::MIN..=u8::MAX {
            hash.norm_hash.log_blocksize = log_block_size;
            let is_valid = block_size::is_log_valid(log_block_size);
            assert_eq!(hash.is_valid(), is_valid, "failed (1-3) on typename={}", typename);
            assert_eq!(hash.norm_hash.is_valid(), is_valid, "failed (1-4) on typename={}", typename);
        }
        hash.norm_hash.log_blocksize = 0; // set to the valid value (again)
        // RLE block is currently filled with zeroes.
        assert!(hash.rle_block1.iter().all(|&x| x == 0), "failed (2-1) on typename={}", typename);
        assert!(hash.rle_block2.iter().all(|&x| x == 0), "failed (2-2) on typename={}", typename);
        // RLE Block: Non-zero RLE block after termination (block hash 1)
        {
            for index in 1..<$ty>::RLE_BLOCK_SIZE_1 {
                for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                    let mut hash = hash;
                    hash.rle_block1[index] = 1 | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (3-1-{}) on typename={}, index={}, length={}", index, length);
                }
            }
        }
        // RLE Block: Non-zero RLE block after termination (block hash 2)
        {
            for index in 1..<$ty>::RLE_BLOCK_SIZE_2 {
                for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                    let mut hash = hash;
                    hash.rle_block2[index] = 1 | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (3-2-{}) on typename={}, index={}, length={}", index, length);
                }
            }
        }
        // RLE Block: Position exceeds the block hash size (block hash 1)
        {
            let mut hash = hash;
            for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                hash.rle_block1[0] = 6 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (4-1-1) on typename={}, length={}", typename, length);
            }
            for index in hash.norm_hash.len_blockhash1..=rle_encoding::MASK_POSITION {
                for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                    hash.rle_block1[0] = index | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (4-1-2-{}) on typename={}, index={}, length={}", index, length);
                }
            }
        }
        // RLE Block: Position exceeds the block hash size (block hash 2)
        {
            let mut hash = hash;
            for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                hash.rle_block2[0] = 6 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (4-2-1) on typename={}, length={}", typename, length);
            }
            for index in hash.norm_hash.len_blockhash2..=rle_encoding::MASK_POSITION {
                for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                    hash.rle_block2[0] = index | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (4-2-2-{}) on typename={}, index={}, length={}", index, length);
                }
            }
        }
        // RLE Block: Position is not the tail of identical character sequence (1)
        {
            let mut hash = hash;
            for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                if length != 0 {
                    hash.rle_block1[0] = 0 | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (5-1-1-{}) on typename={}, length={}", length);   // "**B"
                }
                hash.rle_block1[0] = 1 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-1-2-{}) on typename={}, length={}", length);   // "*BB"
                hash.rle_block1[0] = 2 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (5-1-3) on typename={}", typename); // "BBB" (valid)
                hash.rle_block1[0] = 3 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-1-4-{}) on typename={}, length={}", length);   // "BBC"
                hash.rle_block1[0] = 4 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-1-5-{}) on typename={}, length={}", length);   // "BCD"
                hash.rle_block1[0] = 5 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-1-6-{}) on typename={}, length={}", length);   // "CDD"
                hash.rle_block1[0] = 6 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (5-1-7) on typename={}", typename); // "DDD" (valid)
            }
        }
        // RLE Block: Position is not the tail of identical character sequence (2)
        {
            let mut hash = hash;
            for length in 0..rle_encoding::MAX_RUN_LENGTH as u8 {
                if length != 0 {
                    hash.rle_block2[0] = 0 | (length << rle_encoding::BITS_POSITION);
                    hash_is_invalid!($ty, hash, "failed (5-2-1-{}) on typename={}, length={}", length);   // "**E"
                }
                hash.rle_block2[0] = 1 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-2-2-{}) on typename={}, length={}", length);   // "*EE"
                hash.rle_block2[0] = 2 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (5-2-3) on typename={}", typename); // "EEE" (valid)
                hash.rle_block2[0] = 3 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-2-4-{}) on typename={}, length={}", length);   // "EEF"
                hash.rle_block2[0] = 4 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-2-5-{}) on typename={}, length={}", length);   // "EFG"
                hash.rle_block2[0] = 5 | (length << rle_encoding::BITS_POSITION);
                hash_is_invalid!($ty, hash, "failed (5-2-6-{}) on typename={}, length={}", length);   // "FGG"
                hash.rle_block2[0] = 6 | (length << rle_encoding::BITS_POSITION);
                assert!(hash.is_valid(), "failed (5-2-7) on typename={}", typename); // "GGG" (valid)
            }
        }
        // RLE Block: Must be sorted by position (block hash 1)
        {
            let mut hash = hash;
            // "BBBCDDD" -> "BBBBCDDDD"
            hash.rle_block1[0] = 2;
            hash.rle_block1[1] = 6;
            assert!(hash.is_valid(), "failed (6-1-1) on typename={}", typename);
            // Now swap the order (making the RLE block invalid)
            hash.rle_block1[0] = 6;
            hash.rle_block1[1] = 2;
            hash_is_invalid!($ty, hash, "failed (6-1-2-{}) on typename={}");
        }
        // RLE Block: Must be sorted by position (block hash 2)
        {
            let mut hash = hash;
            // "EEEFGGG" -> "EEEEFGGGG"
            hash.rle_block2[0] = 2;
            hash.rle_block2[1] = 6;
            assert!(hash.is_valid(), "failed (6-2-1) on typename={}", typename);
            // Now swap the order (making the RLE block invalid)
            hash.rle_block2[0] = 6;
            hash.rle_block2[1] = 2;
            hash_is_invalid!($ty, hash, "failed (6-2-2-{}) on typename={}");
        }
        // RLE Block: Canonicality on extension using multiple RLE encodings (1)
        {
            let mut hash = hash;
            // Extend five characters
            hash.rle_block1[0] = 0xc2; // RLE(2, 4)
            hash.rle_block1[1] = 0x02; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-1-1) on typename={}", typename);
            // Non-canonical encodings
            hash.rle_block1[0] = 0x02; // RLE(2, 1)
            hash.rle_block1[1] = 0xc2; // RLE(2, 4)
            hash_is_invalid!($ty, hash, "failed (7-1-2-{}) on typename={}");
            hash.rle_block1[0] = 0x42; // RLE(2, 2)
            hash.rle_block1[1] = 0x82; // RLE(2, 3)
            hash_is_invalid!($ty, hash, "failed (7-1-3-{}) on typename={}");
            hash.rle_block1[0] = 0x82; // RLE(2, 3)
            hash.rle_block1[1] = 0x42; // RLE(2, 2)
            hash_is_invalid!($ty, hash, "failed (7-1-4-{}) on typename={}");
            // Back to valid one (rle_block1[1] does not have maximum length)
            hash.rle_block1[0] = 0xc2; // RLE(2, 4)
            hash.rle_block1[1] = 0x02; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-1-5) on typename={}", typename);
            // Test extension with another position
            hash.rle_block1[2] = 0x06; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-1-6) on typename={}", typename);
        }
        // RLE Block: Canonicality on extension using multiple RLE encodings (2)
        {
            let mut hash = hash;
            // Extend five characters
            hash.rle_block2[0] = 0xc2; // RLE(2, 4)
            hash.rle_block2[1] = 0x02; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-2-1) on typename={}", typename);
            // Non-canonical encodings
            hash.rle_block2[0] = 0x02; // RLE(2, 1)
            hash.rle_block2[1] = 0xc2; // RLE(2, 4)
            hash_is_invalid!($ty, hash, "failed (7-2-2-{}) on typename={}");
            hash.rle_block2[0] = 0x42; // RLE(2, 2)
            hash.rle_block2[1] = 0x82; // RLE(2, 3)
            hash_is_invalid!($ty, hash, "failed (7-2-3-{}) on typename={}");
            hash.rle_block2[0] = 0x82; // RLE(2, 3)
            hash.rle_block2[1] = 0x42; // RLE(2, 2)
            hash_is_invalid!($ty, hash, "failed (7-2-4-{}) on typename={}");
            // Back to valid one (rle_block2[1] does not have maximum length)
            hash.rle_block2[0] = 0xc2; // RLE(2, 4)
            hash.rle_block2[1] = 0x02; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-2-5) on typename={}", typename);
            // Test extension with another position
            hash.rle_block2[2] = 0x06; // RLE(2, 1)
            assert!(hash.is_valid(), "failed (7-2-6) on typename={}", typename);
        }
        // RLE Block: Maximum extension exceeds maximum length on current config (1)
        {
            let mut hash = hash;
            // On the current design, it exceeds maximum length by 7 (len_blockhash1).
            hash.rle_block1.fill(0xc2); // Fill with RLE(2, 4)
            hash_is_invalid!($ty, hash, "failed (8-1-1-{}) on typename={}"); // +7
            // Decrease the trailing RLE block 7 times
            // (until the hash becomes valid).
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x82;
            hash_is_invalid!($ty, hash, "failed (8-1-2-{}) on typename={}"); // +6
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x42;
            hash_is_invalid!($ty, hash, "failed (8-1-3-{}) on typename={}"); // +5
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x02;
            hash_is_invalid!($ty, hash, "failed (8-1-4-{}) on typename={}"); // +4
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x00;
            hash.rle_block1[hash.rle_block1.len() - 2] = 0xc2;
            hash_is_invalid!($ty, hash, "failed (8-1-5-{}) on typename={}"); // +3
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x82;
            hash_is_invalid!($ty, hash, "failed (8-1-6-{}) on typename={}"); // +2
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x42;
            hash_is_invalid!($ty, hash, "failed (8-1-7-{}) on typename={}"); // +1
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x02;
            assert!(hash.is_valid(), "failed (8-1-8) on typename={}", typename); // +0
        }
        // RLE Block: Maximum extension exceeds maximum length on current config (2)
        {
            let mut hash = hash;
            // On the current design, it exceeds maximum length by 7 (len_blockhash2).
            hash.rle_block2.fill(0xc2); // Fill with RLE(2, 4)
            hash_is_invalid!($ty, hash, "failed (8-2-1-{}) on typename={}"); // +7
            // Decrease the trailing RLE block 7 times
            // (until the hash becomes valid).
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x82;
            hash_is_invalid!($ty, hash, "failed (8-2-2-{}) on typename={}"); // +6
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x42;
            hash_is_invalid!($ty, hash, "failed (8-2-3-{}) on typename={}"); // +5
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x02;
            hash_is_invalid!($ty, hash, "failed (8-2-4-{}) on typename={}"); // +4
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x00;
            hash.rle_block2[hash.rle_block2.len() - 2] = 0xc2;
            hash_is_invalid!($ty, hash, "failed (8-2-5-{}) on typename={}"); // +3
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x82;
            hash_is_invalid!($ty, hash, "failed (8-2-6-{}) on typename={}"); // +2
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x42;
            hash_is_invalid!($ty, hash, "failed (8-2-7-{}) on typename={}"); // +1
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x02;
            assert!(hash.is_valid(), "failed (8-2-8) on typename={}", typename); // +0
        }
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn parse_overflow_examples_long_and_short() {
    // Block hash 1: block_hash::FULL_SIZE
    // Block hash 2: block_hash::HALF_SIZE + 1 (will overflow on DualFuzzyHash)
    const HASH_STR_1: &str = "3\
        :0123456789012345678901234567890123456789012345678901234567890123\
        :012345678901234567890123456789012";
    assert_eq!(
        str::parse::<DualFuzzyHash>(HASH_STR_1),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 32))
    );
    assert!(str::parse::<LongDualFuzzyHash>(HASH_STR_1).is_ok());
    // Block hash 1: block_hash::FULL_SIZE
    // Block hash 2: block_hash::FULL_SIZE + 1 (will also overflow on LongDualFuzzyHash)
    const HASH_STR_2: &str = "3\
        :0123456789012345678901234567890123456789012345678901234567890123\
        :01234567890123456789012345678901234567890123456789012345678901234";
    assert_eq!(
        str::parse::<DualFuzzyHash>(HASH_STR_2),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 32))
    );
    assert_eq!(
        str::parse::<LongDualFuzzyHash>(HASH_STR_2),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 64))
    );
}

#[test]
fn parse_errors() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        assert_eq!(
            <$ty>::from_bytes(b""),
            Err(ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize, 0)),
            "failed on typename={}", typename
        );
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[test]
fn cover_hash() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let mut hashes = std::collections::HashSet::<$ty>::new();
        assert!(hashes.insert(<$ty>::new()), "failed (1) on typename={}", typename);
        assert!(!hashes.insert(<$ty>::new()), "failed (2) on typename={}", typename);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn ord_and_sorting() {
    use core::cmp::Ordering;
    use std::string::ToString;
    use std::vec;
    use std::vec::Vec;
    use std::collections::HashSet;
    /*
        Sorted by block hash order (Base64 indices and length).

        Each internal vector indicates that they are equivalent
        after performing normalization.
        Note that 'A' has Base64 index zero and FuzzyHashData zero-fills
        each tail of block hashes (making the behavior more deterministic).
    */
    let sorted_dict = vec![
        vec![
            "ABBBR",
            "ABBBBR",
        ],
        vec![
            "ABBBRA",
            "ABBBBRA",
        ],
        vec![
            "ABBBRAA",
            "ABBBBRAA",
        ],
        vec![
            "ABBBREVIATES",
            "ABBBBREVIATES",
        ],
        vec!["ABBR"],
        vec!["ABBRA"],
        vec!["ABBRAA"],
        vec![
            "ABBRAAA",
            "ABBRAAAA",
        ],
        vec!["ABBREVIATES"],
        vec![
            "abbbr",
            "abbbbr",
        ],
        vec![
            "abbbrA",
            "abbbbrA",
        ],
        vec![
            "abbbrAA",
            "abbbbrAA",
        ],
        vec![
            "abbbreviates",
            "abbbbreviates",
        ],
        vec!["abbr"],
        vec!["abbrA"],
        vec!["abbrAA"],
        vec![
            "abbrAAA",
            "abbrAAAA",
        ],
        vec!["abbreviates"],
        vec![
            "000123",
            "0000123",
        ],
        vec!["0123"],
        vec!["0123A"],
        vec!["0123AA"],
        vec![
            "0123AAA",
            "0123AAAA",
        ],
        vec!["01234567"],
    ];
    // Make sure that all strings inside sorted_dict are unique.
    {
        let mut strings = HashSet::<&str>::new();
        for bh in &sorted_dict {
            for &bh_entry in bh {
                assert!(strings.insert(bh_entry), "failed on bh_entry={:?}", bh_entry);
            }
        }
    }
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        // Construct sorted hashes list
        let mut hashes: Vec<$ty> = Vec::new();
        for log_block_size_raw in 0u8..=3 {
            for bh1 in &sorted_dict {
                for bh2 in &sorted_dict {
                    for &bh1_entry in bh1 {
                        for &bh2_entry in bh2 {
                            let mut s = block_size::from_log_internal(log_block_size_raw).to_string();
                            s += ":";
                            s += bh1_entry;
                            s += ":";
                            s += bh2_entry;
                            hashes.push(str::parse(s.as_str()).unwrap());
                        }
                    }
                }
            }
        }
        // Test consistency between Vec order and comparison results
        for (i1, h1) in hashes.iter().enumerate() {
            for (i2, h2) in hashes.iter().enumerate() {
                match h1.as_normalized().cmp(h2.as_normalized()) {
                    Ordering::Equal => {
                        // Because "equal" elements (by normalized hashes) are
                        // surrounded by "lesser" elements and "greater" elements,
                        // they will make a consecutive "block".
                        // Just check whether direct comparison between h1 and h2
                        // can be used to determine whether the hashes are the same.
                        assert_eq!(h1.cmp(&h2) == Ordering::Equal, i1 == i2,
                            "failed (1) on typename={}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
                    },
                    Ordering::Greater => {
                        // Make sure that the result is the same as direct comparison between h1 and h2.
                        assert_eq!(h1.cmp(&h2), Ordering::Greater,
                            "failed (2-1) on typename={}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
                        // Check sorted indexes
                        assert!(i1 > i2,
                            "failed (2-2) on typename={}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
                    },
                    Ordering::Less => {
                        // Make sure that the result is the same as direct comparison between h1 and h2.
                        assert_eq!(h1.cmp(&h2), Ordering::Less,
                            "failed (3-1) on typename={}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
                        // Check sorted indexes
                        assert!(i1 < i2,
                            "failed (3-2) on typename={}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
                    },
                }
            }
        }
        // Sorting the list makes the order the same as the original.
        // This (partially) tests that `FuzzyHashDualData` ordering is
        // deterministic enough.
        let cloned = hashes.clone();
        hashes.reverse();
        hashes.sort();
        assert_eq!(hashes, cloned, "failed (4) on typename={}", typename);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[test]
fn impl_debug() {
    // Test empty hashes
    let hash = DualFuzzyHash::new();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            LONG: false, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\", \
            rle_block1: [], \
            rle_block2: [] \
        }"
    );
    let hash = LongDualFuzzyHash::new();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            LONG: true, \
            block_size: 3, \
            blockhash1: \"\", \
            blockhash2: \"\", \
            rle_block1: [], \
            rle_block2: [] \
        }"
    );
    // Short expansion
    // "AAAA"  -> "AAA" + RLE expansion (length 1)
    // "BBBBB" -> "BBB" + RLE expansion (length 2)
    // Note that valid hash object will not show trailing RLENull encodings.
    let hash: DualFuzzyHash = str::parse("3\
        :AAAA\
        :01234567BBBBB").unwrap();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            LONG: false, \
            block_size: 3, \
            blockhash1: \"AAA\", \
            blockhash2: \"01234567BBB\", \
            rle_block1: [\
                RLE(2, 1)\
            ], \
            rle_block2: [\
                RLE(10, 2)\
            ] \
        }"
    );
    // Long expansion: maximum block hash length (when in raw form; short)
    let hash: DualFuzzyHash = str::parse("3\
        :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        :BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            LONG: false, \
            block_size: 3, \
            blockhash1: \"AAA\", \
            blockhash2: \"BBB\", \
            rle_block1: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ], \
            rle_block2: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ] \
        }"
    );
    // Long expansion: maximum block hash length (when in raw form; long)
    let hash: LongDualFuzzyHash = str::parse("3\
        :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        :BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            LONG: true, \
            block_size: 3, \
            blockhash1: \"AAA\", \
            blockhash2: \"BBB\", \
            rle_block1: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ], \
            rle_block2: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ] \
        }"
    );
    // Corrupted RLE block (RLENull)
    let mut hash: DualFuzzyHash = str::parse("3\
        :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        :BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    hash.rle_block1[4] = 0;
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            ILL_FORMED: true, \
            LONG: false, \
            log_blocksize: 0, \
            len_blockhash1: 3, \
            len_blockhash2: 3, \
            blockhash1: [\
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            blockhash2: [\
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            rle_block1: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLENull, RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ], \
            rle_block2: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 1)\
            ] \
        }"
    );
    // Corrupted length after expansion (that would make an overflow)
    // Note that we use 31 'B's here instead of 32 'B's above to see
    // a valid RLENull (block hash 1 is invalid but 2 is valid).
    let mut hash: DualFuzzyHash = str::parse("3\
        :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        :BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    hash.rle_block1[15] = rle_encoding::encode(2, 4);
    assert_eq!(
        format!("{:?}", hash),
        "FuzzyHashDualData { \
            ILL_FORMED: true, \
            LONG: false, \
            log_blocksize: 0, \
            len_blockhash1: 3, \
            len_blockhash2: 3, \
            blockhash1: [\
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            blockhash2: [\
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            rle_block1: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4)\
            ], \
            rle_block2: [\
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLE(2, 4), \
                RLE(2, 4), RLE(2, 4), RLE(2, 4), RLENull\
            ] \
        }"
    );
}

const TEST_VECTOR_SHORT_FHASH_NORM_0: &str = "3:ABBCCCDDDDEEEEE:555554444333221";
const TEST_VECTOR_SHORT_FHASH_NORM_1: &str = "3:ABBCCCDDDEEE:555444333221";

#[test]
fn impl_display() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let hash = str::parse::<$ty>(TEST_VECTOR_SHORT_FHASH_NORM_0).unwrap();
        assert_eq!(
            format!("{}", hash),
            format!("{{{}|{}}}", TEST_VECTOR_SHORT_FHASH_NORM_1, TEST_VECTOR_SHORT_FHASH_NORM_0),
            "failed on typename={}", typename
        );
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[cfg(feature = "alloc")]
#[test]
fn impl_to_string() {
    macro_rules! test {($ty: ty) => {
        let typename = stringify!($ty);
        let hash = str::parse::<$ty>(TEST_VECTOR_SHORT_FHASH_NORM_0).unwrap();
        assert_eq!(hash.to_raw_form_string(), TEST_VECTOR_SHORT_FHASH_NORM_0, "failed (1) on typename={}", typename);
        assert_eq!(hash.to_normalized_string(), TEST_VECTOR_SHORT_FHASH_NORM_1, "failed (2) on typename={}", typename);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}
