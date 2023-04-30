// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::cmp::Ordering;
use core::str::FromStr;
#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

use crate::base64::BASE64_INVALID;
use crate::hash::{
    FuzzyHashData,
    FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash,
    FuzzyHashOperationError
};
use crate::hash::block::{
    BlockSize, BlockHash
};
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin
};
use crate::test_utils::{assert_fits_in, test_auto_clone, test_for_each_type};
#[cfg(feature = "alloc")]
use crate::test_utils::test_auto_debug_for_enum;


macro_rules! test_for_each_block_sizes {
    ($test: ident) => {{
        loop
        {
            $test!(BlockHash::FULL_SIZE, BlockHash::FULL_SIZE);
            break;
        }
        loop
        {
            $test!(BlockHash::FULL_SIZE, BlockHash::HALF_SIZE);
            break;
        }
    }};
}


#[test]
fn test_datamodel_new() {
    macro_rules! test {
        ($ty: ty) => {
            let hash_new: $ty = <$ty>::new();
            let hash_default: $ty = <$ty>::default();
            let hash_cloned: $ty = hash_new.clone();
            let hash_from_str: $ty = <$ty>::from_str("3::").unwrap();
            // Test validity of the empty value.
            assert!(hash_new.is_valid());
            assert!(hash_default.is_valid());
            assert!(hash_cloned.is_valid());
            // Test validity of fuzzy hashes converted from "empty" fuzzy hash string.
            assert!(hash_from_str.is_valid());
            // Compare two values.
            assert_eq!(hash_new, hash_default);
            assert_eq!(hash_new, hash_cloned);
            assert_eq!(hash_new, hash_from_str);
            assert!(hash_new.full_eq(&hash_default));
            assert!(hash_new.full_eq(&hash_cloned));
            assert!(hash_new.full_eq(&hash_from_str));
        };
    }
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}

#[test]
fn test_fuzzy_hash_operation_error_basic() {
    #[cfg(feature = "alloc")]
    {
        test_auto_debug_for_enum!(
            FuzzyHashOperationError,
            [
                BlockHashOverflow,
                StringizationOverflow,
            ]
        );
    }
    test_auto_clone::<FuzzyHashOperationError>(&FuzzyHashOperationError::BlockHashOverflow);
}

#[cfg(feature = "alloc")]
#[test]
fn cover_fuzzy_hash_operation_error_display() {
    assert_eq!(format!("{}", FuzzyHashOperationError::BlockHashOverflow),
        "overflow will occur while copying the block hash.");
    assert_eq!(format!("{}", FuzzyHashOperationError::StringizationOverflow),
        "overflow will occur while converting to the string representation.");
}


#[test]
fn test_datamodel_generic() {
    /*
        Tested methods:
        1. Initialization from Internal Data (only valid cases)
            *   init_from_internals_raw_internal
            *   init_from_internals_raw_unchecked
            *   new_from_internals_raw_internal
            *   new_from_internals_raw_unchecked
            *   init_from_internals_raw
            *   new_from_internals_raw
            *   new_from_internals_internal
            *   new_from_internals_unchecked
            *   new_from_internals
            *   clone
        2. Direct Mapping to Internal Data
            *   block_hash_1
            *   block_hash_2
            *   block_hash_1_as_array
            *   block_hash_2_as_array
            *   block_hash_1_len
            *   block_hash_2_len
            *   log_block_size
        3. String Conversion
            *   len_in_str
            *   MAX_LEN_IN_STR
            *   store_into_bytes (length and minimum requirements)
            *   to_string        (length and minimum requirements)
        4. String Parser
            *   from_bytes (involution when no normalization occur)
            *   from_str   (involution when no normalization occur)
    */
    macro_rules! test {($ty: ty) => {
        let mut passed_max_len_in_str = false;
        for log_block_size in 0..BlockSize::NUM_VALID {
            for len_blockhash1 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                assert_fits_in!(len_blockhash1, u8);
                assert!(len_blockhash1 <= BlockHash::FULL_SIZE);
                let mut blockhash1 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1]; // zero fill is mandatory
                for i in 0..len_blockhash1 {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    blockhash1[i] = i as u8;
                }
                for len_blockhash2 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                    assert_fits_in!(len_blockhash2, u8);
                    assert!(len_blockhash2 <= BlockHash::FULL_SIZE);
                    let mut blockhash2 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2]; // zero fill is mandatory
                    for i in 0..len_blockhash2 {
                        assert!(i < BlockHash::ALPHABET_SIZE);
                        blockhash2[i] = (BlockHash::ALPHABET_SIZE - 1 - i) as u8;
                    }
                    let log_block_size_raw = u8::try_from(log_block_size).unwrap();
                    let len_blockhash1_raw = u8::try_from(len_blockhash1).unwrap();
                    let len_blockhash2_raw = u8::try_from(len_blockhash2).unwrap();
                    let blockhash1_slice = &blockhash1[..len_blockhash1];
                    let blockhash2_slice = &blockhash2[..len_blockhash2];
                    // Make fuzzy hashes using various methods and
                    // make sure that they are equivalent.
                    let hash: $ty = {
                        let mut hash1: $ty = <$ty>::new();
                        hash1.init_from_internals_raw_internal(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw
                        );
                        let hash2: $ty =
                            <$ty>::new_from_internals_raw_internal(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                        let mut hash3: $ty = <$ty>::new();
                        hash3.init_from_internals_raw(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw
                        );
                        let hash4: $ty =
                            <$ty>::new_from_internals_raw(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                        let hash5: $ty =
                            <$ty>::new_from_internals_internal(
                                BlockSize::from_log(log_block_size_raw).unwrap(),
                                blockhash1_slice,
                                blockhash2_slice
                            );
                        let hash6: $ty =
                            <$ty>::new_from_internals(
                                BlockSize::from_log(log_block_size_raw).unwrap(),
                                blockhash1_slice,
                                blockhash2_slice
                            );
                        let hash7: $ty = hash1.clone();
                        assert_eq!(hash1, hash2);
                        assert_eq!(hash1, hash3);
                        assert_eq!(hash1, hash4);
                        assert_eq!(hash1, hash5);
                        assert_eq!(hash1, hash6);
                        assert_eq!(hash1, hash7);
                        assert!(hash1.full_eq(&hash2));
                        assert!(hash1.full_eq(&hash3));
                        assert!(hash1.full_eq(&hash4));
                        assert!(hash1.full_eq(&hash5));
                        assert!(hash1.full_eq(&hash6));
                        assert!(hash1.full_eq(&hash7));
                        #[cfg(feature = "unsafe")]
                        unsafe {
                            let mut hash_u1 = <$ty>::new();
                            hash_u1.init_from_internals_raw_unchecked(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                            let hash_u2 = <$ty>::new_from_internals_raw_unchecked(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                            let hash_u5 = <$ty>::new_from_internals_unchecked(
                                BlockSize::from_log(log_block_size_raw).unwrap(),
                                blockhash1_slice,
                                blockhash2_slice
                            );
                            assert_eq!(hash1, hash_u1);
                            assert_eq!(hash1, hash_u2);
                            assert_eq!(hash1, hash_u5);
                            assert!(hash1.full_eq(&hash_u1));
                            assert!(hash1.full_eq(&hash_u2));
                            assert!(hash1.full_eq(&hash_u5));
                        }
                        hash1
                    };
                    // Check validity
                    assert!(hash.is_valid());
                    // Check raw values
                    assert_eq!(hash.blockhash1, blockhash1);
                    assert_eq!(hash.blockhash2, blockhash2);
                    assert_eq!(hash.len_blockhash1, len_blockhash1_raw);
                    assert_eq!(hash.len_blockhash2, len_blockhash2_raw);
                    assert_eq!(hash.log_blocksize, log_block_size_raw);
                    // Check direct correspondence to raw values
                    assert_eq!(hash.block_hash_1(), blockhash1_slice);
                    assert_eq!(hash.block_hash_2(), blockhash2_slice);
                    assert_eq!(hash.block_hash_1_as_array(), &blockhash1);
                    assert_eq!(hash.block_hash_2_as_array(), &blockhash2);
                    assert_eq!(hash.block_hash_1_len(), len_blockhash1);
                    assert_eq!(hash.block_hash_2_len(), len_blockhash2);
                    assert_eq!(hash.log_block_size(), log_block_size_raw);
                    // Check len_in_str: buffer size fits in MAX_LEN_IN_STR
                    if log_block_size as usize == BlockSize::NUM_VALID - 1 &&
                        len_blockhash1 == <$ty>::MAX_BLOCK_HASH_SIZE_1 &&
                        len_blockhash2 == <$ty>::MAX_BLOCK_HASH_SIZE_2
                    {
                        // Upper bound must be exact.
                        assert!(hash.len_in_str() == <$ty>::MAX_LEN_IN_STR);
                        // This branch must be reached (at least once).
                        passed_max_len_in_str = true;
                    }
                    else {
                        assert!(hash.len_in_str() <= <$ty>::MAX_LEN_IN_STR);
                    }
                    // Check store_into_bytes
                    const NULL_CH: u8 = 0;
                    let mut str_buffer = [NULL_CH; <$ty>::MAX_LEN_IN_STR + 1];
                    hash.store_into_bytes(&mut str_buffer[..]).unwrap();
                    assert_eq!(str_buffer[str_buffer.len() - 1], NULL_CH);
                    // Check store_into_bytes and len_in_str:
                    // len_in_str is the exact length of the output.
                    let len_in_str: usize = str_buffer.iter().position(|&x| x == NULL_CH).unwrap();
                    assert_eq!(hash.len_in_str(), len_in_str);
                    // Check minimum string requirements (only ASCII printable).
                    assert!(str_buffer[..len_in_str].iter().all(
                        |&x| x != NULL_CH && x.is_ascii() && !x.is_ascii_control()
                    ));
                    // Converting back to the original hash preserves the value.
                    {
                        let hash_back: $ty = <$ty>::from_bytes(&str_buffer[..len_in_str]).unwrap();
                        assert_eq!(hash, hash_back);
                        assert!(hash.full_eq(&hash_back));
                    }
                    // Check to_string and String::from
                    #[cfg(feature = "alloc")]
                    {
                        let s = hash.to_string();
                        let s2 = String::from(hash);
                        // Two strings match.
                        assert_eq!(s, s2);
                        // len_in_str is the exact length of the output.
                        assert_eq!(s.len(), hash.len_in_str());
                        // Check minimum string requirements (only ASCII printable).
                        assert!(s.chars().all(
                            |x| x.is_ascii() && !x.is_ascii_control() && u32::from(x) != 0
                        ));
                        // Converting back to the original hash preserves the value.
                        {
                            let hash_back: $ty = <$ty>::from_str(s.as_str()).unwrap();
                            assert_eq!(hash, hash_back);
                            assert!(hash.full_eq(&hash_back));
                        }
                        // Converting back to the original hash preserves the value.
                        {
                            let hash_back: $ty = <$ty>::from_bytes(s.as_bytes()).unwrap();
                            assert_eq!(hash, hash_back);
                            assert!(hash.full_eq(&hash_back));
                        }
                    }
                }
            }
        }
        assert!(passed_max_len_in_str);
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn test_datamodel_block_size() {
    /*
        Tested methods:
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
        for bs1 in 0..BlockSize::NUM_VALID as u8 {
            for bs2 in 0..BlockSize::NUM_VALID as u8 {
                // [BS1]:A:
                let lhs = <$ty>::new_from_internals(
                    BlockSize::from_log(bs1).unwrap(), &[0], &[]);
                // [BS2]::A
                let rhs = <$ty>::new_from_internals(
                    BlockSize::from_log(bs2).unwrap(), &[], &[0]);
                assert!(lhs.is_valid());
                assert!(rhs.is_valid());
                assert_ne!(lhs, rhs);
                // Use cmp_by_block_size (call with two different conventions).
                let ord = <$ty>::cmp_by_block_size(&lhs, &rhs);
                match ord {
                    Ordering::Equal => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Equal);
                        assert!(bs1 == bs2);
                        // [BS]:A: > [BS]::A
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Greater);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Less);
                    }
                    Ordering::Less => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Greater);
                        assert!(bs1 < bs2);
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Less);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Greater);
                    }
                    Ordering::Greater => {
                        assert_eq!(<$ty>::cmp_by_block_size(&rhs, &lhs), Ordering::Less);
                        assert!(bs1 > bs2);
                        assert_eq!(<$ty>::cmp(&lhs, &rhs), Ordering::Greater);
                        assert_eq!(<$ty>::cmp(&rhs, &lhs), Ordering::Less);
                    }
                }
                assert_eq!(ord, lhs.cmp_by_block_size(&rhs));
                // Use compare_block_sizes.
                let rel = <$ty>::compare_block_sizes(&lhs, &rhs);
                // Test consistency between logical expressions and the BlockSizeRelation value.
                // TODO: Replace plain subtraction with abs_diff when MSRV 1.60 is acceptable.
                assert_eq!(bs1 == bs2, rel == BlockSizeRelation::NearEq);
                assert_eq!(bs1 == bs2 + 1, rel == BlockSizeRelation::NearGt);
                assert_eq!(bs1 + 1 == bs2, rel == BlockSizeRelation::NearLt);
                assert_eq!(((bs1 as i32) - (bs2 as i32)).abs() > 1, rel == BlockSizeRelation::Far);
                // Test consistency between the result of other functions and the BlockSizeRelation value.
                #[allow(clippy::bool_assert_comparison)]
                match rel {
                    BlockSizeRelation::Far => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false);
                        assert_ne!(ord, Ordering::Equal);
                    }
                    BlockSizeRelation::NearLt => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), true);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false);
                        assert_eq!(ord, Ordering::Less);
                    }
                    BlockSizeRelation::NearEq => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), true);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), false);
                        assert_eq!(ord, Ordering::Equal);
                    }
                    BlockSizeRelation::NearGt => {
                        assert_eq!(<$ty>::is_block_sizes_near(&lhs, &rhs), true);
                        assert_eq!(<$ty>::is_block_sizes_near_lt(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_eq(&lhs, &rhs), false);
                        assert_eq!(<$ty>::is_block_sizes_near_gt(&lhs, &rhs), true);
                        assert_eq!(ord, Ordering::Greater);
                    }
                }
            }
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn test_datamodel_blockhash_contents() {
    crate::hash::test_utils::test_blockhash_contents_all(&|bh1, bh2, bh1_norm, bh2_norm|
    {
        /*
            Normalization (simple):
            *   is_normalized
        */
        {
            let raw_hash: LongRawFuzzyHash =
                LongRawFuzzyHash::new_from_internals(BlockSize::MIN, bh1, bh2);
            let norm_hash: LongFuzzyHash =
                LongFuzzyHash::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
            assert!(norm_hash.is_normalized());
            assert_eq!(raw_hash.is_normalized(), bh1.len() == bh1_norm.len() && bh2.len() == bh2_norm.len());
            if bh2.len() <= BlockHash::HALF_SIZE {
                let raw_hash: RawFuzzyHash =
                    RawFuzzyHash::new_from_internals(BlockSize::MIN, bh1, bh2);
                assert_eq!(raw_hash.is_normalized(), bh1.len() == bh1_norm.len() && bh2.len() == bh2_norm.len());
            }
            if bh2_norm.len () <= BlockHash::HALF_SIZE {
                let norm_hash: FuzzyHash =
                    FuzzyHash::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
                assert!(norm_hash.is_normalized());
            }
        }
        /*
            Normalization (complex):
            1. Normalization
                *   normalize
                *   normalize_in_place
                *   clone_normalized
            2. Conversion involving normalization and non-normalization
                *   to_raw_form
                *   from_raw_form
            3. Clone
                *   clone
        */
        macro_rules! test {($bh1_sz: expr, $bh2_sz: expr) => {
            type FuzzyHashType = FuzzyHashData<{$bh1_sz}, {$bh2_sz}, true>;
            type RawFuzzyHashType = FuzzyHashData<{$bh1_sz}, {$bh2_sz}, false>;
            if bh2.len() > $bh2_sz {
                break;
            }
            let raw_hash: RawFuzzyHashType =
                RawFuzzyHashType::new_from_internals(BlockSize::MIN, bh1, bh2);
            let norm_hash: FuzzyHashType =
                FuzzyHashType::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
            let norm_ref_hash: RawFuzzyHashType = norm_hash.to_raw_form();
            let norm_from_raw_hash: FuzzyHashType = raw_hash.normalize();
            let norm_from_raw_hash_2: FuzzyHashType = FuzzyHashType::from_raw_form(&raw_hash);
            let mut norm_from_raw_inplace_hash: RawFuzzyHashType = raw_hash;
            norm_from_raw_inplace_hash.normalize_in_place();
            let norm_raw_hash: RawFuzzyHashType = raw_hash.clone_normalized();
            let norm_norm_hash: FuzzyHashType = norm_hash.clone_normalized();
            assert!(norm_hash.is_normalized());
            macro_rules! test_norm_eq {
                ($target: ident) => {
                    assert!($target.is_valid());
                    assert!($target.is_normalized());
                    let mut transplanted_1: RawFuzzyHashType = RawFuzzyHashType::new();
                    let mut transplanted_2: RawFuzzyHashType = RawFuzzyHashType::new();
                    transplanted_1.log_blocksize = norm_hash.log_blocksize;
                    transplanted_1.blockhash1    = norm_hash.blockhash1;
                    transplanted_1.blockhash2    = norm_hash.blockhash2;
                    transplanted_2.log_blocksize = $target.log_blocksize;
                    transplanted_2.blockhash1    = $target.blockhash1;
                    transplanted_2.blockhash2    = $target.blockhash2;
                    assert!(transplanted_2.is_normalized());
                    assert!(transplanted_1.full_eq(&transplanted_2));
                };
            }
            test_norm_eq!(norm_ref_hash);
            test_norm_eq!(norm_from_raw_hash);
            test_norm_eq!(norm_from_raw_hash_2);
            test_norm_eq!(norm_from_raw_inplace_hash);
            test_norm_eq!(norm_raw_hash);
            test_norm_eq!(norm_norm_hash);
            assert_eq!(norm_hash, norm_from_raw_hash);
            assert_eq!(norm_hash, norm_from_raw_hash_2);
            assert_eq!(norm_hash, norm_norm_hash);
            assert_eq!(norm_ref_hash, norm_from_raw_inplace_hash);
            assert_eq!(norm_ref_hash, norm_raw_hash);
        }}
        test_for_each_block_sizes!(test);
        /*
            Lossless (or mostly lossless) conversion:
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
                *   try_from (long to short)
                *   try_into_mut_short
        */
        // Test macro
        macro_rules! test_lossless_conversion {
            ($hash_target: ident, $hash_cvt: ident) => {
                assert!($hash_cvt.is_valid());
                // Check equality
                assert_eq!($hash_cvt.log_block_size(), $hash_target.log_block_size());
                assert_eq!($hash_cvt.block_hash_1(), $hash_target.block_hash_1());
                assert_eq!($hash_cvt.block_hash_2(), $hash_target.block_hash_2());
            };
        }
        if bh2.len() <= BlockHash::HALF_SIZE {
            // Truncated fuzzy hashes
            let orig_hash_s_r: RawFuzzyHash =
                RawFuzzyHash::new_from_internals(BlockSize::MIN, bh1, bh2);
            let orig_hash_s_n: FuzzyHash =
                FuzzyHash::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
            assert!(orig_hash_s_r.is_valid());
            assert!(orig_hash_s_n.is_valid());
            assert!(orig_hash_s_n.is_normalized());
            assert_eq!(orig_hash_s_r.normalize(), orig_hash_s_n);

            // True Lossless (normalized):
            // preparation
            let hash_s_n: FuzzyHash = orig_hash_s_n;
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
            let cloned_hash_s_r: RawFuzzyHash = hash_s_r.clone();
            let cloned_hash_s_n: FuzzyHash = hash_s_n.clone();
            let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
            let cloned_hash_l_n: LongFuzzyHash = hash_l_n.clone();
            test_lossless_conversion!(hash_s_n, cloned_hash_s_n);
            test_lossless_conversion!(hash_s_r, cloned_hash_s_r);
            test_lossless_conversion!(hash_l_n, cloned_hash_l_n);
            test_lossless_conversion!(hash_l_r, cloned_hash_l_r);

            // Lossless (raw form; sometimes normalized):
            // preparation
            let hash_s_r: RawFuzzyHash = orig_hash_s_r;
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
            let cloned_hash_s_r: RawFuzzyHash = hash_s_r.clone();
            let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
            test_lossless_conversion!(hash_s_r, cloned_hash_s_r);
            test_lossless_conversion!(hash_l_r, cloned_hash_l_r);

            // Lossless (short and long forms; succeeds in this case):
            let hash_s_n: FuzzyHash = FuzzyHash::try_from(hash_l_n).unwrap();
            let hash_s_r: RawFuzzyHash = RawFuzzyHash::try_from(hash_l_r).unwrap();
            test_lossless_conversion!(hash_s_n, hash_l_n);
            test_lossless_conversion!(hash_s_r, hash_l_r);
        }
        else {
            // Long fuzzy hashes
            let orig_hash_l_r: LongRawFuzzyHash =
                LongRawFuzzyHash::new_from_internals(BlockSize::MIN, bh1, bh2);
            let orig_hash_l_n: LongFuzzyHash =
                LongFuzzyHash::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);

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
            let cloned_hash_l_n: LongFuzzyHash = hash_l_n.clone();
            let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
            test_lossless_conversion!(hash_l_n, cloned_hash_l_n);
            test_lossless_conversion!(hash_l_r, cloned_hash_l_r);

            // Lossless (short and long forms; fails on raw hashes):
            // preparation
            let hash_l_r: LongRawFuzzyHash = orig_hash_l_r;
            // `try_from`
            assert_eq!(RawFuzzyHash::try_from(hash_l_r), Err(FuzzyHashOperationError::BlockHashOverflow));
            // `try_into_mut_short`
            let mut hash_s_r: RawFuzzyHash = RawFuzzyHash::new();
            assert_eq!(hash_l_r.try_into_mut_short(&mut hash_s_r), Err(FuzzyHashOperationError::BlockHashOverflow));
            // `clone`
            let cloned_hash_l_r: LongRawFuzzyHash = hash_l_r.clone();
            test_lossless_conversion!(hash_l_r, cloned_hash_l_r);

            // Lossless (short and long forms; depends on normalized hashes):
            // preparation
            let hash_l_n: LongFuzzyHash = orig_hash_l_n;
            // `try_from`
            let result_hash_s_n = FuzzyHash::try_from(hash_l_n);
            assert_eq!(result_hash_s_n.is_err(), bh2_norm.len() > BlockHash::HALF_SIZE);
            if !result_hash_s_n.is_err() {
                let hash_s_n: FuzzyHash = result_hash_s_n.unwrap();
                test_lossless_conversion!(hash_l_n, hash_s_n);
            }
            // `try_into_mut_short`
            let mut hash_s_n: FuzzyHash = FuzzyHash::new();
            let result = hash_l_n.try_into_mut_short(&mut hash_s_n);
            assert_eq!(result.is_err(), bh2_norm.len() > BlockHash::HALF_SIZE);
            if !result.is_err() {
                test_lossless_conversion!(hash_l_n, hash_s_n);
            }
        }
    });
}


#[test]
fn test_datamodel_corruption() {
    /*
        Tested methods:
        1. Validity
            *   is_valid
            *   is_valid
        2. Debug output (when invalid)
            *   fmt (Debug)
    */
    macro_rules! test {($ty: ty) => {
        macro_rules! hash_is_valid {
            ($hash: expr) => {
                assert!($hash.is_valid());
            };
        }
        macro_rules! hash_is_invalid {
            ($hash: expr) => {
                assert!(!$hash.is_valid());
                #[cfg(feature = "alloc")]
                {
                    assert!(format!("{:?}", $hash).starts_with("FuzzyHashData { ILL_FORMED: true,"));
                }
            };
        }
        let hash: $ty = <$ty>::new();
        hash_is_valid!(hash);
        // Invalid block size
        {
            let mut hash = hash;
            hash.log_blocksize = BlockSize::NUM_VALID as u8;
            hash_is_invalid!(hash);
        }
        // Corrupt block hash 1 size
        {
            let mut hash = hash;
            hash.len_blockhash1 = <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8;
            // Fill with valid pattern
            for (i, ch) in hash.blockhash1.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *ch = i as u8;
            }
            hash_is_valid!(hash); // Maximum length (inclusive)
            assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_1 + 1, u8);
            hash.len_blockhash1 = <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8 + 1;
            hash_is_invalid!(hash); // Maximum length + 1 (invalid)
        }
        // Corrupt block hash 2 size
        {
            let mut hash = hash;
            hash.len_blockhash2 = <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8;
            // Fill with valid pattern
            for (i, ch) in hash.blockhash2.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *ch = i as u8;
            }
            hash_is_valid!(hash); // Maximum length (inclusive)
            assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_2 + 1, u8);
            hash.len_blockhash2 = <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8 + 1;
            hash_is_invalid!(hash); // Maximum length + 1 (invalid)
        }
        // Corrupt block hash 1 contents (in the block hash)
        {
            for block_hash_1_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                assert_fits_in!(block_hash_1_len, u8);
                hash.len_blockhash1 = block_hash_1_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.blockhash1[..block_hash_1_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put an invalid character in the block hash.
                for i in 0..block_hash_1_len {
                    let mut hash = hash;
                    hash.blockhash1[i] = BASE64_INVALID;
                    hash_is_invalid!(hash);
                }
            }
        }
        // Corrupt block hash 2 contents (in the block hash)
        {
            for block_hash_2_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                assert_fits_in!(block_hash_2_len, u8);
                hash.len_blockhash2 = block_hash_2_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.blockhash2[..block_hash_2_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put an invalid character in the block hash.
                for i in 0..block_hash_2_len {
                    let mut hash = hash;
                    hash.blockhash2[i] = BASE64_INVALID;
                    hash_is_invalid!(hash);
                }
            }
        }
        // Corrupt block hash 1 contents (out of the block hash)
        {
            for block_hash_1_len in 1..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                assert_fits_in!(block_hash_1_len, u8);
                hash.len_blockhash1 = block_hash_1_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.blockhash1[..block_hash_1_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put a non-zero character outside the block hash.
                for i in block_hash_1_len..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                    let mut hash = hash;
                    hash.blockhash1[i] = 1;
                    hash_is_invalid!(hash);
                }
            }
        }
        // Corrupt block hash 2 contents (out of the block hash)
        {
            for block_hash_2_len in 0..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                assert_fits_in!(block_hash_2_len, u8);
                hash.len_blockhash2 = block_hash_2_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.blockhash2[..block_hash_2_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put a non-zero character outside the block hash.
                for i in block_hash_2_len..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                    let mut hash = hash;
                    hash.blockhash2[i] = 1;
                    hash_is_invalid!(hash);
                }
            }
        }
        // Break block hash 1 normalization
        if <$ty>::IS_NORMALIZED_FORM {
            assert!(BlockHash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_1); // prerequisite
            let mut hash = hash;
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE, u8);
            hash.len_blockhash1 = BlockHash::MAX_SEQUENCE_SIZE as u8;
            hash_is_valid!(hash); // block hash 1 "AAA" (max sequence size): valid
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE + 1, u8);
            hash.len_blockhash1 = BlockHash::MAX_SEQUENCE_SIZE as u8 + 1;
            hash_is_invalid!(hash); // block hash 1 "AAAA" (max sequence size + 1): invalid
        }
        // Break block hash 2 normalization
        if <$ty>::IS_NORMALIZED_FORM {
            assert!(BlockHash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_2); // prerequisite
            let mut hash = hash;
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE, u8);
            hash.len_blockhash2 = BlockHash::MAX_SEQUENCE_SIZE as u8;
            hash_is_valid!(hash); // block hash 2 "AAA" (max sequence size): valid
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE + 1, u8);
            hash.len_blockhash2 = BlockHash::MAX_SEQUENCE_SIZE as u8 + 1;
            hash_is_invalid!(hash); // block hash 2 "AAAA" (max sequence size + 1): invalid
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
    #[cfg(feature = "std")] { println!("OK"); }
}


#[test]
fn test_datamodel_norm_windows() {
    macro_rules! test {($ty: ty) => {
        // Test empty or not for all block hash sizes
        for sz1 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
            let mut bh1 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1];
            // Fill with valid pattern
            for (i, ch) in bh1[0..sz1].iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *ch = i as u8;
            }
            for sz2 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut bh2 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2];
                // Fill with valid pattern
                for (i, ch) in bh2[0..sz2].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = (BlockHash::ALPHABET_SIZE - 1 - i) as u8;
                }
                // Make a hash
                let hash = <$ty>::new_from_internals(3, &bh1[0..sz1], &bh2[0..sz2]);
                // For each block hash, windows will return nothing as long as
                // the block hash is shorter than BlockHash::MIN_LCS_FOR_COMPARISON.
                assert_eq!(
                    hash.block_hash_1_windows().next().is_none(),
                    hash.block_hash_1_len() < BlockHash::MIN_LCS_FOR_COMPARISON
                );
                assert_eq!(
                    hash.block_hash_2_windows().next().is_none(),
                    hash.block_hash_2_len() < BlockHash::MIN_LCS_FOR_COMPARISON
                );
            }
        }
        // Test some example "3:mG+XtIWRQX:7mYCCCWdq"
        assert_eq!(BlockHash::MIN_LCS_FOR_COMPARISON, 7);
        let bh1 = &[38,  6, 62, 23, 45,  8, 22, 17, 16, 23]; // length 10
        let bh2 = &[59, 38, 24,  2,  2,  2, 22, 29, 42];     // length  9
        let hash = <$ty>::new_from_internals(3, bh1, bh2);
        let mut windows_1 = hash.block_hash_1_windows();
        assert_eq!(windows_1.next().unwrap(), &bh1[0..0+7]);
        assert_eq!(windows_1.next().unwrap(), &bh1[1..1+7]);
        assert_eq!(windows_1.next().unwrap(), &bh1[2..2+7]);
        assert_eq!(windows_1.next().unwrap(), &bh1[3..3+7]);
        assert!(windows_1.next().is_none());
        let mut windows_2 = hash.block_hash_2_windows();
        assert_eq!(windows_2.next().unwrap(), &bh2[0..0+7]);
        assert_eq!(windows_2.next().unwrap(), &bh2[1..1+7]);
        assert_eq!(windows_2.next().unwrap(), &bh2[2..2+7]);
        assert!(windows_2.next().is_none());
    }}
    // Normalized variants only
    test_for_each_type!(test, [FuzzyHash, LongFuzzyHash]);
}


#[test]
fn test_datamodel_eq() {
    /*
        Tested methods:
        1. Equality
            *   eq
            *   full_eq
            *   full_eq
    */
    macro_rules! test {($ty: ty) => {
        let hash = <$ty>::new();
        assert!(hash.is_valid());
        // Write a non-zero value to "out of block hash" location.
        let mut hash_corrupted_1 = hash;
        hash_corrupted_1.blockhash1[0] = 1;
        let mut hash_corrupted_2 = hash;
        hash_corrupted_2.blockhash2[0] = 1;
        // Now those two hashes are corrupted.
        assert!(!hash_corrupted_1.is_valid());
        assert!(!hash_corrupted_2.is_valid());
        // But, default comparison results in "equal" because of ignoring
        // certain bytes.
        assert_eq!(hash, hash_corrupted_1);
        assert_eq!(hash, hash_corrupted_2);
        // Still, full_eq will return false.
        assert!(!hash.full_eq(&hash_corrupted_1));
        assert!(!hash.full_eq(&hash_corrupted_2));
        assert!(!hash_corrupted_1.full_eq(&hash));
        assert!(!hash_corrupted_2.full_eq(&hash));
        assert!(!hash_corrupted_1.full_eq(&hash_corrupted_2));
        assert!(!hash_corrupted_2.full_eq(&hash_corrupted_1));
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


macro_rules! assert_parse_ng {
    ($ctor: expr, $err_kind: ident, $err_origin: ident, $err_pos: expr) => {
        assert_eq!($ctor, Err(ParseError(
            ParseErrorKind::$err_kind, ParseErrorOrigin::$err_origin, $err_pos)));
    };
}

macro_rules! assert_parse_ok {
    ($ctor: expr) => {
        assert!($ctor.is_ok());
    };
}

#[test]
fn test_parse_patterns() {
    macro_rules! test {($ty: ty) => {
        // Block Size
        assert_parse_ng!(<$ty>::from_bytes(b""),     UnexpectedEndOfString, BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"::"),   BlockSizeIsEmpty,      BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"@::"),  UnexpectedCharacter,   BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"3@::"), UnexpectedCharacter,   BlockSize, 1);
        assert_parse_ng!(<$ty>::from_bytes(b"3,::"), UnexpectedCharacter,   BlockSize, 1);
        assert_parse_ng!(<$ty>::from_bytes(b"4::"),  BlockSizeIsInvalid,    BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"16::"), BlockSizeIsInvalid,    BlockSize, 0);
        assert_parse_ok!(<$ty>::from_bytes(b"3::"));
        assert_parse_ng!(<$ty>::from_bytes(b"03::"), BlockSizeStartsWithZero, BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"04::"), BlockSizeStartsWithZero, BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"4294967295::"), BlockSizeIsInvalid,  BlockSize, 0); // u32::MAX
        assert_parse_ng!(<$ty>::from_bytes(b"4294967296::"), BlockSizeIsTooLarge, BlockSize, 0); // u32::MAX + 1
        assert_parse_ng!(<$ty>::from_bytes(b"\
                1234567890123456789012345678901234567890\
                1234567890123456789012345678901234567890\
                ::"), // 80 digits long (too large), valid terminator
            BlockSizeIsTooLarge, BlockSize, 0);
        assert_parse_ng!(<$ty>::from_bytes(b"\
                1234567890123456789012345678901234567890\
                1234567890123456789012345678901234567890\
                @:"), // 80 digits long (too large), invalid terminator
            UnexpectedCharacter, BlockSize, 80);
        assert_parse_ng!(<$ty>::from_bytes(b"\
                1234567890123456789012345678901234567890\
                1234567890123456789012345678901234567890\
                "), // 80 digits long (too large), block hashes do not exist
            UnexpectedEndOfString, BlockSize, 80);
        // Block Hash 1
        assert_parse_ng!(<$ty>::from_bytes(b"3:"),    UnexpectedEndOfString, BlockHash1, 2);
        assert_parse_ng!(<$ty>::from_bytes(b"3:a"),   UnexpectedEndOfString, BlockHash1, 3);
        assert_parse_ng!(<$ty>::from_bytes(b"3:a@"),  UnexpectedCharacter,   BlockHash1, 3);
        assert_parse_ng!(<$ty>::from_bytes(b"3:ab@"), UnexpectedCharacter,   BlockHash1, 4);
        assert_parse_ng!(<$ty>::from_bytes(b"3:a,"),  UnexpectedCharacter,   BlockHash1, 3);
        assert_parse_ng!(<$ty>::from_bytes(b"3:ab,"), UnexpectedCharacter,   BlockHash1, 4);
        assert_parse_ok!(<$ty>::from_bytes(b"3\
            :0123456789012345678901234567890123456789012345678901234567890123\
            :"));
        assert_parse_ng!(<$ty>::from_bytes(b"3\
            :01234567890123456789012345678901234567890123456789012345678901234\
            :"), BlockHashIsTooLong, BlockHash1, 2 + 64);
        // Block Hash 2
        assert_parse_ng!(<$ty>::from_bytes(b"3::a@"),  UnexpectedCharacter, BlockHash2, 4);
        assert_parse_ng!(<$ty>::from_bytes(b"3::ab@"), UnexpectedCharacter, BlockHash2, 5);
        assert_parse_ng!(<$ty>::from_bytes(b"3::a:"),  UnexpectedCharacter, BlockHash2, 4);
        assert_parse_ng!(<$ty>::from_bytes(b"3::ab:"), UnexpectedCharacter, BlockHash2, 5);
        assert_parse_ok!(<$ty>::from_bytes(b"3::a"));
        assert_parse_ok!(<$ty>::from_bytes(b"3::ab"));
        assert_parse_ok!(<$ty>::from_bytes(b"3::a,"));
        assert_parse_ok!(<$ty>::from_bytes(b"3::ab,"));
        assert_parse_ok!(<$ty>::from_bytes(b"3\
            :0123456789012345678901234567890123456789012345678901234567890123\
            :01234567890123456789012345678901"));
        if <$ty>::IS_LONG_FORM {
            assert_parse_ok!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :012345678901234567890123456789012"));
            assert_parse_ok!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :0123456789012345678901234567890123456789012345678901234567890123"));
            assert_parse_ng!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :01234567890123456789012345678901234567890123456789012345678901234"),
                BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 64);
        }
        else {
            assert_parse_ng!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :012345678901234567890123456789012"),
                BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 32);
            assert_parse_ng!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :0123456789012345678901234567890123456789012345678901234567890123"),
                BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 32);
            assert_parse_ng!(<$ty>::from_bytes(b"3\
                :0123456789012345678901234567890123456789012345678901234567890123\
                :01234567890123456789012345678901234567890123456789012345678901234"),
                BlockHashIsTooLong, BlockHash2, 2 + 64 + 1 + 32);
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}

#[test]
fn test_parse_block_hash_1_patterns() {
    let hash_noovf        = "6:0123456701234567012345670123456701234567012345670123456701234567:";
    let hash_noovf_seq1_s = "6:0003456701234567012345670123456701234567012345670123456701234567:";
    let hash_noovf_seq1_l = "6:000000003456701234567012345670123456701234567012345670123456701234567:"; // +5bytes
    let hash_noovf_seq2_s = "6:0123456701234567012345670123456700034567012345670123456701234567:";
    let hash_noovf_seq2_l = "6:012345670123456701234567012345670000000034567012345670123456701234567:"; // +5bytes
    let hash_noovf_seq3_s = "6:0123456701234567012345670123456701234567012345670123456701234777:";
    let hash_noovf_seq3_l = "6:012345670123456701234567012345670123456701234567012345670123477777777:"; // +5bytes
    // Append '0' to the first block hash to cause overflow
    let hash_ovf          = "6:01234567012345670123456701234567012345670123456701234567012345670:";
    let hash_ovf_seq_s    = "6:00034567012345670123456701234567012345670123456701234567012345670:";
    let hash_ovf_seq_l    = "6:0000000034567012345670123456701234567012345670123456701234567012345670:";
    let base_offset = 2 + 64;

    // Blockhash with maximum length
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf));
    // ... considering sequence elimination by default
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq1_s));
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq1_l));
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq2_s));
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq2_l));
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq3_s));
    assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq3_l));
    // Blockhash exceeds maximum length
    assert_parse_ng!(FuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash1, base_offset);
    // ... even after the normalization
    assert_parse_ng!(FuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ng!(FuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash1, base_offset + 5);

    // Parse as non-normalized hashes
    assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf));
    assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq1_s));
    // as sequence elimination would not occur, long blockhash immediately causes an error.
    assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq1_l), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq2_s));
    assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq2_l), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq3_s));
    assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq3_l), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash1, base_offset);
    assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash1, base_offset);
}

#[test]
fn test_parse_block_hash_2_patterns() {
    // Short variants
    {
        let hash_noovf        = "6::01234567012345670123456701234567";
        let hash_noovf_seq1_s = "6::00034567012345670123456701234567";
        let hash_noovf_seq1_l = "6::0000000034567012345670123456701234567"; // +5bytes
        let hash_noovf_seq2_s = "6::01234567012345670003456701234567";
        let hash_noovf_seq2_l = "6::0123456701234567000000003456701234567"; // +5bytes
        let hash_noovf_seq3_s = "6::01234567012345670123456701234777";
        let hash_noovf_seq3_l = "6::0123456701234567012345670123477777777"; // +5bytes
        // Append '0' to the first block hash to cause overflow
        let hash_ovf          = "6::01234567012345670123456701234567012345670123456701234567012345670";
        let hash_ovf_seq_s    = "6::00034567012345670123456701234567012345670123456701234567012345670";
        let hash_ovf_seq_l    = "6::0000000034567012345670123456701234567012345670123456701234567012345670";
        let base_offset = 2 + 32 + 1;

        // Blockhash with maximum length
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf));
        // ... considering sequence elimination by default
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq1_s));
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq1_l));
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq2_s));
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq2_l));
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq3_s));
        assert_parse_ok!(FuzzyHash::from_str(hash_noovf_seq3_l));
        // Blockhash exceeds maximum length
        assert_parse_ng!(FuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash2, base_offset);
        // ... even after the normalization
        assert_parse_ng!(FuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(FuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash2, base_offset + 5);

        // Parse as non-normalized hashes
        assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf));
        assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq1_s));
        // as sequence elimination would not occur, long blockhash immediately causes an error.
        assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq1_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq2_s));
        assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq2_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ok!(RawFuzzyHash::from_str(hash_noovf_seq3_s));
        assert_parse_ng!(RawFuzzyHash::from_str(hash_noovf_seq3_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(RawFuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash2, base_offset);
    }
    // Long variants
    {
        let hash_noovf        = "6::0123456701234567012345670123456701234567012345670123456701234567";
        let hash_noovf_seq1_s = "6::0003456701234567012345670123456701234567012345670123456701234567";
        let hash_noovf_seq1_l = "6::000000003456701234567012345670123456701234567012345670123456701234567"; // +5bytes
        let hash_noovf_seq2_s = "6::0123456701234567012345670123456700034567012345670123456701234567";
        let hash_noovf_seq2_l = "6::012345670123456701234567012345670000000034567012345670123456701234567"; // +5bytes
        let hash_noovf_seq3_s = "6::0123456701234567012345670123456701234567012345670123456701234777";
        let hash_noovf_seq3_l = "6::012345670123456701234567012345670123456701234567012345670123477777777"; // +5bytes
        // Append '0' to the first block hash to cause overflow
        let hash_ovf          = "6::01234567012345670123456701234567012345670123456701234567012345670";
        let hash_ovf_seq_s    = "6::00034567012345670123456701234567012345670123456701234567012345670";
        let hash_ovf_seq_l    = "6::0000000034567012345670123456701234567012345670123456701234567012345670";
        let base_offset = 2 + 64 + 1;

        // Blockhash with maximum length
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf));
        // ... considering sequence elimination by default
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq1_s));
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq1_l));
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq2_s));
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq2_l));
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq3_s));
        assert_parse_ok!(LongFuzzyHash::from_str(hash_noovf_seq3_l));
        // Blockhash exceeds maximum length
        assert_parse_ng!(LongFuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash2, base_offset);
        // ... even after the normalization
        assert_parse_ng!(LongFuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(LongFuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash2, base_offset + 5);

        // Parse as non-normalized hashes
        assert_parse_ok!(LongRawFuzzyHash::from_str(hash_noovf));
        assert_parse_ok!(LongRawFuzzyHash::from_str(hash_noovf_seq1_s));
        // as sequence elimination would not occur, long blockhash immediately causes an error.
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_noovf_seq1_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ok!(LongRawFuzzyHash::from_str(hash_noovf_seq2_s));
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_noovf_seq2_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ok!(LongRawFuzzyHash::from_str(hash_noovf_seq3_s));
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_noovf_seq3_l), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_ovf), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_ovf_seq_s), BlockHashIsTooLong, BlockHash2, base_offset);
        assert_parse_ng!(LongRawFuzzyHash::from_str(hash_ovf_seq_l), BlockHashIsTooLong, BlockHash2, base_offset);
    }
}


#[test]
fn test_parsed_block_size() {
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
        for (log_block_size, &str_block_size) in
            BlockSize::BLOCK_SIZES_STR.iter().enumerate()
        {
            let block_size = u32::from_str(str_block_size).unwrap();
            let str_block_size = str_block_size.as_bytes();
            // For each BlockSize::BLOCK_SIZES_STR entry "[BS]", make "[BS]::"
            // and parse as a fuzzy hash.
            let mut buf = [0u8; <$ty>::MAX_LEN_IN_STR];
            buf[..str_block_size.len()].clone_from_slice(str_block_size);
            buf[str_block_size.len()] = b':';
            buf[str_block_size.len() + 1] = b':';
            // Use from_bytes.
            let hash = <$ty>::from_bytes(&buf[..str_block_size.len() + 2]).unwrap();
            assert!(hash.is_valid());
            // Check log_block_size() and block_size()
            assert_eq!(hash.log_block_size(), log_block_size as u8);
            assert_eq!(hash.block_size(), block_size);
            // Use from_str.
            let hash = <$ty>::from_str(
                core::str::from_utf8(&buf[..str_block_size.len() + 2]).unwrap()
            ).unwrap();
            assert!(hash.is_valid());
            // Check log_block_size() and block_size()
            assert_eq!(hash.log_block_size(), log_block_size as u8);
            assert_eq!(hash.block_size(), block_size);
        }
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[test]
fn test_parsed_data_example() {
    let hash = FuzzyHash::from_str("3:ABCD:abcde").unwrap();
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



// Each block hash repeats 4 times (thus normalization causes block hash changes)
const TEST_VECTOR_SHORT_FHASH_NORM_0: &str = "6:11112222333344445555:aaaabbbbccccddddeeee";
// Each block hash repeats 3 times (normalization does not change the contents)
const TEST_VECTOR_SHORT_FHASH_NORM_1: &str = "6:111222333444555:aaabbbcccdddeee";

#[test]
fn test_from_with_str() {
    let norm0 = TEST_VECTOR_SHORT_FHASH_NORM_0;
    let norm1 = TEST_VECTOR_SHORT_FHASH_NORM_1;
    // Test normalization conversions
    {
        let hash_l_r: LongRawFuzzyHash = LongRawFuzzyHash::from_str(norm0).unwrap();
        let hash_s_r: RawFuzzyHash = RawFuzzyHash::from_str(norm0).unwrap();
        let hash_l_n: LongFuzzyHash = LongFuzzyHash::from(hash_l_r);
        let hash_s_n: FuzzyHash = FuzzyHash::from(hash_s_r);
        assert!(hash_l_r.is_valid());
        assert!(hash_s_r.is_valid());
        assert!(hash_l_n.is_valid());
        assert!(hash_s_n.is_valid());
        // Test whether comparing normalized fuzzy hashes constructed from
        // normalized or raw forms are equivalent.
        assert_eq!(hash_l_n, LongFuzzyHash::from_str(norm0).unwrap());
        assert_eq!(hash_l_n, LongFuzzyHash::from_str(norm1).unwrap());
        assert_eq!(hash_s_n, FuzzyHash::from_str(norm0).unwrap());
        assert_eq!(hash_s_n, FuzzyHash::from_str(norm1).unwrap());
    }
}

#[test]
fn test_from_bytes_with_str() {
    let norm0 = TEST_VECTOR_SHORT_FHASH_NORM_0;
    let norm1 = TEST_VECTOR_SHORT_FHASH_NORM_1;
    assert_eq!(FuzzyHash::from_bytes(norm0.as_bytes()).unwrap(), FuzzyHash::from_str(norm0).unwrap());
    assert_eq!(FuzzyHash::from_bytes(norm1.as_bytes()).unwrap(), FuzzyHash::from_str(norm1).unwrap());
    assert_eq!(RawFuzzyHash::from_bytes(norm0.as_bytes()).unwrap(), RawFuzzyHash::from_str(norm0).unwrap());
    assert_eq!(RawFuzzyHash::from_bytes(norm1.as_bytes()).unwrap(), RawFuzzyHash::from_str(norm1).unwrap());
    assert_eq!(LongFuzzyHash::from_bytes(norm0.as_bytes()).unwrap(), LongFuzzyHash::from_str(norm0).unwrap());
    assert_eq!(LongFuzzyHash::from_bytes(norm1.as_bytes()).unwrap(), LongFuzzyHash::from_str(norm1).unwrap());
    assert_eq!(LongRawFuzzyHash::from_bytes(norm0.as_bytes()).unwrap(), LongRawFuzzyHash::from_str(norm0).unwrap());
    assert_eq!(LongRawFuzzyHash::from_bytes(norm1.as_bytes()).unwrap(), LongRawFuzzyHash::from_str(norm1).unwrap());
}

#[test]
fn test_normalize_with_str() {
    let norm0 = TEST_VECTOR_SHORT_FHASH_NORM_0;
    let norm1 = TEST_VECTOR_SHORT_FHASH_NORM_1;
    // Perform normalization of normalized variants.
    // In this case, normalize would not change the result.
    assert_eq!(FuzzyHash::from_str(norm1).unwrap(), FuzzyHash::from_str(norm0).unwrap());
    assert_eq!(FuzzyHash::from_str(norm1).unwrap(), FuzzyHash::from_str(norm0).unwrap().normalize());
    assert_eq!(LongFuzzyHash::from_str(norm1).unwrap(), LongFuzzyHash::from_str(norm0).unwrap());
    assert_eq!(LongFuzzyHash::from_str(norm1).unwrap(), LongFuzzyHash::from_str(norm0).unwrap().normalize());
    // Perform normalization of raw variants.
    // In this case, normalize would change the result and its type.
    assert_eq!(FuzzyHash::from_str(norm0).unwrap(), RawFuzzyHash::from_str(norm0).unwrap().normalize());
    assert_eq!(FuzzyHash::from_str(norm1).unwrap(), RawFuzzyHash::from_str(norm0).unwrap().normalize());
    assert_eq!(LongFuzzyHash::from_str(norm0).unwrap(), LongRawFuzzyHash::from_str(norm0).unwrap().normalize());
    assert_eq!(LongFuzzyHash::from_str(norm1).unwrap(), LongRawFuzzyHash::from_str(norm0).unwrap().normalize());
}

#[cfg(feature = "alloc")]
#[test]
fn test_normalization_with_to_string() {
    let norm0 = TEST_VECTOR_SHORT_FHASH_NORM_0;
    let norm1 = TEST_VECTOR_SHORT_FHASH_NORM_1;
    // Perform stringization
    assert_eq!(FuzzyHash::from_str(norm0).unwrap().to_string(), norm1);
    assert_eq!(RawFuzzyHash::from_str(norm0).unwrap().to_string(), norm0);
    assert_eq!(LongFuzzyHash::from_str(norm0).unwrap().to_string(), norm1);
    assert_eq!(LongRawFuzzyHash::from_str(norm0).unwrap().to_string(), norm0);
    // Perform stringization with normalization (always equal to norm1)
    assert_eq!(FuzzyHash::from_str(norm0).unwrap().normalize().to_string(), norm1);
    assert_eq!(RawFuzzyHash::from_str(norm0).unwrap().normalize().to_string(), norm1);
    assert_eq!(LongFuzzyHash::from_str(norm0).unwrap().normalize().to_string(), norm1);
    assert_eq!(LongRawFuzzyHash::from_str(norm0).unwrap().normalize().to_string(), norm1);
}

#[test]
fn test_store_into_bytes_with_str() {
    let norm0 = TEST_VECTOR_SHORT_FHASH_NORM_0.as_bytes();
    let norm1 = TEST_VECTOR_SHORT_FHASH_NORM_1.as_bytes();
    macro_rules! test {
        ($ty: ty, $expected_norm0: expr) => {{
            let mut buffer = [0; LongFuzzyHash::MAX_LEN_IN_STR + 1];
            // Input size is the exact size
            buffer.fill(1);
            let h = <$ty>::from_bytes(norm1).unwrap();
            assert_eq!(h.store_into_bytes(&mut buffer[..h.len_in_str()]), Ok(()));
            assert_eq!(&buffer[..h.len_in_str()], norm1);
            for ch in &buffer[h.len_in_str()..] {
                assert_eq!(*ch, 1);
            }
            // Input size is the exact size (considering normalization)
            buffer.fill(2);
            let h = <$ty>::from_bytes(norm0).unwrap();
            assert_eq!(h.store_into_bytes(&mut buffer[..h.len_in_str()]), Ok(()));
            assert_eq!(&buffer[..h.len_in_str()], $expected_norm0);
            for ch in &buffer[h.len_in_str()..] {
                assert_eq!(*ch, 2);
            }
            // Input size is larger than required.
            buffer.fill(3);
            let h = <$ty>::from_bytes(norm1).unwrap();
            assert_eq!(h.store_into_bytes(&mut buffer), Ok(()));
            assert_eq!(&buffer[..h.len_in_str()], norm1);
            for ch in &buffer[h.len_in_str()..] {
                assert_eq!(*ch, 3);
            }
            // Input size is larger than required.
            buffer.fill(4);
            let h = <$ty>::from_bytes(norm0).unwrap();
            assert_eq!(h.store_into_bytes(&mut buffer), Ok(()));
            assert_eq!(&buffer[..h.len_in_str()], $expected_norm0);
            for ch in &buffer[h.len_in_str()..] {
                assert_eq!(*ch, 4);
            }
            // Input size is smaller than requested (buffer is unchanged).
            buffer.fill(5);
            let h = <$ty>::from_bytes(norm1).unwrap();
            assert!(h.len_in_str() > 2);
            assert_eq!(
                h.store_into_bytes(&mut buffer[..h.len_in_str() - 1]),
                Err(FuzzyHashOperationError::StringizationOverflow)
            );
            assert_eq!(buffer, [5; LongFuzzyHash::MAX_LEN_IN_STR + 1]);
            // Input size is smaller than requested (buffer is unchanged).
            buffer.fill(6);
            let h = <$ty>::from_bytes(norm0).unwrap();
            assert!(h.len_in_str() > 2);
            assert_eq!(
                h.store_into_bytes(&mut buffer[..h.len_in_str() - 1]),
                Err(FuzzyHashOperationError::StringizationOverflow)
            );
            assert_eq!(buffer, [6; LongFuzzyHash::MAX_LEN_IN_STR + 1]);
        }};
    }
    test!(FuzzyHash, norm1);
    test!(RawFuzzyHash, norm0);
    test!(LongFuzzyHash, norm1);
    test!(LongRawFuzzyHash, norm0);
}


#[cfg(feature = "std")]
#[test]
fn cover_hash() {
    macro_rules! test {($ty: ty) => {
        let mut hashes = std::collections::HashSet::<$ty>::new();
        assert!(hashes.insert(<$ty>::new()));
        assert!(!hashes.insert(<$ty>::new()));
    }}
    test_for_each_type!(test, [FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash]);
}


#[cfg(feature = "alloc")]
#[test]
fn test_ord() {
    // Sorted by block hash order (Base64 indices and length).
    // Note that 'A' has Base64 index zero and FuzzyHashData zero-fills
    // each tail of block hashes (making the behavior more deterministic).
    let sorted_dict = [
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
    for i in 0u8..=3 {
        for bs1 in sorted_dict {
            for bs2 in sorted_dict {
                let mut s = BlockSize::from_log_unchecked(i).to_string();
                s += ":";
                s += bs1;
                s += ":";
                s += bs2;
                hashes.push(FuzzyHash::from_str(s.as_str()).unwrap());
            }
        }
    }
    // Test consistency between Vec order and comparison results
    for (i1, h1) in hashes.iter().enumerate() {
        for (i2, h2) in hashes.iter().enumerate() {
            match h1.cmp(h2) {
                Ordering::Equal   => { assert!(i1 == i2); },
                Ordering::Greater => { assert!(i1 > i2); },
                Ordering::Less    => { assert!(i1 < i2); },
            }
        }
    }
    // Sorting the list makes the order the same as the original.
    let cloned = hashes.clone();
    hashes.reverse();
    hashes.sort();
    assert_eq!(hashes, cloned);
}

#[cfg(feature = "alloc")]
#[test]
fn test_ord_by_block_size() {
    let strs_unsorted = [
        "12:a:",
        "12:z:",
        "12288:a:",
        "12288:z:",
        "3:z:",
        "3:a:",
        "6144:z:",
        "6144:a:",
    ];
    let strs_sorted_all = [
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
    let strs_sorted_block_size = [
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
    let mut hashes_orig: Vec<FuzzyHash> = Vec::new();
    for s in &strs_unsorted {
        hashes_orig.push(FuzzyHash::from_str(s).unwrap());
    }
    assert!(hashes_orig.iter().all(|x| x.is_valid()));
    // Perform and check sorting by all fields
    let mut hashes = hashes_orig.clone();
    hashes.sort_by(FuzzyHash::cmp);
    for i in 0..hashes.len() {
        assert_eq!(hashes[i].to_string(), strs_sorted_all[i]);
    }
    // Perform and check sorting only by block size
    let mut hashes = hashes_orig.clone();
    hashes.sort_by(FuzzyHash::cmp_by_block_size);
    for i in 0..hashes.len() {
        assert_eq!(hashes[i].to_string(), strs_sorted_block_size[i]);
    }
}


#[cfg(feature = "alloc")]
#[test]
fn test_debug_dump() {
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
    let hash: LongFuzzyHash = LongFuzzyHash::from_str(s).unwrap();
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
    let s_a = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
    let s_b = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:H5d+X36WnL5d+X3v5d+X315d+X3+";
    let h_a = FuzzyHash::from_str(s_a).unwrap();
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    assert!(BlockSize::is_near_eq(h_a.log_block_size(), h_b.log_block_size()));
    assert_eq!(h_a.compare(h_b), 94);
    assert_eq!(h_b.compare(h_a), 94);
    // ... with only first block hash
    let s_a = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
    let s_b = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:";
    let h_a = FuzzyHash::from_str(s_a).unwrap();
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    assert_eq!(h_a.compare(h_b), 94);
    assert_eq!(h_b.compare(h_a), 94);
    // ... with only second block hash
    let s_a = "6144::Z5d+X395d+X3X5d+X315d+X3+";
    let s_b = "6144::H5d+X36WnL5d+X3v5d+X315d+X3+";
    let h_a = FuzzyHash::from_str(s_a).unwrap();
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    assert_eq!(h_a.compare(h_b), 85);
    assert_eq!(h_b.compare(h_a), 85);
}

#[test]
fn compare_fuzzy_hash_data_examples_eq_near_but_not_eq() {
    // Test examples from FuzzyHashData (block sizes near but not equal)
    let s_a = "3072:S+IiyfkMY+BES09JXAnyrZalI+YuyfkMY+BES09JXAnyrZalI+YQ:S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
    let s_b = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
    let s_c = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:1+Jr+d++H+5+e";
    let h_a = FuzzyHash::from_str(s_a).unwrap();
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    let h_c = FuzzyHash::from_str(s_c).unwrap();
    assert!(BlockSize::is_near_lt(h_a.log_block_size(), h_b.log_block_size()));
    assert!(BlockSize::is_near_lt(h_b.log_block_size(), h_c.log_block_size()));
    assert_eq!(h_a.compare(h_b), 72);
    assert_eq!(h_b.compare(h_c), 88);
    assert_eq!(h_a.compare(h_c),  0);
    assert_eq!(h_b.compare(h_a), 72);
    assert_eq!(h_c.compare(h_b), 88);
    assert_eq!(h_c.compare(h_a),  0);
    // ... with only block hashes compared (A and B)
    let s_a = "3072::S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
    let s_b = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
    let h_a = FuzzyHash::from_str(s_a).unwrap();
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    assert_eq!(h_a.compare(h_b), 72);
    assert_eq!(h_b.compare(h_a), 72);
    // ... with only block hashes compared (B and C)
    let s_b = "6144::Z5d+X395d+X3X5d+X315d+X3+";
    let s_c = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:";
    let h_b = FuzzyHash::from_str(s_b).unwrap();
    let h_c = FuzzyHash::from_str(s_c).unwrap();
    assert_eq!(h_b.compare(h_c), 88);
    assert_eq!(h_c.compare(h_b), 88);
}
