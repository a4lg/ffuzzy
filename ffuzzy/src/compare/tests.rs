// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

#[cfg(feature = "alloc")]
use alloc::format;

use crate::compare::FuzzyHashCompareTarget;
use crate::compare::position_array::{
    BlockHashPositionArray,
    BlockHashPositionArrayData,
    BlockHashPositionArrayDataMut,
    BlockHashPositionArrayImpl,
    BlockHashPositionArrayImplInternal,
};
#[cfg(feature = "unsafe")]
use crate::compare::position_array::BlockHashPositionArrayImplUnsafe;
use crate::hash::{FuzzyHash, LongFuzzyHash};
use crate::hash::block::{BlockSize, BlockSizeRelation, BlockHash};
use crate::test_utils::{assert_fits_in, test_recommended_default};


#[test]
fn test_position_array_basic() {
    test_recommended_default!(BlockHashPositionArray);
}

#[test]
fn test_position_array_usage() {
    let mut pa = BlockHashPositionArray::new();
    // Test "[BLOCKHASH]:AAABCDEFG:HIJKLMMM" (normalized)
    pa.init_from(&[0, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(pa.len(), 9);
    assert!(pa.is_valid());
    assert!(pa.is_valid_and_normalized());
    assert!(pa.has_common_substring(&[0, 0, 0, 1, 2, 3, 4]));
    assert!(pa.has_common_substring(&[0, 1, 2, 3, 4, 5, 6]));
    assert!(!pa.has_common_substring(&[1, 2, 3, 4, 5, 6, 7]));
    assert!(!pa.has_common_substring(&[0, 0, 0, 0, 1, 2, 3]));
    pa.init_from(&[7, 8, 9, 10, 11, 12, 12, 12]);
    assert_eq!(pa.len(), 8);
    assert!(pa.is_valid());
    assert!(pa.is_valid_and_normalized());
    // Test "[BLOCKHASH]:AAAABCDEFG:HIJKLMMMM" (not normalized)
    // BlockHashPositionArray itself does not do the normalization.
    pa.init_from(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(pa.len(), 10);
    assert!(pa.is_valid());
    assert!(!pa.is_valid_and_normalized());
    assert!(pa.has_common_substring(&[0, 0, 0, 0, 1, 2, 3]));
    assert!(pa.has_common_substring(&[0, 0, 0, 1, 2, 3, 4]));
    assert!(pa.has_common_substring(&[0, 1, 2, 3, 4, 5, 6]));
    assert!(!pa.has_common_substring(&[1, 2, 3, 4, 5, 6, 7]));
    pa.init_from(&[7, 8, 9, 10, 11, 12, 12, 12, 12]);
    assert_eq!(pa.len(), 9);
    assert!(pa.is_valid());
    assert!(!pa.is_valid_and_normalized());
    // Clearing the position array resets the contents to the initial value.
    pa.clear();
    assert_eq!(pa.len(), 0);
    assert_eq!(pa, BlockHashPositionArray::new());
}


#[cfg(feature = "alloc")]
#[test]
fn test_position_array_debug() {
    let mut pa = BlockHashPositionArray::new();
    assert_eq!(
        format!("{:?}", pa),
        "BlockHashPositionArray { \
            representation: [\
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            len: 0 \
        }"
    );
    // Test "[BLOCKHASH]:AAAABCDEFG:HIJKLMMMM"
    // BlockHashPositionArray itself does not do the normalization.
    pa.init_from(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        format!("{:?}", pa),
        "BlockHashPositionArray { \
            representation: [\
                15, 16, 32, 64, 128, 256, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            len: 10 \
        }"
    ); // 15 == 1 + 2 + 4 + 8
    pa.init_from(&[7, 8, 9, 10, 11, 12, 12, 12, 12]);
    assert_eq!(
        format!("{:?}", pa),
        "BlockHashPositionArray { \
            representation: [\
                0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 480, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
            ], \
            len: 9 \
        }"
    ); // 480 == 32 + 64 + 128 + 256
}


#[test]
fn test_position_array_block_hash_content() {
    // Prerequisite for inequality test:
    assert_eq!(BlockHash::ALPHABET_SIZE % 2, 0);
    // Test block hash contents
    crate::hash::test_utils::test_blockhash_content_all(&|bh, bh_norm| {
        /*
            Initialization and validness:
            *   init_from
            *   is_valid
            *   is_valid_and_normalized
            *   is_equiv
            *   is_equiv_internal
            *   is_equiv_unchecked
        */
        // Initialize with not normalized block hash.
        let mut pa = BlockHashPositionArray::new();
        pa.init_from(bh);
        assert!(pa.is_valid());
        assert!(pa.is_equiv(bh));
        assert!(pa.is_equiv_internal(bh));
        assert_eq!(pa.is_valid_and_normalized(), bh == bh_norm);
        #[cfg(feature = "unsafe")]
        unsafe {
            pa.is_equiv_unchecked(bh);
        }
        // Initialize with normalized block hash.
        pa.init_from(bh_norm);
        assert!(pa.is_valid());
        assert!(pa.is_equiv(bh_norm));
        assert!(pa.is_equiv_internal(bh_norm));
        assert!(pa.is_valid_and_normalized());
        assert_eq!(pa.is_equiv(bh), bh == bh_norm);
        assert_eq!(pa.is_equiv_internal(bh), bh == bh_norm);
        #[cfg(feature = "unsafe")]
        unsafe {
            assert!(pa.is_equiv_unchecked(bh_norm));
            assert_eq!(pa.is_equiv_unchecked(bh), bh == bh_norm);
        }
        /*
            Is empty:
            *   is_empty
        */
        assert_eq!(pa.is_empty(), bh_norm.len() == 0);
        /*
            Inequality:
            *   is_equiv
            *   is_equiv_internal
            *   is_equiv_unchecked
        */
        if bh_norm.len() != 0 {
            let mut bh_norm_mod = [0u8; BlockHash::FULL_SIZE];
            let bh_norm_mod = bh_norm_mod[0..bh_norm.len()].as_mut();
            bh_norm_mod.copy_from_slice(bh_norm);
            for i in 0..bh_norm.len() {
                bh_norm_mod[i] ^= 1; // requires that ALPHABET_SIZE is an even number.
                assert!(!pa.is_equiv(bh_norm_mod));
                assert!(!pa.is_equiv_internal(bh_norm_mod));
                #[cfg(feature = "unsafe")]
                unsafe {
                    assert!(!pa.is_equiv_unchecked(bh_norm_mod));
                }
                bh_norm_mod[i] ^= 1;
            }
        }
        /*
            Substring (with itself):
            *   has_common_substring
            *   has_common_substring_internal
            *   has_common_substring_unchecked

            Note: checking common substring with itself always results in
            the checking the length of it.
        */
        assert_eq!(
            pa.has_common_substring(bh_norm),
            bh_norm.len() >= BlockHash::MIN_LCS_FOR_COMPARISON
        );
        assert_eq!(
            pa.has_common_substring_internal(bh_norm),
            bh_norm.len() >= BlockHash::MIN_LCS_FOR_COMPARISON
        );
        #[cfg(feature = "unsafe")]
        unsafe {
            assert_eq!(
                pa.has_common_substring_unchecked(bh_norm),
                bh_norm.len() >= BlockHash::MIN_LCS_FOR_COMPARISON
            );
        }
        /*
            Edit distance (with itself):
            *   edit_distance
            *   edit_distance_internal
            *   edit_distance_unchecked

            Note: edit distance with itself should always return 0.
        */
        assert_eq!(pa.edit_distance(bh_norm), 0);
        assert_eq!(pa.edit_distance_internal(bh_norm), 0);
        #[cfg(feature = "unsafe")]
        unsafe {
            assert_eq!(pa.edit_distance_unchecked(bh_norm), 0);
        }
        /*
            Scoring (with itself):
            *   score_strings_raw
            *   score_strings_raw_internal
            *   score_strings_raw_unchecked

            Note: raw similarity score with itself should always return 100
            unless the block hash is too small (in this case, it should be 0).
        */
        let len_norm = u8::try_from(bh_norm.len()).unwrap();
        let expected_score = if bh_norm.len() >= BlockHash::MIN_LCS_FOR_COMPARISON { 100 } else { 0 };
        assert_eq!(pa.score_strings_raw(bh_norm), expected_score);
        assert_eq!(pa.score_strings_raw_internal(bh_norm), expected_score);
        assert_eq!(pa.score_strings(bh_norm, FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER), expected_score);
        #[cfg(feature = "unsafe")]
        unsafe {
            assert_eq!(pa.score_strings_raw_unchecked(bh_norm), expected_score);
        }
        let log_block_size = 0u8;
        let score_cap = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison_internal(
            log_block_size,
            len_norm,
            len_norm
        ).min(100);
        let capped_score = expected_score.min(score_cap);
        assert_eq!(pa.score_strings(bh_norm, log_block_size), capped_score);
        assert_eq!(pa.score_strings_internal(bh_norm, log_block_size), capped_score);
        #[cfg(feature = "unsafe")]
        unsafe {
            assert_eq!(pa.score_strings_unchecked(bh_norm, log_block_size), capped_score);
        }
    });
}


#[test]
fn test_position_array_corruption() {
    // Prerequisites
    assert_eq!(BlockHash::FULL_SIZE, 64);
    assert_eq!(BlockHash::ALPHABET_SIZE, 64);
    // Not Corrupted
    {
        let pa = BlockHashPositionArray::new();
        assert!(pa.is_valid());
        assert!(pa.is_valid_and_normalized());
    }
    // Block hash length (and some of its contents)
    {
        let mut pa = BlockHashPositionArray::new();
        assert_eq!(pa.len, 0);
        // Just changing the length will make this invalid
        // because there's "no character" at position 0.
        for len in 1..=u8::MAX {
            pa.len = len;
            assert!(!pa.is_valid());
            assert!(!pa.is_valid_and_normalized());
        }
        // Setting same character sequence with matching length will make this valid.
        for len in 1u8..=64 {
            let target_value = if len == 64 { u64::MAX } else { (1 << len) - 1 };
            pa.len = len;
            for i in 0..pa.representation.len() {
                pa.representation[i] = target_value;
                assert!(pa.is_valid());
                assert_eq!(pa.is_valid_and_normalized(), (len as usize) <= BlockHash::MAX_SEQUENCE_SIZE);
                pa.representation[i] = 0;
                assert!(!pa.is_valid());
                assert!(!pa.is_valid_and_normalized());
            }
        }
        pa.len = 64;
        pa.representation[0] = u64::MAX;
        assert!(pa.is_valid());
        assert!(!pa.is_valid_and_normalized());
        for len in (64 + 1)..=u8::MAX {
            pa.len = len;
            assert!(!pa.is_valid());
            assert!(!pa.is_valid_and_normalized());
        }
    }
    // Block hash contents (outside the valid hash)
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut pa = BlockHashPositionArray::new();
            for i in 0..len {
                pa.representation[i] = 1 << i;
            }
            pa.len = len as u8;
            assert!(pa.is_valid());
            assert!(pa.is_valid_and_normalized());
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..pa.representation.len() {
                    pa.representation[ch] |= bitpos;
                    assert!(!pa.is_valid());
                    assert!(!pa.is_valid_and_normalized());
                    pa.representation[ch] &= !bitpos;
                    assert!(pa.is_valid());
                    assert!(pa.is_valid_and_normalized());
                }
            }
        }
    }
    // Block hash contents (inside the valid hash)
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut pa = BlockHashPositionArray::new();
            for i in 0..len {
                pa.representation[i] = 1 << i;
            }
            pa.len = len as u8;
            assert!(pa.is_valid());
            assert!(pa.is_valid_and_normalized());
            // If the position array either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..pa.representation.len() {
                    pa.representation[ch] ^= bitpos;
                    assert!(!pa.is_valid());
                    assert!(!pa.is_valid_and_normalized());
                    pa.representation[ch] ^= bitpos;
                    assert!(pa.is_valid());
                    assert!(pa.is_valid_and_normalized());
                }
            }
        }
    }
}


#[test]
fn test_datamodel_new() {
    let hash = FuzzyHashCompareTarget::new();
    assert!(hash.is_valid());
    let short_hash = FuzzyHash::new();
    let long_hash = LongFuzzyHash::new();
    assert!(hash.is_equiv(&short_hash));
    assert!(hash.is_equiv(&long_hash));
}


#[test]
fn test_datamodel_generic() {
    let mut common_target = FuzzyHashCompareTarget::new();
    for log_block_size in 0..BlockSize::NUM_VALID {
        for len_blockhash1 in 0..=BlockHash::FULL_SIZE {
            assert_fits_in!(len_blockhash1, u8);
            let mut blockhash1 = [0u8; BlockHash::FULL_SIZE];
            for i in 0..len_blockhash1 {
                assert!(i < BlockHash::ALPHABET_SIZE);
                blockhash1[i] = i as u8;
            }
            for len_blockhash2 in 0..=BlockHash::FULL_SIZE {
                assert_fits_in!(len_blockhash2, u8);
                let mut blockhash2 = [0u8; BlockHash::FULL_SIZE];
                for i in 0..len_blockhash2 {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    blockhash2[i] = (BlockHash::ALPHABET_SIZE - 1 - i) as u8;
                }
                let log_block_size_raw = u8::try_from(log_block_size).unwrap();
                let len_blockhash1_raw = u8::try_from(len_blockhash1).unwrap();
                let len_blockhash2_raw = u8::try_from(len_blockhash2).unwrap();
                let block_size = BlockSize::from_log(log_block_size_raw).unwrap();
                macro_rules! test_all {
                    ($hash: ident) => {
                        let test_validity_and_equality = |target: &FuzzyHashCompareTarget, hash: &_| {
                            assert!(target.is_valid());
                            assert!(target.is_equiv(hash));
                            assert_eq!(target.log_block_size(), log_block_size_raw);
                            assert_eq!(target.block_size(), block_size);
                        };
                        // Initialization: from (with value)
                        let target = FuzzyHashCompareTarget::from($hash);
                        test_validity_and_equality(&target, &$hash);
                        // Initialization: from (with ref)
                        let target = FuzzyHashCompareTarget::from(&$hash);
                        test_validity_and_equality(&target, &$hash);
                        // Initialization: init_from
                        let mut target = FuzzyHashCompareTarget::new();
                        target.init_from(&$hash);
                        test_validity_and_equality(&target, &$hash);
                        // Initialization: init_from (reuse the object)
                        common_target.init_from(&$hash);
                        test_validity_and_equality(&common_target, &$hash);
                        // Change block hash 1 contents and check inequality
                        for i in 0..len_blockhash1 {
                            let mut hash = $hash;
                            hash.blockhash1[i] = if i == 2 { 0 } else { 2 };
                            assert!(!target.is_equiv(&hash));
                            assert!(!target.is_equiv_except_block_size(&hash));
                        }
                        // Change block hash 2 contents and check inequality
                        for i in 0..len_blockhash2 {
                            let mut hash = $hash;
                            hash.blockhash2[i] = if i == BlockHash::FULL_SIZE - 1 - 2 { 0 } else { 2 };
                            assert!(!target.is_equiv(&hash));
                            assert!(!target.is_equiv_except_block_size(&hash));
                        }
                        // Change block size and check inequality
                        for log_block_size_2 in 0..(BlockSize::NUM_VALID as u8) {
                            if log_block_size_raw == log_block_size_2 {
                                continue;
                            }
                            let mut hash = $hash;
                            hash.log_blocksize = log_block_size_2;
                            assert!(!target.is_equiv(&hash));
                            assert!(target.is_equiv_except_block_size(&hash));
                        }
                        // Check BlockHashPositionArrayRef
                        let mut target = FuzzyHashCompareTarget::from(&$hash);
                        assert_eq!(target.block_hash_1().is_empty(), target.block_hash_1().len() == 0);
                        assert_eq!(target.block_hash_2().is_empty(), target.block_hash_2().len() == 0);
                        assert_eq!(target.block_hash_1().len(), target.len_blockhash1);
                        assert_eq!(target.block_hash_2().len(), target.len_blockhash2);
                        assert_eq!(target.block_hash_1().representation(), &target.blockhash1);
                        assert_eq!(target.block_hash_2().representation(), &target.blockhash2);
                        assert_eq!(target.block_hash_1_internal().len(), target.len_blockhash1);
                        assert_eq!(target.block_hash_2_internal().len(), target.len_blockhash2);
                        assert_eq!(target.block_hash_1_internal().representation(), &target.blockhash1);
                        assert_eq!(target.block_hash_2_internal().representation(), &target.blockhash2);
                        // Check BlockHashPositionArrayMutRef
                        let bh1_len = target.block_hash_1_mut().len();
                        let bh2_len = target.block_hash_2_mut().len();
                        assert_eq!(bh1_len, target.len_blockhash1);
                        assert_eq!(bh2_len, target.len_blockhash2);
                        let mut bh = [0u64; BlockHash::ALPHABET_SIZE];
                        bh.copy_from_slice(target.block_hash_1_mut().representation_mut());
                        assert_eq!(bh, target.blockhash1);
                        assert_eq!(&bh, target.block_hash_1_mut().representation());
                        assert_eq!(&bh, target.block_hash_1().representation());
                        bh.copy_from_slice(target.block_hash_2_mut().representation_mut());
                        assert_eq!(bh, target.blockhash2);
                        assert_eq!(&bh, target.block_hash_2_mut().representation());
                        assert_eq!(&bh, target.block_hash_2().representation());
                    };
                }
                if len_blockhash2 <= BlockHash::HALF_SIZE {
                    let mut blockhash2_short = [0u8; BlockHash::HALF_SIZE];
                    blockhash2_short[..BlockHash::HALF_SIZE].clone_from_slice(&blockhash2[..BlockHash::HALF_SIZE]);
                    let hash = FuzzyHash::new_from_internals_raw(
                        log_block_size_raw,
                        &blockhash1,
                        &blockhash2_short,
                        len_blockhash1_raw,
                        len_blockhash2_raw
                    );
                    test_all!(hash);
                    // Comparison: with self
                    let target = FuzzyHashCompareTarget::from(&hash);
                    assert_eq!(hash.compare(&hash), 100);
                    assert_eq!(target.compare(&hash), 100);
                }
                let hash = LongFuzzyHash::new_from_internals_raw(
                    log_block_size_raw,
                    &blockhash1,
                    &blockhash2,
                    len_blockhash1_raw,
                    len_blockhash2_raw
                );
                test_all!(hash);
                // Equality: non-empty is not empty.
                if len_blockhash1 != 0 || len_blockhash2 != 0 {
                    let target = FuzzyHashCompareTarget::from(&hash);
                    assert!(!target.is_equiv(&FuzzyHash::new()));
                    assert!(!target.is_equiv(&LongFuzzyHash::new()));
                    assert!(!target.is_equiv_except_block_size(&FuzzyHash::new()));
                    assert!(!target.is_equiv_except_block_size(&LongFuzzyHash::new()));
                }
                // Comparison: with self
                {
                    let target = FuzzyHashCompareTarget::from(&hash);
                    assert_eq!(hash.compare(&hash), 100);
                    assert_eq!(target.compare(&hash), 100);
                }
                // Comparison: with only one-character different hashes (score capping)
                if len_blockhash1 != 0 || len_blockhash2 != 0 {
                    let target = FuzzyHashCompareTarget::from(&hash);
                    // Modify block hash 1 (only slightly) and test comparison
                    if hash.len_blockhash1 > 0 {
                        let mut diff_hash = hash;
                        assert_ne!(diff_hash.blockhash1[0], 2);
                        diff_hash.blockhash1[0] = 2;
                        assert_eq!(target.compare(&diff_hash), target.compare_unequal(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), target.compare_near_eq(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), target.compare_unequal_near_eq(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), hash.compare(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), hash.compare_unequal(&diff_hash));
                        let score = target.compare_unequal_near_eq(&diff_hash);
                        let score_cap_1 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw, len_blockhash1_raw, len_blockhash1_raw);
                        let score_cap_2 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw + 1, len_blockhash2_raw, len_blockhash2_raw);
                        let score_cap = u32::max(score_cap_1, score_cap_2);
                        assert!(score <= score_cap);
                        if len_blockhash1 < BlockHash::MIN_LCS_FOR_COMPARISON &&
                           len_blockhash2 < BlockHash::MIN_LCS_FOR_COMPARISON
                        {
                            // For short fuzzy hashes (when different),
                            // the score will be zero regardless of its similarity.
                            assert_eq!(score, 0);
                        }
                        else if len_blockhash2 >= BlockHash::MIN_LCS_FOR_COMPARISON &&
                                score_cap_2 >= 100
                        {
                            // If block hash 2 (we haven't touched) is long enough,
                            // its raw comparison reports a perfect match.
                            // At least, make sure that it's perfect as long as not capped.
                            assert_eq!(score, 100);
                        }
                    }
                    // Modify block hash 2 (only slightly) and test comparison
                    if hash.len_blockhash2 > 0 {
                        let mut diff_hash = hash;
                        assert_ne!(diff_hash.blockhash2[0], 0);
                        diff_hash.blockhash2[0] = 0;
                        assert_eq!(target.compare(&diff_hash), target.compare_unequal(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), target.compare_near_eq(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), target.compare_unequal_near_eq(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), hash.compare(&diff_hash));
                        assert_eq!(target.compare(&diff_hash), hash.compare_unequal(&diff_hash));
                        let score = target.compare_unequal_near_eq(&diff_hash);
                        let score_cap_1 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw, len_blockhash1_raw, len_blockhash1_raw);
                        let score_cap_2 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw + 1, len_blockhash2_raw, len_blockhash2_raw);
                        let score_cap = u32::max(score_cap_1, score_cap_2);
                        assert!(score <= score_cap);
                        if len_blockhash1 < BlockHash::MIN_LCS_FOR_COMPARISON &&
                           len_blockhash2 < BlockHash::MIN_LCS_FOR_COMPARISON
                        {
                            // For short fuzzy hashes (when different),
                            // the score will be zero regardless of its similarity.
                            assert_eq!(score, 0);
                        }
                        else if len_blockhash1 >= BlockHash::MIN_LCS_FOR_COMPARISON &&
                                score_cap_1 >= 100
                        {
                            // If block hash 1 (we haven't touched) is long enough,
                            // its raw comparison reports a perfect match.
                            // At least, make sure that it's perfect as long as not capped.
                            assert_eq!(score, 100);
                        }
                    }
                }
            }
        }
    }
}


#[test]
fn test_datamodel_corruption() {
    // Prerequisites
    assert_eq!(BlockHash::FULL_SIZE, 64);
    assert_eq!(BlockHash::ALPHABET_SIZE, 64);
    assert_eq!(BlockHash::MAX_SEQUENCE_SIZE, 3);
    // Not Corrupted
    {
        let target = FuzzyHashCompareTarget::new();
        assert!(target.is_valid());
    }
    // Block size
    {
        let mut target = FuzzyHashCompareTarget::new();
        for i in u8::MIN..=u8::MAX {
            target.log_blocksize = i;
            // Valid and invalid block sizes
            assert_eq!(target.is_valid(), i < BlockSize::NUM_VALID as u8);
        }
    }
    // Block hash 1 length (and some of its contents)
    {
        let mut target = FuzzyHashCompareTarget::new();
        assert_eq!(target.len_blockhash1, 0);
        // Just changing the length will make this invalid
        // because there's "no character" at position 0.
        target.len_blockhash1 = 1;
        assert!(!target.is_valid());
        // Setting some character on position 0 will make this valid.
        for i in 0..target.blockhash1.len() {
            target.blockhash1[i] = 1;  // Position 0 is character index i.
            assert!(target.is_valid());
            target.blockhash1[i] = 0;
            assert!(!target.is_valid());
        }
        // Fill with valid pattern (maximum length)
        for i in 0..64usize {
            assert!(i < 64);
            target.blockhash1[i] = 1 << (i as u32);
        }
        target.len_blockhash1 = 64;
        assert!(target.is_valid());
        // Once it exceeds the valid length, it's invalid.
        for i in 65u8..=u8::MAX {
            target.len_blockhash1 = i;
            assert!(!target.is_valid());
        }
    }
    // Block hash 2 length (and some of its contents)
    {
        let mut target = FuzzyHashCompareTarget::new();
        assert_eq!(target.len_blockhash2, 0);
        // Just changing the length will make this invalid
        // because there's "no character" at position 0.
        target.len_blockhash2 = 1;
        assert!(!target.is_valid());
        // Setting some character on position 0 will make this valid.
        for i in 0..target.blockhash2.len() {
            target.blockhash2[i] = 1;  // Position 0 is character index i.
            assert!(target.is_valid());
            target.blockhash2[i] = 0;
        }
        // Fill with valid pattern (maximum length)
        for i in 0..64usize {
            assert!(i < 64);
            target.blockhash2[i] = 1 << (i as u32);
        }
        target.len_blockhash2 = 64;
        assert!(target.is_valid());
        // Once it exceeds the valid length, it's invalid.
        for i in 65u8..=u8::MAX {
            target.len_blockhash2 = i;
            assert!(!target.is_valid());
        }
    }
    // Block hash 1 contents: outside the valid hash.
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut target = FuzzyHashCompareTarget::new();
            // Fill with valid contents
            for i in 0..len {
                assert!(i < 64);
                target.blockhash1[i] = 1 << (i as u32);
            }
            target.len_blockhash1 = len as u8;
            assert!(target.is_valid());
            // If we have a character past the block hash, it's invalid.
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..target.blockhash1.len() {
                    target.blockhash1[ch] |= bitpos;
                    assert!(!target.is_valid());
                    target.blockhash1[ch] &= !bitpos;
                    assert!(target.is_valid());
                }
            }
        }
    }
    // Block hash 2 contents: outside the valid hash.
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut target = FuzzyHashCompareTarget::new();
            // Fill with valid contents
            for i in 0..len {
                assert!(i < 64);
                target.blockhash2[i] = 1 << (i as u32);
            }
            target.len_blockhash2 = len as u8;
            assert!(target.is_valid());
            // If we have a character past the block hash, it's invalid.
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..target.blockhash2.len() {
                    target.blockhash2[ch] ^= bitpos;
                    assert!(!target.is_valid());
                    target.blockhash2[ch] ^= bitpos;
                    assert!(target.is_valid());
                }
            }
        }
    }
    // Block hash 1 contents: inside the valid hash.
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut target = FuzzyHashCompareTarget::new();
            // Fill with valid contents
            for i in 0..len {
                assert!(i < 64);
                target.blockhash1[i] = 1 << (i as u32);
            }
            target.len_blockhash1 = len as u8;
            assert!(target.is_valid());
            // If the target either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..target.blockhash1.len() {
                    target.blockhash1[ch] ^= bitpos;
                    assert!(!target.is_valid());
                    target.blockhash1[ch] ^= bitpos;
                    assert!(target.is_valid());
                }
            }
        }
    }
    // Block hash 2 contents: inside the valid hash.
    {
        for len in 0..=BlockHash::FULL_SIZE {
            let mut target = FuzzyHashCompareTarget::new();
            // Fill with valid contents
            for i in 0..len {
                assert!(i < 64);
                target.blockhash2[i] = 1 << (i as u32);
            }
            target.len_blockhash2 = len as u8;
            assert!(target.is_valid());
            // If the target either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..target.blockhash2.len() {
                    target.blockhash2[ch] ^= bitpos;
                    assert!(!target.is_valid());
                    target.blockhash2[ch] ^= bitpos;
                    assert!(target.is_valid());
                }
            }
        }
    }
    // Block hash 1 normalization
    {
        // Block hash "AAA" (max sequence size): valid
        let mut target = FuzzyHashCompareTarget::new();
        target.blockhash1[0] = (1u64 << (BlockHash::MAX_SEQUENCE_SIZE as u32)) - 1;
        target.len_blockhash1 = BlockHash::MAX_SEQUENCE_SIZE as u8;
        assert!(target.is_valid());
        // Block hash "AAAA" (max sequence size + 1): invalid
        target.blockhash1[0] <<= 1;
        target.blockhash1[0] |= 1;
        target.len_blockhash1 += 1;
        assert!(!target.is_valid());
    }
    // Block hash 2 normalization
    {
        // Block hash "AAA" (max sequence size): valid
        let mut target = FuzzyHashCompareTarget::new();
        target.blockhash2[0] = (1u64 << (BlockHash::MAX_SEQUENCE_SIZE as u32)) - 1;
        target.len_blockhash2 = BlockHash::MAX_SEQUENCE_SIZE as u8;
        assert!(target.is_valid());
        // Block hash "AAAA" (max sequence size + 1): invalid
        target.blockhash2[0] <<= 1;
        target.blockhash2[0] |= 1;
        target.len_blockhash2 += 1;
        assert!(!target.is_valid());
    }
}


#[test]
fn test_score_cap_on_block_hash_comparison() {
    // This test assumes that score_cap_on_blockhash_comparison function
    // actually depends on min(len1, len2).
    for log_block_size in 0..FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER {
        let mut score_cap = 0;
        for len in BlockHash::MIN_LCS_FOR_COMPARISON as u8..=BlockHash::FULL_SIZE as u8 {
            let new_score_cap =
                FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size, len, len);
            #[cfg(feature = "unsafe")]
            unsafe {
                assert_eq!(
                    new_score_cap,
                    FuzzyHashCompareTarget::score_cap_on_block_hash_comparison_unchecked(log_block_size, len, len)
                );
            }
            if len == BlockHash::MIN_LCS_FOR_COMPARISON as u8 {
                assert!(new_score_cap < 100);
            }
            else {
                assert_eq!(new_score_cap - score_cap, 1u32 << log_block_size);
            }
            score_cap = new_score_cap;
        }
    }
    for log_block_size in FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER..u8::MAX {
        for len in BlockHash::MIN_LCS_FOR_COMPARISON as u8..=BlockHash::FULL_SIZE as _ {
            assert!(FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size, len, len) >= 100);
        }
    }
}

#[test]
fn test_comparison() {
    /*
        Sample data for block hash comparisons:

        They are similar but designed to produce unique comparison score per pair.
        For all x1,x2,y1,y2,
            (x1,x2)!=(y1,y2) && (x1,x2)!=(y2,y1)
            iff
            score_uncapped(x1,x2) != score_uncapped(y1,y2).
    */
    const BLOCK_HASH_SAMPLE_DATA: [[u8; 20]; 4] = [
        [59, 12, 10, 19, 21, 28, 60, 56, 61, 42, 56, 18, 19, 16, 17, 45, 34, 50, 57, 13], // "7MKTVc849q4STQRtiy5N"
        [45, 12, 10, 19, 21, 28, 60, 56, 22, 22, 27, 56, 18, 16, 39, 14, 14, 34, 60, 57], // "tMKTVc84WWb4SQnOOi85"
        [47, 12, 10, 19, 21, 28, 60, 56, 30, 40, 26, 22, 22, 30, 29, 42, 19, 39, 34, 46], // "vMKTVc84eoaWWedqTniu"
        [24, 12, 10, 19, 21, 28, 60, 56, 14, 12, 18, 52, 37, 50, 31, 32, 47, 33, 56, 53], // "YMKTVc84OMS0lyfgvh41"
    ];
    const BLOCK_HASH_SAMPLE_SCORES: [[u32; 4]; 4] = [
        [100,  61,  50,  46],
        [ 61, 100,  57,  41],
        [ 50,  57, 100,  36],
        [ 46,  41,  36, 100],
    ];
    let mut target_s = FuzzyHashCompareTarget::new();
    let mut target_l = FuzzyHashCompareTarget::new();
    for bs1 in 0..BlockSize::NUM_VALID {
        // Hash 1: (BS1):[0]:[1]
        let log_block_size_1 = bs1 as u8;
        let block_size_1 = BlockSize::from_log(log_block_size_1).unwrap();
        let hash1_s = FuzzyHash::new_from_internals(
            block_size_1,
            &BLOCK_HASH_SAMPLE_DATA[0][..],
            &BLOCK_HASH_SAMPLE_DATA[1][..]
        );
        let hash1_l = hash1_s.to_long_form();
        target_s.init_from(&hash1_s);
        target_l.init_from(&hash1_l);
        for bs2 in 0..BlockSize::NUM_VALID {
            // Hash 2: (BS2):[2]:[3]
            let log_block_size_2 = bs2 as u8;
            let block_size_2 = BlockSize::from_log(log_block_size_2).unwrap();
            let hash2_s = FuzzyHash::new_from_internals(
                block_size_2,
                &BLOCK_HASH_SAMPLE_DATA[2][..],
                &BLOCK_HASH_SAMPLE_DATA[3][..]
            );
            let hash2_l = hash2_s.to_long_form();
            let score = target_s.compare(&hash2_s);
            assert_eq!(score, target_s.compare(&hash2_l));
            assert_eq!(score, target_l.compare(&hash2_s));
            assert_eq!(score, target_l.compare(&hash2_l));
            assert_eq!(score, target_s.compare_unequal(&hash2_s));
            assert_eq!(score, target_s.compare_unequal(&hash2_l));
            assert_eq!(score, target_l.compare_unequal(&hash2_s));
            assert_eq!(score, target_l.compare_unequal(&hash2_l));
            assert_eq!(score, target_s.compare_unequal_internal(&hash2_s));
            assert_eq!(score, target_s.compare_unequal_internal(&hash2_l));
            assert_eq!(score, target_l.compare_unequal_internal(&hash2_s));
            assert_eq!(score, target_l.compare_unequal_internal(&hash2_l));
            assert_eq!(score, hash1_s.compare(&hash2_s));
            assert_eq!(score, hash1_l.compare(&hash2_l));
            assert_eq!(score, hash1_s.compare_unequal(&hash2_s));
            assert_eq!(score, hash1_l.compare_unequal(&hash2_l));
            assert_eq!(score, hash1_s.compare_unequal_internal(&hash2_s));
            assert_eq!(score, hash1_l.compare_unequal_internal(&hash2_l));
            #[cfg(feature = "unsafe")]
            unsafe {
                assert_eq!(score, target_s.compare_unequal_unchecked(&hash2_s));
                assert_eq!(score, target_s.compare_unequal_unchecked(&hash2_l));
                assert_eq!(score, target_l.compare_unequal_unchecked(&hash2_s));
                assert_eq!(score, target_l.compare_unequal_unchecked(&hash2_l));
                assert_eq!(score, hash1_s.compare_unequal_unchecked(&hash2_s));
                assert_eq!(score, hash1_l.compare_unequal_unchecked(&hash2_l));
            }
            match BlockSize::compare_sizes(log_block_size_1, log_block_size_2) {
                BlockSizeRelation::Far => {
                    assert_eq!(score, 0);
                }
                BlockSizeRelation::NearEq => {
                    // Compare two block hashes (lower block size: [0] and [2], higher block size: [1] and [3])
                    // and take the maximum (considering the capping).
                    let score_cap_1 = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size_1, hash1_s.len_blockhash1, hash2_s.len_blockhash1);
                    let score_cap_2 = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size_1+1, hash1_s.len_blockhash2, hash2_s.len_blockhash2);
                    let expected_score_uncapped_1 = BLOCK_HASH_SAMPLE_SCORES[0][2];
                    let expected_score_uncapped_2 = BLOCK_HASH_SAMPLE_SCORES[1][3];
                    let expected_score_capped_1 = u32::min(expected_score_uncapped_1, score_cap_1);
                    let expected_score_capped_2 = u32::min(expected_score_uncapped_2, score_cap_2);
                    let expected_score = u32::max(expected_score_capped_1, expected_score_capped_2);
                    assert_eq!(score, expected_score);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target_s.compare_near_eq(&hash2_s));
                    assert_eq!(score, target_s.compare_near_eq(&hash2_l));
                    assert_eq!(score, target_l.compare_near_eq(&hash2_s));
                    assert_eq!(score, target_l.compare_near_eq(&hash2_l));
                    assert_eq!(score, target_s.compare_near_eq_internal(&hash2_s));
                    assert_eq!(score, target_s.compare_near_eq_internal(&hash2_l));
                    assert_eq!(score, target_l.compare_near_eq_internal(&hash2_s));
                    assert_eq!(score, target_l.compare_near_eq_internal(&hash2_l));
                    assert_eq!(score, target_s.compare_unequal_near_eq(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_eq(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_eq(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_eq(&hash2_l));
                    assert_eq!(score, target_s.compare_unequal_near_eq_internal(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_eq_internal(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_eq_internal(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_eq_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert_eq!(score, target_s.compare_near_eq_unchecked(&hash2_s));
                        assert_eq!(score, target_s.compare_near_eq_unchecked(&hash2_l));
                        assert_eq!(score, target_l.compare_near_eq_unchecked(&hash2_s));
                        assert_eq!(score, target_l.compare_near_eq_unchecked(&hash2_l));
                        assert_eq!(score, target_s.compare_unequal_near_eq_unchecked(&hash2_s));
                        assert_eq!(score, target_s.compare_unequal_near_eq_unchecked(&hash2_l));
                        assert_eq!(score, target_l.compare_unequal_near_eq_unchecked(&hash2_s));
                        assert_eq!(score, target_l.compare_unequal_near_eq_unchecked(&hash2_l));
                    }
                }
                BlockSizeRelation::NearGt => {
                    // BS1 > BS2 but not too far.
                    // Compare [0] and [3] and cap the raw score.
                    let score_cap = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size_1, hash1_s.len_blockhash1, hash2_s.len_blockhash2);
                    let expected_score_uncapped = BLOCK_HASH_SAMPLE_SCORES[0][3];
                    let expected_score = u32::min(expected_score_uncapped, score_cap);
                    assert_eq!(score, expected_score);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target_s.compare_unequal_near_gt(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_gt(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_gt(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_gt(&hash2_l));
                    assert_eq!(score, target_s.compare_unequal_near_gt_internal(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_gt_internal(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_gt_internal(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_gt_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert_eq!(score, target_s.compare_unequal_near_gt_unchecked(&hash2_s));
                        assert_eq!(score, target_s.compare_unequal_near_gt_unchecked(&hash2_l));
                        assert_eq!(score, target_l.compare_unequal_near_gt_unchecked(&hash2_s));
                        assert_eq!(score, target_l.compare_unequal_near_gt_unchecked(&hash2_l));
                    }
                }
                BlockSizeRelation::NearLt => {
                    // BS1 < BS2 but not too far.
                    // Compare [1] and [2] and cap the raw score.
                    let score_cap = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size_2, hash1_s.len_blockhash2, hash2_s.len_blockhash1);
                    let expected_score_uncapped = BLOCK_HASH_SAMPLE_SCORES[1][2];
                    let expected_score = u32::min(expected_score_uncapped, score_cap);
                    assert_eq!(score, expected_score);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target_s.compare_unequal_near_lt(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_lt(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_lt(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_lt(&hash2_l));
                    assert_eq!(score, target_s.compare_unequal_near_lt_internal(&hash2_s));
                    assert_eq!(score, target_s.compare_unequal_near_lt_internal(&hash2_l));
                    assert_eq!(score, target_l.compare_unequal_near_lt_internal(&hash2_s));
                    assert_eq!(score, target_l.compare_unequal_near_lt_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert_eq!(score, target_s.compare_unequal_near_lt_unchecked(&hash2_s));
                        assert_eq!(score, target_s.compare_unequal_near_lt_unchecked(&hash2_l));
                        assert_eq!(score, target_l.compare_unequal_near_lt_unchecked(&hash2_s));
                        assert_eq!(score, target_l.compare_unequal_near_lt_unchecked(&hash2_l));
                    }
                }
            }
        }
    }
}


#[test]
fn test_default() {
    let hash = FuzzyHashCompareTarget::default();
    assert!(hash.is_valid());
    // Because we don't support direct comparison,
    // check equality with new fuzzy hashes (just like "new").
    let short_hash = FuzzyHash::new();
    let long_hash = LongFuzzyHash::new();
    assert!(hash.is_equiv(&short_hash));
    assert!(hash.is_equiv(&long_hash));
}

#[cfg(feature = "alloc")]
#[test]
fn test_debug() {
    // Test empty hash
    let mut hash = FuzzyHashCompareTarget::new();
    let expected_empty_bh = "[\
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
    ]";
    assert_eq!(
        format!("{:?}", hash),
        format!("FuzzyHashCompareTarget {{ \
                blockhash1: {}, \
                blockhash2: {}, \
                len_blockhash1: 0, \
                len_blockhash2: 0, \
                log_blocksize: 0 \
            }}",
            expected_empty_bh,
            expected_empty_bh
        )
    );
    // Test debug output of BlockHashPositionArray and its representation.
    assert_eq!(format!("{:?}", hash.blockhash1), expected_empty_bh);
    assert_eq!(format!("{:?}", hash.blockhash2), expected_empty_bh);
    // Test "3072:AAAABCDEFG:HIJKLMMMM"
    // (normalized into "3072:AAABCDEFG:HIJKLMMM")
    let s = b"3072:AAAABCDEFG:HIJKLMMMM";
    hash.init_from(&FuzzyHash::from_bytes(s).unwrap());
    let expected_bh1 = "[\
        7, 8, 16, 32, 64, 128, 256, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
    ]";
    let expected_bh2 = "[\
        0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 224, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
    ]";
    assert_eq!(
        format!("{:?}", hash),
        format!("FuzzyHashCompareTarget {{ \
                blockhash1: {}, \
                blockhash2: {}, \
                len_blockhash1: 9, \
                len_blockhash2: 8, \
                log_blocksize: 10 \
            }}",
            expected_bh1,
            expected_bh2
        )
    );
    // Test debug output of BlockHashPositionArray and its representation.
    assert_eq!(format!("{:?}", hash.blockhash1), expected_bh1);
    assert_eq!(format!("{:?}", hash.blockhash2), expected_bh2);
}


#[test]
fn test_has_sequences() {
    use crate::compare::position_array::BlockHashPositionArrayElement;
    // All zero
    assert!(BlockHashPositionArrayElement::has_sequences(0, 0));
    for len in 1u32..=100 {
        assert!(!BlockHashPositionArrayElement::has_sequences(0, len));
    }
    // All one
    assert!(BlockHashPositionArrayElement::has_sequences(u64::MAX, 0));
    for len in 1u32..=64 {
        assert!(BlockHashPositionArrayElement::has_sequences(u64::MAX, len));
    }
    assert!(!BlockHashPositionArrayElement::has_sequences(u64::MAX, 65));
    // Test pattern: stripes
    const STRIPE_1: u64 = 0xaaaa_aaaa_aaaa_aaaa;
    const STRIPE_2: u64 = 0x5555_5555_5555_5555;
    for len in 0u32..=1 {
        assert!(BlockHashPositionArrayElement::has_sequences(STRIPE_1, len));
        assert!(BlockHashPositionArrayElement::has_sequences(STRIPE_2, len));
    }
    for len in 2u32..=100 {
        assert!(!BlockHashPositionArrayElement::has_sequences(STRIPE_1, len));
        assert!(!BlockHashPositionArrayElement::has_sequences(STRIPE_2, len));
    }
    // Test pattern: specific length (≧ 2) sequences
    for len in 2u32..=64 {
        let base = (1u64 << (len - 1)) - 1;
        let base = base | (base << 1);
        if len == 64 {
            assert_eq!(base.wrapping_add(1), 0);
        }
        else {
            assert!(base.wrapping_add(1).is_power_of_two());
            assert_eq!(crate::utils::u64_ilog2(base.wrapping_add(1)), len);
        }
        let mut aggr_bits: u64 = 0;
        for shift in 0..=(u64::BITS - len) {
            let seq = base << shift;
            aggr_bits |= seq;
            assert_eq!(seq >> shift, base);
            for test_len in 1u32..=100 {
                // Subpattern 1: pure bits
                let target = seq;
                assert_eq!(
                    BlockHashPositionArrayElement::has_sequences(target, test_len),
                    test_len <= len
                );
                // Subpattern 2 and 3: stripes
                for stripe in [STRIPE_1, STRIPE_2] {
                    let mut target = stripe;
                    target &= !(seq << 1);
                    target &= !(seq >> 1);
                    target |= seq;
                    if test_len < 2 {
                        // Matches to stripe itself
                        assert!(BlockHashPositionArrayElement::has_sequences(target, test_len));
                    }
                    else {
                        // Possibly matches to the sequence
                        assert_eq!(
                            BlockHashPositionArrayElement::has_sequences(target, test_len),
                            test_len <= len
                        );
                    }
                }
            }
        }
        // check whether the loop above touched all bits.
        assert_eq!(aggr_bits, u64::MAX);
        // Subpattern 4: repeated ones and one zero, repeated
        for offset in 0..=len {
            let mut has_seq = false;
            let mut target = u64::MAX;
            if offset == len {
                has_seq = true;
            }
            if offset != 64 {
                target &= !(1u64 << offset);
            }
            for pos in ((offset + len + 1)..64).step_by(usize::try_from(len + 1).unwrap()) {
                has_seq = true;
                target &= !(1u64 << pos);
            }
            if offset + len + 1 == 64 {
                has_seq = true;
            }
            assert_eq!(has_seq, BlockHashPositionArrayElement::has_sequences(target, len));
            if has_seq {
                for test_len in 0..len {
                    assert!(BlockHashPositionArrayElement::has_sequences(target, test_len));
                }
            }
            else {
                /*
                    `has_seq == false` means,
                    we have zeroed exactly one bit (at `offset`) and that caused
                    the specified length (`len`) sequence to disappear.

                    *   Bits 0..=(offset-1)  [len:    offset]: one
                    *   Bit  offset          [len:         1]: zero
                    *   Bits (offset+1)..=63 [len: 63-offset]: one
                */
                let max_seq_len = u32::max(u64::BITS - 1 - offset, offset);
                for test_len in 0..len {
                    assert_eq!(test_len <= max_seq_len, BlockHashPositionArrayElement::has_sequences(target, test_len));
                }
            }
            for test_len in (len + 1)..=100 {
                assert!(!BlockHashPositionArrayElement::has_sequences(target, test_len));
            }
        }
    }
}


#[cfg(feature = "std")]
fn has_common_substring_naive(
    str1: &[u8],
    str2: &[u8]
) -> bool
{
    use std::collections::HashSet;
    const TARGET_LEN: usize = BlockHash::MIN_LCS_FOR_COMPARISON;
    let mut set1: HashSet<&[u8]> = HashSet::new();
    let mut set2: HashSet<&[u8]> = HashSet::new();
    for window in str1.windows(TARGET_LEN) {
        set1.insert(window);
    }
    for window in str2.windows(TARGET_LEN) {
        set2.insert(window);
    }
    !set1.is_disjoint(&set2)
}

#[cfg(feature = "std")]
#[test]
fn test_has_common_substring_naive() {
    assert!(!has_common_substring_naive(b"", b""));
    assert!(!has_common_substring_naive(b"ABCDEF", b"ABCDEF"));
    // Common substring: "ABCDEFG"
    assert!(has_common_substring_naive(b"ABCDEFG", b"ABCDEFG"));
    // Common substring: "ABCDEFG"
    assert!(has_common_substring_naive(b"00000ABCDEFG", b"ABCDEFG11111"));
    // From an example of BlockHash::MIN_LCS_FOR_COMPARISON.
    assert!(has_common_substring_naive(b"+r/kcOpEYXB+0ZJ", b"7ocOpEYXB+0ZF29"));
    // Corrupt an example above (NOT to match).
    assert!(!has_common_substring_naive(b"+r/kcOpEXXB+0ZJ", b"7ocOpEYXB+0ZF29"));
}

#[cfg(all(feature = "std", feature = "tests-slow"))]
#[test]
fn verify_has_common_substring_by_real_blockhash_vectors() {
    use core::str::FromStr;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use crate::hash::LongFuzzyHash;
    let mut block_hashes: HashSet<Vec<u8>> = HashSet::new();
    for filename in [
        "data/testsuite/compare/big_cluster.uniform_blocksize.4x128.txt",
        "data/testsuite/compare/malware_all.uniform_blocksize.16x32.txt",
        "data/testsuite/compare/various.txt"
    ] {
        let index = BufReader::new(File::open(filename).unwrap());
        for hash in index.lines() {
            let hash = LongFuzzyHash::from_str(&hash.unwrap()).unwrap();
            block_hashes.insert(Vec::from(hash.block_hash_1()));
            block_hashes.insert(Vec::from(hash.block_hash_2()));
        }
    }
    let mut pa = BlockHashPositionArray::new();
    for bh1 in &block_hashes {
        for bh2 in &block_hashes {
            // Make position array (pa) from given block hash (bh1).
            pa.init_from(bh1.as_slice());
            // Test whether the results of a naïve implementation and
            // the fast implementation matches.
            let expected_value = has_common_substring_naive(bh1.as_slice(), bh2.as_slice());
            assert_eq!(
                expected_value,
                pa.has_common_substring(bh2.as_slice())
            );
        }
    }
}

#[cfg(all(feature = "std", feature = "tests-slow"))]
#[test]
fn verify_edit_distance_by_real_blockhash_vectors() {
    use core::str::FromStr;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use crate::hash::LongFuzzyHash;
    let mut block_hashes: HashSet<Vec<u8>> = HashSet::new();
    for filename in [
        "data/testsuite/compare/big_cluster.uniform_blocksize.4x128.txt",
        "data/testsuite/compare/malware_all.uniform_blocksize.16x32.txt",
        "data/testsuite/compare/various.txt"
    ] {
        let index = BufReader::new(File::open(filename).unwrap());
        for hash in index.lines() {
            let hash = LongFuzzyHash::from_str(&hash.unwrap()).unwrap();
            block_hashes.insert(Vec::from(hash.block_hash_1()));
            block_hashes.insert(Vec::from(hash.block_hash_2()));
        }
    }
    let mut pa = BlockHashPositionArray::new();
    let mut target = FuzzyHashCompareTarget::new();
    for bh1 in &block_hashes {
        for bh2 in &block_hashes {
            // Make position array (blockhash1) from given block hash (bh1).
            pa.init_from(bh1.as_slice());
            target.init_from(LongFuzzyHash::new_from_internals(BlockSize::MIN, bh1.as_slice(), &[]));
            let dist_from_dp_impl =
                crate::compare::test_utils::edit_distn(bh1.as_slice(), bh2.as_slice()) as u32;
            let dist_from_fast_impl_1 = pa.edit_distance(bh2.as_slice());
            let dist_from_fast_impl_2 = target.block_hash_1().edit_distance(bh2.as_slice());
            // Test whether the results of a port of old implementation
            // and the fast implementation matches.
            assert_eq!(dist_from_dp_impl, dist_from_fast_impl_1);
            assert_eq!(dist_from_dp_impl, dist_from_fast_impl_2);
        }
    }
}
