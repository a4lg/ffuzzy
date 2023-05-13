// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

#[cfg(feature = "alloc")]
use alloc::format;

use crate::compare::FuzzyHashCompareTarget;
use crate::compare::position_array::{
    BlockHashPositionArrayData,
    BlockHashPositionArrayDataMut,
};
use crate::hash::{FuzzyHash, LongFuzzyHash};
use crate::hash::block::{BlockSize, BlockSizeRelation, BlockHash};
use crate::test_utils::assert_fits_in;


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
fn test_compare_candidate_itself() {
    let mut target = FuzzyHashCompareTarget::new();
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
                let hash = LongFuzzyHash::new_from_internals_raw(
                    log_block_size as u8,
                    &blockhash1,
                    &blockhash2,
                    len_blockhash1 as u8,
                    len_blockhash2 as u8
                );
                target.init_from(&hash);
                // If `target` and `hash` are equivalent, current expected value is
                // whether either of block hashes have enough length.
                let expected_value =
                    len_blockhash1 >= BlockHash::MIN_LCS_FOR_COMPARISON ||
                    len_blockhash2 >= BlockHash::MIN_LCS_FOR_COMPARISON;
                assert_eq!(expected_value, target.is_comparison_candidate(&hash));
                assert_eq!(expected_value, target.is_comparison_candidate_near_eq(&hash));
                assert_eq!(expected_value, target.is_comparison_candidate_near_eq_internal(&hash));
                #[cfg(feature = "unsafe")]
                unsafe {
                    assert_eq!(expected_value, target.is_comparison_candidate_near_eq_unchecked(&hash));
                }
            }
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
                    assert!(!target_s.is_comparison_candidate(&hash2_s));
                    assert!(!target_s.is_comparison_candidate(&hash2_l));
                    assert!(!target_l.is_comparison_candidate(&hash2_s));
                    assert!(!target_l.is_comparison_candidate(&hash2_l));
                }
                BlockSizeRelation::NearEq => {
                    assert!(target_s.is_comparison_candidate(&hash2_s));
                    assert!(target_s.is_comparison_candidate(&hash2_l));
                    assert!(target_l.is_comparison_candidate(&hash2_s));
                    assert!(target_l.is_comparison_candidate(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_eq(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_eq(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_eq(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_eq(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_eq_internal(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_eq_internal(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_eq_internal(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_eq_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert!(target_s.is_comparison_candidate_near_eq_unchecked(&hash2_s));
                        assert!(target_s.is_comparison_candidate_near_eq_unchecked(&hash2_l));
                        assert!(target_l.is_comparison_candidate_near_eq_unchecked(&hash2_s));
                        assert!(target_l.is_comparison_candidate_near_eq_unchecked(&hash2_l));
                    }
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
                    assert!(target_s.is_comparison_candidate(&hash2_s));
                    assert!(target_s.is_comparison_candidate(&hash2_l));
                    assert!(target_l.is_comparison_candidate(&hash2_s));
                    assert!(target_l.is_comparison_candidate(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_gt(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_gt(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_gt(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_gt(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_gt_internal(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_gt_internal(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_gt_internal(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_gt_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert!(target_s.is_comparison_candidate_near_gt_unchecked(&hash2_s));
                        assert!(target_s.is_comparison_candidate_near_gt_unchecked(&hash2_l));
                        assert!(target_l.is_comparison_candidate_near_gt_unchecked(&hash2_s));
                        assert!(target_l.is_comparison_candidate_near_gt_unchecked(&hash2_l));
                    }
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
                    assert!(target_s.is_comparison_candidate(&hash2_s));
                    assert!(target_s.is_comparison_candidate(&hash2_l));
                    assert!(target_l.is_comparison_candidate(&hash2_s));
                    assert!(target_l.is_comparison_candidate(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_lt(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_lt(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_lt(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_lt(&hash2_l));
                    assert!(target_s.is_comparison_candidate_near_lt_internal(&hash2_s));
                    assert!(target_s.is_comparison_candidate_near_lt_internal(&hash2_l));
                    assert!(target_l.is_comparison_candidate_near_lt_internal(&hash2_s));
                    assert!(target_l.is_comparison_candidate_near_lt_internal(&hash2_l));
                    #[cfg(feature = "unsafe")]
                    unsafe {
                        assert!(target_s.is_comparison_candidate_near_lt_unchecked(&hash2_s));
                        assert!(target_s.is_comparison_candidate_near_lt_unchecked(&hash2_l));
                        assert!(target_l.is_comparison_candidate_near_lt_unchecked(&hash2_s));
                        assert!(target_l.is_comparison_candidate_near_lt_unchecked(&hash2_l));
                    }
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
