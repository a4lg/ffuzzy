// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

/*
    We want to suppress the needless borrow error WITH THE FOLLOWING MESSAGE (ONLY):
        "warning: the borrowed expression implements the required traits"
    So we have to check (in the maintainance mode) whether we haven't disabled
    other clippy::needless_borrow failures.
*/
#![cfg_attr(not(feature = "maint-lints"), allow(clippy::needless_borrow))]

#[cfg(feature = "alloc")]
use alloc::format;

use crate::compare::FuzzyHashCompareTarget;
use crate::compare::position_array::{
    BlockHashPositionArrayData,
    BlockHashPositionArrayDataMut,
    BlockHashPositionArrayRef,
};
use crate::hash::{FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash};
use crate::hash::block::{block_size, block_hash, BlockSizeRelation};
use crate::hash::test_utils::{
    test_blockhash_contents_all,
    test_blockhash_contents_no_sequences
};
use crate::hash_dual::{DualFuzzyHash, LongDualFuzzyHash};
use crate::test_utils::assert_fits_in;
use crate::utils::u64_lsb_ones;


#[test]
fn common_prerequisites() {
    // Both NUM_VALID and FULL_SIZE can be represented as u8.
    assert_fits_in!(block_size::NUM_VALID, u8);
    assert_fits_in!(block_hash::FULL_SIZE, u8);
}


#[test]
fn data_model_internal_refs() {
    /*
        References to the position array implementation
        points to the corresponding member:
        *   block_hash_1
        *   block_hash_1_internal
        *   block_hash_1_mut
        *   block_hash_2
        *   block_hash_2_internal
        *   block_hash_2_mut
    */
    type BlockHashPointerType = *const [u64; block_hash::ALPHABET_SIZE];
    type LengthPointerType = *const u8;
    let mut hash = FuzzyHashCompareTarget::new();
    // Representation of the Block hash 1
    {
        let p_blockhash1_1 = &hash.blockhash1 as BlockHashPointerType;
        let p_blockhash1_2 = hash.block_hash_1().representation() as BlockHashPointerType;
        let p_blockhash1_3 = hash.block_hash_1_internal().representation() as BlockHashPointerType;
        let p_blockhash1_4 = hash.block_hash_1_mut().representation() as BlockHashPointerType;
        let p_blockhash1_5 = hash.block_hash_1_mut().representation_mut() as BlockHashPointerType;
        assert_eq!(p_blockhash1_1, p_blockhash1_2);
        assert_eq!(p_blockhash1_1, p_blockhash1_3);
        assert_eq!(p_blockhash1_1, p_blockhash1_4);
        assert_eq!(p_blockhash1_1, p_blockhash1_5);
    }
    // Length of the Block hash 1
    {
        let p_len_blockhash1_1 = &hash.len_blockhash1 as LengthPointerType;
        let p_len_blockhash1_2 = unsafe {
            let p_block_hash_1 =
                (&hash.block_hash_1() as *const _) as *const BlockHashPositionArrayRef;
            (*p_block_hash_1).1 as LengthPointerType
        };
        let p_len_blockhash1_3 = unsafe {
            let p_block_hash_1 =
                (&hash.block_hash_1_internal() as *const _) as *const BlockHashPositionArrayRef;
            (*p_block_hash_1).1 as LengthPointerType
        };
        let p_len_blockhash1_4 = hash.block_hash_1_mut().len_mut() as LengthPointerType;
        assert_eq!(p_len_blockhash1_1, p_len_blockhash1_2);
        assert_eq!(p_len_blockhash1_1, p_len_blockhash1_3);
        assert_eq!(p_len_blockhash1_1, p_len_blockhash1_4);
    }
    // Representation of the Block hash 2
    {
        let p_blockhash2_1 = &hash.blockhash2 as BlockHashPointerType;
        let p_blockhash2_2 = hash.block_hash_2().representation() as BlockHashPointerType;
        let p_blockhash2_3 = hash.block_hash_2_internal().representation() as BlockHashPointerType;
        let p_blockhash2_4 = hash.block_hash_2_mut().representation() as BlockHashPointerType;
        let p_blockhash2_5 = hash.block_hash_2_mut().representation_mut() as BlockHashPointerType;
        assert_eq!(p_blockhash2_1, p_blockhash2_2);
        assert_eq!(p_blockhash2_1, p_blockhash2_3);
        assert_eq!(p_blockhash2_1, p_blockhash2_4);
        assert_eq!(p_blockhash2_1, p_blockhash2_5);
    }
    // Length of the Block hash 2
    {
        let p_len_blockhash2_1 = &hash.len_blockhash2 as LengthPointerType;
        let p_len_blockhash2_2 = unsafe {
            let p_block_hash_2 =
                (&hash.block_hash_2() as *const _) as *const BlockHashPositionArrayRef;
            (*p_block_hash_2).1 as LengthPointerType
        };
        let p_len_blockhash2_3 = unsafe {
            let p_block_hash_2 =
                (&hash.block_hash_2_internal() as *const _) as *const BlockHashPositionArrayRef;
            (*p_block_hash_2).1 as LengthPointerType
        };
        let p_len_blockhash2_4 = hash.block_hash_2_mut().len_mut() as LengthPointerType;
        assert_eq!(p_len_blockhash2_1, p_len_blockhash2_2);
        assert_eq!(p_len_blockhash2_1, p_len_blockhash2_3);
        assert_eq!(p_len_blockhash2_1, p_len_blockhash2_4);
    }
}


#[test]
fn data_model_new() {
    let hash = {
        let hash = FuzzyHashCompareTarget::new();
        let hash_default = FuzzyHashCompareTarget::default();
        let hash_cloned = hash.clone();
        // Test Default and Clone
        assert!(hash.full_eq(&hash_default));
        assert!(hash.full_eq(&hash_cloned));
        // Test Clone::clone_from (hash2 is initialized with a non-defualt value)
        let mut hash2 =
            FuzzyHashCompareTarget::from(str::parse::<FuzzyHash>("6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW").unwrap());
        hash2.clone_from(&hash);
        assert!(hash.full_eq(&hash2));
        hash
    };
    // Check raw values
    assert_eq!(hash.log_blocksize, 0);
    assert_eq!(hash.len_blockhash1, 0);
    assert_eq!(hash.len_blockhash2, 0);
    assert_eq!(hash.blockhash1, [0; block_hash::ALPHABET_SIZE]);
    assert_eq!(hash.blockhash2, [0; block_hash::ALPHABET_SIZE]);
    // Check basic methods
    assert!(hash.is_valid());
    assert_eq!(hash.log_block_size(), 0);
    assert_eq!(hash.block_size(), block_size::MIN);
    assert!(hash.block_hash_1().is_valid());
    assert!(hash.block_hash_1().is_valid_and_normalized());
    assert!(hash.block_hash_1().is_empty());
    assert!(hash.block_hash_2().is_valid());
    assert!(hash.block_hash_1().is_valid_and_normalized());
    assert!(hash.block_hash_2().is_empty());
    // Check equivalence
    assert!(hash.is_equiv(&FuzzyHash::new()));
    assert!(hash.is_equiv(&LongFuzzyHash::new()));
}

#[test]
fn data_model_basic() {
    /*
        1. Initialization from existing (normalized) hash
            *   from
            *   init_from
        2. Direct Mapping to the Internal Data
            *   log_block_size
            *   block_size
        3. References to the position array implementation
            *   block_hash_1
            *   block_hash_1_internal
            *   block_hash_1_mut
            *   block_hash_2
            *   block_hash_2_internal
            *   block_hash_2_mut
    */
    test_blockhash_contents_all(&|bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let len_blockhash1 = bh1_norm.len();
            let len_blockhash2 = bh2_norm.len();
            let log_block_size_raw = log_block_size as u8;
            let len_blockhash1_raw = len_blockhash1 as u8;
            let len_blockhash2_raw = len_blockhash2 as u8;
            let block_size = block_size::from_log_internal(log_block_size_raw);
            // Template
            macro_rules! test_all {
                ($hash: ident, $dual_hash: ident) => {
                    let mut target = {
                        // Initialization: from (with value)
                        let target1_1 = FuzzyHashCompareTarget::from($hash);
                        // Initialization: from (with ref)
                        let target1_2 = FuzzyHashCompareTarget::from(&$hash);
                        // Initialization: init_from
                        let mut target1_3 = FuzzyHashCompareTarget::new();
                        target1_3.init_from(&$hash);
                        // Initialization (from dual): from (with value)
                        let target2_1 = FuzzyHashCompareTarget::from($dual_hash);
                        // Initialization (from dual): from (with ref)
                        let target2_2 = FuzzyHashCompareTarget::from(&$dual_hash);
                        // Initialization (from dual): init_from
                        let mut target2_3 = FuzzyHashCompareTarget::new();
                        target2_3.init_from($dual_hash);
                        // Compare equality
                        assert!(target1_1.full_eq(&target1_2),
                            "failed (1-1-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(target1_1.full_eq(&target1_3),
                            "failed (1-1-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(target1_1.full_eq(&target2_1),
                            "failed (1-2-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(target1_1.full_eq(&target2_2),
                            "failed (1-2-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(target1_1.full_eq(&target2_3),
                            "failed (1-2-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        target1_1
                    };
                    // Test validity and equivalence to the original
                    assert!(target.is_valid(),
                        "failed (1-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert!(target.is_equiv(&$hash),
                        "failed (1-4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Check raw values (except position array)
                    assert_eq!(target.log_blocksize, log_block_size_raw,
                        "failed (1-5) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.len_blockhash1, len_blockhash1_raw,
                        "failed (1-6) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.len_blockhash2, len_blockhash2_raw,
                        "failed (1-7) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Check direct correspondence to raw values and basic functions
                    assert_eq!(target.log_block_size(), log_block_size_raw,
                        "failed (1-8) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_size(), block_size,
                        "failed (1-9) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Check BlockHashPositionArrayRef
                    // (except `reference()`, which is checked by `data_model_internal_refs`)
                    assert_eq!(target.block_hash_1().is_empty(), target.block_hash_1().len() == 0,
                        "failed (2-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_2().is_empty(), target.block_hash_2().len() == 0,
                        "failed (2-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_1().len(), target.len_blockhash1,
                        "failed (2-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_2().len(), target.len_blockhash2,
                        "failed (2-4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_1_internal().is_empty(), target.block_hash_1().len() == 0,
                        "failed (2-5) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_2_internal().is_empty(), target.block_hash_2().len() == 0,
                        "failed (2-6) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_1_internal().len(), target.len_blockhash1,
                        "failed (2-7) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_2_internal().len(), target.len_blockhash2,
                        "failed (2-8) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Check BlockHashPositionArrayMutRef
                    // (except `reference{,_mut}()`, that are checked by `data_model_internal_refs`)
                    let bh1_len = target.block_hash_1_mut().len();
                    let bh2_len = target.block_hash_2_mut().len();
                    assert_eq!(target.block_hash_1_mut().is_empty(), bh1_len == 0,
                        "failed (3-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.block_hash_2_mut().is_empty(), bh2_len == 0,
                        "failed (3-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(bh1_len, target.len_blockhash1,
                        "failed (3-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(bh2_len, target.len_blockhash2,
                        "failed (3-4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                };
            }
            // Test body
            if len_blockhash2 <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                assert_eq!(hash, FuzzyHash::try_from(LongRawFuzzyHash::new_from_internals(block_size, bh1, bh2).normalize()).unwrap(),
                    "failed on log_block_size={:?} bh1={:?}, bh2={:?}", log_block_size, bh1, bh2);
                if bh2.len() <= block_hash::HALF_SIZE {
                    let dual_hash = DualFuzzyHash::from_raw_form(&RawFuzzyHash::new_from_internals(block_size, bh1, bh2));
                    test_all!(hash, dual_hash);
                }
                else {
                    let dual_hash = LongDualFuzzyHash::from_raw_form(&LongRawFuzzyHash::new_from_internals(block_size, bh1, bh2));
                    test_all!(hash, dual_hash);
                }
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                assert_eq!(hash, LongRawFuzzyHash::new_from_internals(block_size, bh1, bh2).normalize(),
                    "failed on log_block_size={:?}, bh1={:?}, bh2={:?}", log_block_size, bh1, bh2);
                let dual_hash = LongDualFuzzyHash::from_raw_form(&LongRawFuzzyHash::new_from_internals(block_size, bh1, bh2));
                test_all!(hash, dual_hash);
            }
        }
    });
}

#[test]
fn data_model_equiv() {
    /*
        Equality (with itself or the empty hash):
        *   is_equiv
        *   is_equiv_except_block_size
    */
    test_blockhash_contents_all(&|_bh1, _bh2, bh1_norm, bh2_norm| {
        let empty_hash_s = FuzzyHash::new();
        let empty_hash_l = LongFuzzyHash::new();
        for log_block_size in 0..block_size::NUM_VALID {
            let block_size = block_size::from_log_internal(log_block_size as u8);
            // Template
            macro_rules! test_all {
                ($hash: ident) => {
                    let target = FuzzyHashCompareTarget::from(&$hash);
                    // Equivalence with the empty hash.
                    let is_empty = bh1_norm.is_empty() && bh2_norm.is_empty();
                    let is_equiv_with_empty = log_block_size == 0 && is_empty;
                    assert_eq!(is_equiv_with_empty, target.is_equiv(&empty_hash_s),
                        "failed (1-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(is_equiv_with_empty, target.is_equiv(&empty_hash_l),
                        "failed (1-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(is_empty, target.is_equiv_except_block_size(&empty_hash_s),
                        "failed (1-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(is_empty, target.is_equiv_except_block_size(&empty_hash_l),
                        "failed (1-4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Equivalence with the original
                    assert!(target.is_equiv(&$hash),
                        "failed (1-5) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert!(target.is_equiv_except_block_size(&$hash),
                        "failed (1-6) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    // Inequality when block size is changed from the original.
                    // Note: `is_equiv_except_block_size()` should still return true.
                    let mut hash2 = $hash;
                    for log_block_size_2 in 0..block_size::NUM_VALID {
                        hash2.log_blocksize = log_block_size_2 as u8;
                        assert_eq!(target.is_equiv(&hash2), log_block_size == log_block_size_2,
                            "failed (2-1) on \
                                log_block_size={:?}, \
                                log_block_size_2={:?}, \
                                bh1_norm={:?}, \
                                bh2_norm={:?}",
                            log_block_size,
                            log_block_size_2,
                            bh1_norm,
                            bh2_norm
                        );
                        assert!(target.is_equiv_except_block_size(&hash2),
                            "failed (2-2) on \
                                log_block_size={:?}, \
                                log_block_size_2={:?}, \
                                bh1_norm={:?}, \
                                bh2_norm={:?}",
                            log_block_size,
                            log_block_size_2,
                            bh1_norm,
                            bh2_norm
                        );
                    }
                };
            }
            // Test body
            if bh2_norm.len() <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
        }
    });
}

#[test]
fn data_model_equiv_inequality_block_hash() {
    /*
        Equality (when block hashes are not equivalent):
        *   is_equiv
        *   is_equiv_except_block_size
    */
    test_blockhash_contents_no_sequences(|_bh1, _bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let block_size = block_size::from_log_internal(log_block_size as u8);
            // Template
            macro_rules! test_all {
                ($hash: ident) => {
                    let target = FuzzyHashCompareTarget::from(&$hash);
                    // Change block hash 1 contents and check inequality
                    for i in 0..bh1_norm.len() {
                        let mut hash = $hash;
                        hash.blockhash1[i] = if i == 2 { 0 } else { 2 };
                        assert!(!target.is_equiv(&hash),
                            "failed (1-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(!target.is_equiv_except_block_size(&hash),
                            "failed (1-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    }
                    // Change block hash 2 contents and check inequality
                    for i in 0..bh2_norm.len() {
                        let mut hash = $hash;
                        hash.blockhash2[i] = if i == block_hash::FULL_SIZE - 1 - 2 { 0 } else { 2 };
                        assert!(!target.is_equiv(&hash),
                            "failed (2-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        assert!(!target.is_equiv_except_block_size(&hash),
                            "failed (2-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    }
                };
            }
            // Test body
            if bh2_norm.len() <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
        }
    });
}

#[test]
fn data_model_inequality_slightly_different() {
    /*
        Inequality
        *   full_eq
    */
    let hash1 = FuzzyHashCompareTarget::new();
    // Block hash 1
    let mut hash2 = FuzzyHashCompareTarget::new();
    hash2.blockhash1[0] = 1; // hash1: 0
    assert!(!hash1.full_eq(&hash2));
    assert!(!hash2.full_eq(&hash1));
    // Block hash 2
    let mut hash2 = FuzzyHashCompareTarget::new();
    hash2.blockhash2[0] = 1; // hash1: 0
    assert!(!hash1.full_eq(&hash2));
    assert!(!hash2.full_eq(&hash1));
    // Block hash 1 length
    let mut hash2 = FuzzyHashCompareTarget::new();
    hash2.len_blockhash1 = 1; // hash1: 0
    assert!(!hash1.full_eq(&hash2));
    assert!(!hash2.full_eq(&hash1));
    // Block hash 2 length
    let mut hash2 = FuzzyHashCompareTarget::new();
    hash2.len_blockhash2 = 1; // hash1: 0
    assert!(!hash1.full_eq(&hash2));
    assert!(!hash2.full_eq(&hash1));
    // Block size
    let mut hash2 = FuzzyHashCompareTarget::new();
    hash2.log_blocksize = 1; // hash1: 0
    assert!(!hash1.full_eq(&hash2));
    assert!(!hash2.full_eq(&hash1));
}


#[test]
fn data_model_corruption() {
    /*
        Validity:
        *   is_valid
    */
    // Prerequisites
    assert_eq!(block_hash::FULL_SIZE, 64);
    assert_eq!(block_hash::ALPHABET_SIZE, 64);
    // Not Corrupted
    {
        let target = FuzzyHashCompareTarget::new();
        assert!(target.is_valid());
    }
    // Block size
    {
        let mut target = FuzzyHashCompareTarget::new();
        for log_block_size in u8::MIN..=u8::MAX {
            target.log_blocksize = log_block_size;
            // Valid and invalid block sizes
            assert_eq!(target.is_valid(), block_size::is_log_valid(log_block_size),
                "failed on log_block_size={:?}", log_block_size);
        }
    }
    // Block hash 1 length (and some of its contents)
    {
        let target = {
            let mut target = FuzzyHashCompareTarget::new();
            // Just changing the length will make this invalid
            // because there's "no character" at position 0.
            target.len_blockhash1 = 1;
            assert!(!target.is_valid());
            target
        };
        // Setting some character on position 0 will make this valid.
        for index in 0..target.blockhash1.len() {
            let mut target = target.clone();
            target.blockhash1[index] = 1;  // Position 0 is character index i.
            assert!(target.is_valid(), "failed on index={:?}", index);
        }
        let mut target = FuzzyHashCompareTarget::new();
        // Fill with valid pattern (maximum length)
        for (i, pa) in target.blockhash1.iter_mut().enumerate() {
            *pa = 1 << i;
        }
        target.len_blockhash1 = 64;
        assert!(target.is_valid());
        // Once it exceeds the valid length, it's invalid.
        for len in 65u8..=u8::MAX {
            target.len_blockhash1 = len;
            assert!(!target.is_valid(), "failed on len={:?}", len);
        }
    }
    // Block hash 2 length (and some of its contents)
    {
        let target = {
            let mut target = FuzzyHashCompareTarget::new();
            target.len_blockhash2 = 1;
            // Just changing the length will make this invalid
            // because there's "no character" at position 0.
            assert!(!target.is_valid());
            target
        };
        // Setting some character on position 0 will make this valid.
        for index in 0..target.blockhash2.len() {
            let mut target = target.clone();
            target.blockhash2[index] = 1;  // Position 0 is character index i.
            assert!(target.is_valid(), "failed on index={:?}", index);
        }
        let mut target = FuzzyHashCompareTarget::new();
        // Fill with valid pattern (maximum length)
        for (i, pa) in target.blockhash2.iter_mut().enumerate() {
            *pa = 1 << i;
        }
        target.len_blockhash2 = 64;
        assert!(target.is_valid());
        // Once it exceeds the valid length, it's invalid.
        for len in 65u8..=u8::MAX {
            target.len_blockhash2 = len;
            assert!(!target.is_valid(), "failed on len={:?}", len);
        }
    }
    // Block hash 1 contents: outside the valid hash.
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                // Fill with valid contents
                for i in 0..len {
                    assert!(i < 64);
                    target.blockhash1[i] = 1 << i;
                }
                target.len_blockhash1 = len as u8;
                assert!(target.is_valid(), "failed on len={:?}", len);
                target
            };
            // If we have a character past the block hash, it's invalid.
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..target.blockhash1.len() {
                    let mut target = target.clone();
                    target.blockhash1[ch] ^= bitpos;
                    assert!(!target.is_valid(),
                        "failed on len={:?}, invalid_bitpos={:?}, ch={:?}", len, invalid_pos, ch);
                }
            }
        }
    }
    // Block hash 2 contents: outside the valid hash.
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                // Fill with valid contents
                for i in 0..len {
                    target.blockhash2[i] = 1 << i;
                }
                target.len_blockhash2 = len as u8;
                assert!(target.is_valid(), "failed on len={:?}", len);
                target
            };
            // If we have a character past the block hash, it's invalid.
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..target.blockhash2.len() {
                    let mut target = target.clone();
                    target.blockhash2[ch] ^= bitpos;
                    assert!(!target.is_valid(),
                        "failed on len={:?}, invalid_bitpos={:?}, ch={:?}", len, invalid_pos, ch);
                }
            }
        }
    }
    // Block hash 1 contents: inside the valid hash.
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                // Fill with valid contents
                for i in 0..len {
                    assert!(i < 64);
                    target.blockhash1[i] = 1 << i;
                }
                target.len_blockhash1 = len as u8;
                assert!(target.is_valid(), "failed on len={:?}", len);
                target
            };
            // If the target either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..target.blockhash1.len() {
                    let mut target = target.clone();
                    target.blockhash1[ch] ^= bitpos;
                    assert!(!target.is_valid(),
                        "failed on len={:?}, invalid_bitpos={:?}, ch={:?}", len, invalid_pos, ch);
                }
            }
        }
    }
    // Block hash 2 contents: inside the valid hash.
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                // Fill with valid contents
                for i in 0..len {
                    assert!(i < 64);
                    target.blockhash2[i] = 1 << i;
                }
                target.len_blockhash2 = len as u8;
                assert!(target.is_valid(), "failed on len={:?}", len);
                target
            };
            // If the target either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..target.blockhash1.len() {
                    let mut target = target.clone();
                    target.blockhash1[ch] ^= bitpos;
                    assert!(!target.is_valid(),
                        "failed on len={:?}, invalid_bitpos={:?}, ch={:?}", len, invalid_pos, ch);
                }
            }
        }
    }
    // Block hash 1 normalization
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                target.len_blockhash1 = len as u8;
                assert_eq!(target.is_valid(), len == 0, "failed on len={:?}", len);
                target
            };
            for index in 0..target.blockhash1.len() {
                let mut target = target.clone();
                target.blockhash1[index] = u64_lsb_ones(len as u32);
                assert_eq!(target.is_valid(), len <= block_hash::MAX_SEQUENCE_SIZE,
                    "failed on len={:?}, index={:?}", len, index);
            }
        }
    }
    // Block hash 2 normalization
    {
        for len in 0..=block_hash::FULL_SIZE {
            let target = {
                let mut target = FuzzyHashCompareTarget::new();
                target.len_blockhash2 = len as u8;
                assert_eq!(target.is_valid(), len == 0, "failed on len={:?}", len);
                target
            };
            for index in 0..target.blockhash2.len() {
                let mut target = target.clone();
                target.blockhash2[index] = u64_lsb_ones(len as u32);
                assert_eq!(target.is_valid(), len <= block_hash::MAX_SEQUENCE_SIZE,
                    "failed on len={:?}, index={:?}", len, index);
            }
        }
    }
}


#[test]
fn score_caps_on_block_hash_comparison() {
    /*
        Score capping:
        *   score_cap_on_block_hash_comparison
        *   score_cap_on_block_hash_comparison_unchecked
    */
    // This test assumes that score_cap_on_blockhash_comparison function
    // actually depends on min(len1, len2).
    for log_block_size in 0..FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER {
        let mut score_cap = 0;
        for len in 1..block_hash::MIN_LCS_FOR_COMPARISON as u8 {
            // If non-zero arguments are specified, the score cap must be non-zero
            assert_ne!(
                FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size, len, len),
                0,
                "failed on log_block_size={:?}, len={:?}", log_block_size, len
            );
        }
        for len in block_hash::MIN_LCS_FOR_COMPARISON as u8..=block_hash::FULL_SIZE as u8 {
            let new_score_cap =
                FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size, len, len);
            #[cfg(feature = "unchecked")]
            unsafe {
                assert_eq!(
                    new_score_cap,
                    FuzzyHashCompareTarget::score_cap_on_block_hash_comparison_unchecked(log_block_size, len, len),
                    "failed on log_block_size={:?}, len={:?}", log_block_size, len
                );
            }
            // If valid arguments are specified, the score cap must be non-zero
            assert_ne!(new_score_cap, 0,
                "failed on log_block_size={:?}, len={:?}", log_block_size, len);
            // Check the score cap in detail
            if len == block_hash::MIN_LCS_FOR_COMPARISON as u8 {
                // Minimum score cap is less than 100 while log_block_size is
                // smaller than LOG_BLOCK_SIZE_CAPPING_BORDER.
                assert!(new_score_cap < 100,
                    "failed on log_block_size={:?}, len={:?}", log_block_size, len);
            }
            else {
                // If the length increases by one, the score cap increases by
                // 1 << log_block_size.
                assert_eq!(new_score_cap - score_cap, 1u32 << log_block_size,
                    "failed on log_block_size={:?}, len={:?}", log_block_size, len);
            }
            score_cap = new_score_cap;
        }
    }
    for log_block_size in FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER..u8::MAX {
        for len in block_hash::MIN_LCS_FOR_COMPARISON as u8..=block_hash::FULL_SIZE as _ {
            assert!(FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(log_block_size, len, len) >= 100,
                "failed on log_block_size={:?}, len={:?}", log_block_size, len);
        }
    }
}

#[test]
fn compare_self() {
    /*
        Comparison (with itself):
        *   compare
        *   compare_near_eq
        *   compare_near_eq_internal
        *   compare_near_eq_unchecked
        *   compare (FuzzyHashData)
    */
    test_blockhash_contents_all(&|_bh1, _bh2, bh1_norm, bh2_norm| {
        for log_block_size in 0..block_size::NUM_VALID {
            let block_size = block_size::from_log_internal(log_block_size as u8);
            // Template
            macro_rules! test_all {
                ($hash: ident) => {
                    let target = FuzzyHashCompareTarget::from(&$hash);
                    assert_eq!(target.compare(&$hash), 100,
                        "failed (1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.compare_near_eq(&$hash), 100,
                        "failed (2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(target.compare_near_eq_internal(&$hash), 100,
                        "failed (3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(target.compare_near_eq_unchecked(&$hash), 100,
                        "failed (4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    }
                    assert_eq!($hash.compare(&$hash), 100,
                        "failed (5) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                };
            }
            // Test body
            if bh2_norm.len() <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
        }
    });
}

#[test]
fn compare_slightly_different() {
    /*
        Comparison with score capping (same block size, slightly different):
        *   compare
        *   compare_near_eq
        *   compare_near_eq_internal
        *   compare_near_eq_unchecked
        *   compare_unequal
        *   compare_unequal_internal
        *   compare_unequal_unchecked
        *   compare_unequal_near_eq
        *   compare_unequal_near_eq_internal
        *   compare_unequal_near_eq_unchecked
        *   compare (FuzzyHashData)
        *   compare_unequal (FuzzyHashData)
        *   compare_unequal_internal (FuzzyHashData)
        *   compare_unequal_unchecked (FuzzyHashData)
        *   score_cap_on_block_hash_comparison
    */
    test_blockhash_contents_no_sequences(|_bh1, _bh2, bh1_norm, bh2_norm| {
        let len_blockhash1 = bh1_norm.len();
        let len_blockhash2 = bh2_norm.len();
        let len_blockhash1_raw = len_blockhash1 as u8;
        let len_blockhash2_raw = len_blockhash2 as u8;
        for log_block_size in 0..block_size::NUM_VALID {
            let log_block_size_raw = log_block_size as u8;
            let block_size = block_size::from_log_internal(log_block_size_raw);
            // Template
            macro_rules! test_all {
                ($hash: ident) => {
                    let target = FuzzyHashCompareTarget::from(&$hash);
                    let hash = $hash;
                    macro_rules! compare {
                        ($bhidx: literal, $score: ident, $diff_hash: ident) => {
                            assert_eq!($score, target.compare_near_eq(&$diff_hash),
                                "failed ({}-1-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, target.compare_near_eq_internal(&$diff_hash),
                                "failed ({}-1-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, hash.compare(&$diff_hash),
                                "failed ({}-1-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, target.compare_unequal(&$diff_hash),
                                "failed ({}-1-4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, target.compare_unequal_internal(&$diff_hash),
                                "failed ({}-1-5) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, target.compare_unequal_near_eq(&$diff_hash),
                                "failed ({}-1-6) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, target.compare_unequal_near_eq_internal(&$diff_hash),
                                "failed ({}-1-7) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, hash.compare_unequal(&$diff_hash),
                                "failed ({}-1-8) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            assert_eq!($score, hash.compare_unequal_internal(&$diff_hash),
                                "failed ({}-1-9) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                $bhidx, log_block_size, bh1_norm, bh2_norm);
                            #[cfg(feature = "unchecked")]
                            unsafe {
                                assert_eq!($score, target.compare_near_eq_unchecked(&$diff_hash),
                                    "failed ({}-1-10) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                    $bhidx, log_block_size, bh1_norm, bh2_norm);
                                assert_eq!($score, target.compare_unequal_unchecked(&$diff_hash),
                                    "failed ({}-1-11) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                    $bhidx, log_block_size, bh1_norm, bh2_norm);
                                assert_eq!($score, target.compare_unequal_near_eq_unchecked(&$diff_hash),
                                    "failed ({}-1-12) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                    $bhidx, log_block_size, bh1_norm, bh2_norm);
                                assert_eq!($score, hash.compare_unequal_unchecked(&$diff_hash),
                                    "failed ({}-1-13) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}",
                                    $bhidx, log_block_size, bh1_norm, bh2_norm);
                            }
                        };
                    }
                    // Modify block hash 1 (only slightly) and test comparison
                    if hash.len_blockhash1 > 0 {
                        let mut diff_hash = hash;
                        diff_hash.blockhash1[0] = 2; // Originally, this is not 2.
                        let score = target.compare(&diff_hash);
                        compare!(1, score, diff_hash);
                        let score_cap_1 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw, len_blockhash1_raw, len_blockhash1_raw);
                        let score_cap_2 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw + 1, len_blockhash2_raw, len_blockhash2_raw);
                        let score_cap = u32::max(score_cap_1, score_cap_2);
                        assert!(score <= score_cap,
                            "failed (1-2-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        if len_blockhash1 < block_hash::MIN_LCS_FOR_COMPARISON &&
                           len_blockhash2 < block_hash::MIN_LCS_FOR_COMPARISON
                        {
                            // For short fuzzy hashes (when different),
                            // the score will be zero regardless of its similarity.
                            assert_eq!(score, 0,
                                "failed (1-2-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        }
                        else if len_blockhash2 >= block_hash::MIN_LCS_FOR_COMPARISON &&
                                score_cap_2 >= 100
                        {
                            // If block hash 2 (we haven't touched) is long enough,
                            // its raw comparison reports a perfect match.
                            // At least, make sure that it's perfect as long as not capped.
                            assert_eq!(score, 100,
                                "failed (1-2-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        }
                    }
                    // Modify block hash 2 (only slightly) and test comparison
                    if hash.len_blockhash2 > 0 {
                        let mut diff_hash = hash;
                        diff_hash.blockhash2[0] = 0; // Originally, this is not zero.
                        let score = target.compare(&diff_hash);
                        compare!(2, score, diff_hash);
                        let score_cap_1 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw, len_blockhash1_raw, len_blockhash1_raw);
                        let score_cap_2 = FuzzyHashCompareTarget
                            ::score_cap_on_block_hash_comparison(log_block_size_raw + 1, len_blockhash2_raw, len_blockhash2_raw);
                        let score_cap = u32::max(score_cap_1, score_cap_2);
                        assert!(score <= score_cap,
                            "failed (2-2-1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        if len_blockhash1 < block_hash::MIN_LCS_FOR_COMPARISON &&
                           len_blockhash2 < block_hash::MIN_LCS_FOR_COMPARISON
                        {
                            // For short fuzzy hashes (when different),
                            // the score will be zero regardless of its similarity.
                            assert_eq!(score, 0,
                                "failed (2-2-2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        }
                        else if len_blockhash1 >= block_hash::MIN_LCS_FOR_COMPARISON &&
                                score_cap_1 >= 100
                        {
                            // If block hash 1 (we haven't touched) is long enough,
                            // its raw comparison reports a perfect match.
                            // At least, make sure that it's perfect as long as not capped.
                            assert_eq!(score, 100,
                                "failed (2-2-3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                        }
                    }
                };
            }
            // Test body
            if bh2_norm.len() <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
        }
    });
}

#[test]
fn comparison_with_block_size_pairs() {
    /*
        Comparison with specific block hashes (arbitrary block size pair):
        1. Comparison
            *   compare
            *   compare_unequal
            *   compare_unequal_internal
            *   compare_unequal_unchecked
            *   compare_near_eq
            *   compare_near_eq_internal
            *   compare_near_eq_unchecked
            *   compare_unequal_near_eq
            *   compare_unequal_near_eq_internal
            *   compare_unequal_near_eq_unchecked
            *   compare_unequal_near_gt
            *   compare_unequal_near_gt_internal
            *   compare_unequal_near_gt_unchecked
            *   compare_unequal_near_lt
            *   compare_unequal_near_lt_internal
            *   compare_unequal_near_lt_unchecked
        2. Comparison Candidates
            *   is_comparison_candidate
            *   is_comparison_candidate_near_eq
            *   is_comparison_candidate_near_eq_internal
            *   is_comparison_candidate_near_eq_unchecked
            *   is_comparison_candidate_near_gt
            *   is_comparison_candidate_near_gt_internal
            *   is_comparison_candidate_near_gt_unchecked
            *   is_comparison_candidate_near_lt
            *   is_comparison_candidate_near_lt_internal
            *   is_comparison_candidate_near_lt_unchecked
        3. Score Capping
            *   score_cap_on_block_hash_comparison
    */
    /*
        Sample data for block hash comparisons:
        They are similar but designed to produce unique comparison score per pair.
        For all x1,x2,y1,y2,
            (x1,x2)!=(y1,y2) && (x1,x2)!=(y2,y1)
            iff
            score_uncapped(x1,x2) != score_uncapped(y1,y2).
    */
    const BLOCK_HASH_SAMPLE_DATA: [&[u8]; 4] = [
        &[59, 12, 10, 19, 21, 28, 60, 56, 61, 42, 56, 18, 19, 16, 17, 45, 34, 50, 57, 13], // "7MKTVc849q4STQRtiy5N"
        &[45, 12, 10, 19, 21, 28, 60, 56, 22, 22, 27, 56, 18, 16, 39, 14, 14, 34, 60, 57], // "tMKTVc84WWb4SQnOOi85"
        &[47, 12, 10, 19, 21, 28, 60, 56, 30, 40, 26, 22, 22, 30, 29, 42, 19, 39, 34, 46], // "vMKTVc84eoaWWedqTniu"
        &[24, 12, 10, 19, 21, 28, 60, 56, 14, 12, 18, 52, 37, 50, 31, 32, 47, 33, 56, 53], // "YMKTVc84OMS0lyfgvh41"
    ];
    const BLOCK_HASH_SAMPLE_SCORES: [[u32; 4]; 4] = [
        [100,  61,  50,  46],
        [ 61, 100,  57,  41],
        [ 50,  57, 100,  36],
        [ 46,  41,  36, 100],
    ];
    // Make sure that BLOCK_HASH_SAMPLE_DATA elements
    // can be stored in a truncated block hash.
    for (i, &sample_data) in BLOCK_HASH_SAMPLE_DATA.iter().enumerate() {
        assert!(sample_data.len() <= block_hash::HALF_SIZE, "failed on i={:?}", i);
    }
    let mut target_s = FuzzyHashCompareTarget::new();
    let mut target_l = FuzzyHashCompareTarget::new();
    for bs1 in 0..block_size::NUM_VALID {
        // Hash 1: (BS1):[0]:[1]
        let log_block_size_1 = bs1 as u8;
        let block_size_1 = block_size::from_log(log_block_size_1).unwrap();
        let hash1_s = FuzzyHash::new_from_internals(
            block_size_1,
            BLOCK_HASH_SAMPLE_DATA[0],
            BLOCK_HASH_SAMPLE_DATA[1]
        );
        let hash1_l = hash1_s.to_long_form();
        target_s.init_from(&hash1_s);
        target_l.init_from(&hash1_l);
        assert!(target_s.full_eq(&target_l), "failed on bs1={:?}", bs1);
        let target: &FuzzyHashCompareTarget = &target_s;
        for bs2 in 0..block_size::NUM_VALID {
            // Hash 2: (BS2):[2]:[3]
            let log_block_size_2 = bs2 as u8;
            let block_size_2 = block_size::from_log(log_block_size_2).unwrap();
            let hash2_s = FuzzyHash::new_from_internals(
                block_size_2,
                BLOCK_HASH_SAMPLE_DATA[2],
                BLOCK_HASH_SAMPLE_DATA[3]
            );
            let hash2_l = hash2_s.to_long_form();
            let score = target.compare(&hash2_s);
            assert_eq!(score, target.compare(&hash2_l),                   "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, target.compare_unequal(&hash2_s),           "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, target.compare_unequal(&hash2_l),           "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, target.compare_unequal_internal(&hash2_s),  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, target.compare_unequal_internal(&hash2_l),  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_s.compare(&hash2_s),                  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_l.compare(&hash2_l),                  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_s.compare_unequal(&hash2_s),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_l.compare_unequal(&hash2_l),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_s.compare_unequal_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            assert_eq!(score, hash1_l.compare_unequal_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            #[cfg(feature = "unchecked")]
            unsafe {
                assert_eq!(score, target.compare_unequal_unchecked(&hash2_s),  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                assert_eq!(score, target.compare_unequal_unchecked(&hash2_l),  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                assert_eq!(score, hash1_s.compare_unequal_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                assert_eq!(score, hash1_l.compare_unequal_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
            }
            match block_size::compare_sizes(log_block_size_1, log_block_size_2) {
                BlockSizeRelation::Far => {
                    assert_eq!(score, 0, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(!target.is_comparison_candidate(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(!target.is_comparison_candidate(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                }
                BlockSizeRelation::NearEq => {
                    assert!(target.is_comparison_candidate(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_eq(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_eq(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_eq_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_eq_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert!(target.is_comparison_candidate_near_eq_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert!(target.is_comparison_candidate_near_eq_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                    // Compare two block hashes (lower block size: [0] and [2], higher block size: [1] and [3])
                    // and take the maximum (considering the capping).
                    let score_cap_1 =
                        FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(
                            log_block_size_1,
                            hash1_s.len_blockhash1,
                            hash2_s.len_blockhash1
                        );
                    let score_cap_2 =
                        FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(
                            log_block_size_1 + 1,
                            hash1_s.len_blockhash2,
                            hash2_s.len_blockhash2
                        );
                    let expected_score_uncapped_1 = BLOCK_HASH_SAMPLE_SCORES[0][2];
                    let expected_score_uncapped_2 = BLOCK_HASH_SAMPLE_SCORES[1][3];
                    let expected_score_capped_1 = u32::min(expected_score_uncapped_1, score_cap_1);
                    let expected_score_capped_2 = u32::min(expected_score_uncapped_2, score_cap_2);
                    let expected_score = u32::max(expected_score_capped_1, expected_score_capped_2);
                    assert_eq!(score, expected_score, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target.compare_near_eq(&hash2_s),                  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_near_eq(&hash2_l),                  "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_near_eq_internal(&hash2_s),         "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_near_eq_internal(&hash2_l),         "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_eq(&hash2_s),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_eq(&hash2_l),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_eq_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_eq_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(score, target.compare_near_eq_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert_eq!(score, target.compare_near_eq_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert_eq!(score, target.compare_unequal_near_eq_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert_eq!(score, target.compare_unequal_near_eq_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                }
                BlockSizeRelation::NearGt => {
                    assert!(target.is_comparison_candidate(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_gt(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_gt(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_gt_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_gt_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert!(target.is_comparison_candidate_near_gt_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert!(target.is_comparison_candidate_near_gt_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                    // BS1 > BS2 but not too far.
                    // Compare [0] and [3] and cap the raw score.
                    let score_cap =
                        FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(
                            log_block_size_1,
                            hash1_s.len_blockhash1,
                            hash2_s.len_blockhash2
                        );
                    let expected_score_uncapped = BLOCK_HASH_SAMPLE_SCORES[0][3];
                    let expected_score = u32::min(expected_score_uncapped, score_cap);
                    assert_eq!(score, expected_score, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target.compare_unequal_near_gt(&hash2_s),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_gt(&hash2_l),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_gt_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_gt_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(score, target.compare_unequal_near_gt_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert_eq!(score, target.compare_unequal_near_gt_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                }
                BlockSizeRelation::NearLt => {
                    assert!(target.is_comparison_candidate(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_lt(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_lt(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_lt_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert!(target.is_comparison_candidate_near_lt_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert!(target.is_comparison_candidate_near_lt_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert!(target.is_comparison_candidate_near_lt_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                    // BS1 < BS2 but not too far.
                    // Compare [1] and [2] and cap the raw score.
                    let score_cap =
                        FuzzyHashCompareTarget::score_cap_on_block_hash_comparison(
                            log_block_size_2,
                            hash1_s.len_blockhash2,
                            hash2_s.len_blockhash1
                        );
                    let expected_score_uncapped = BLOCK_HASH_SAMPLE_SCORES[1][2];
                    let expected_score = u32::min(expected_score_uncapped, score_cap);
                    assert_eq!(score, expected_score, "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    // Test other specialized comparison functions (including internal ones)
                    assert_eq!(score, target.compare_unequal_near_lt(&hash2_s),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_lt(&hash2_l),          "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_lt_internal(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    assert_eq!(score, target.compare_unequal_near_lt_internal(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(score, target.compare_unequal_near_lt_unchecked(&hash2_s), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                        assert_eq!(score, target.compare_unequal_near_lt_unchecked(&hash2_l), "failed on bs1={:?}, bs2={:?}", bs1, bs2);
                    }
                }
            }
        }
    }
}


#[test]
fn compare_candidate_self() {
    /*
        Comparison candidate (with itself):
        *   is_comparison_candidate
        *   is_comparison_candidate_near_eq
        *   is_comparison_candidate_near_eq_internal
        *   is_comparison_candidate_near_eq_unchecked
    */
    test_blockhash_contents_all(&|_bh1, _bh2, bh1_norm, bh2_norm| {
        let expected_value =
            bh1_norm.len() >= block_hash::MIN_LCS_FOR_COMPARISON ||
            bh2_norm.len() >= block_hash::MIN_LCS_FOR_COMPARISON;
        for log_block_size in 0..block_size::NUM_VALID {
            let block_size = block_size::from_log_internal(log_block_size as u8);
            // Template
            macro_rules! test_all {
                ($hash: ident) => {
                    let target = FuzzyHashCompareTarget::from(&$hash);
                    assert_eq!(expected_value, target.is_comparison_candidate(&$hash),
                        "failed (1) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(expected_value, target.is_comparison_candidate_near_eq(&$hash),
                        "failed (2) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    assert_eq!(expected_value, target.is_comparison_candidate_near_eq_internal(&$hash),
                        "failed (3) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(expected_value, target.is_comparison_candidate_near_eq_unchecked(&$hash),
                            "failed (4) on log_block_size={:?}, bh1_norm={:?}, bh2_norm={:?}", log_block_size, bh1_norm, bh2_norm);
                    }
                };
            }
            // Test body
            if bh2_norm.len() <= block_hash::HALF_SIZE {
                // Short fuzzy hash
                let hash = FuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
            // Long fuzzy hash
            {
                let hash = LongFuzzyHash::new_from_internals(block_size, bh1_norm, bh2_norm);
                test_all!(hash);
            }
        }
    });
}

#[allow(clippy::type_complexity)]
#[test]
fn compare_candidate_with_block_size_pairs() {
    /*
        Comparison Candidate with specific block hashes (arbitrary block size pair):
        *   is_comparison_candidate
        *   is_comparison_candidate_near_eq
        *   is_comparison_candidate_near_eq_internal
        *   is_comparison_candidate_near_eq_unchecked
        *   is_comparison_candidate_near_gt
        *   is_comparison_candidate_near_gt_internal
        *   is_comparison_candidate_near_gt_unchecked
        *   is_comparison_candidate_near_lt
        *   is_comparison_candidate_near_lt_internal
        *   is_comparison_candidate_near_lt_unchecked
    */
    /*
        Comparing [BS1]:[A]:[B] and [BS2]:[C]:[D]:
        (A==C)=0 (B==C)=0 (A==D)=0 (B==D)=0 ABCD
        (A==C)=0 (B==C)=0 (A==D)=0 (B==D)=1 ABCB   Eq
        (A==C)=0 (B==C)=0 (A==D)=1 (B==D)=0 ABCA      Gt
        (A==C)=0 (B==C)=0 (A==D)=1 (B==D)=1 AACA   Eq Gt
        (A==C)=0 (B==C)=1 (A==D)=0 (B==D)=0 ABBD         Lt
        (A==C)=0 (B==C)=1 (A==D)=0 (B==D)=1 ABBB   Eq    Lt
        (A==C)=0 (B==C)=1 (A==D)=1 (B==D)=0 ABBA      Gt Lt
        (A==C)=0 (B==C)=1 (A==D)=1 (B==D)=1 AAAA ! Eq Gt Lt
        (A==C)=1 (B==C)=0 (A==D)=0 (B==D)=0 ABAD   Eq
        (A==C)=1 (B==C)=0 (A==D)=0 (B==D)=1 ABAB   Eq
        (A==C)=1 (B==C)=0 (A==D)=1 (B==D)=0 ABAA   Eq Gt
        (A==C)=1 (B==C)=0 (A==D)=1 (B==D)=1 AAAA * Eq Gt Lt
        (A==C)=1 (B==C)=1 (A==D)=0 (B==D)=0 AAAD   Eq    Lt
        (A==C)=1 (B==C)=1 (A==D)=0 (B==D)=1 AAAA * Eq Gt Lt
        (A==C)=1 (B==C)=1 (A==D)=1 (B==D)=0 AAAA * Eq Gt Lt
        (A==C)=1 (B==C)=1 (A==D)=1 (B==D)=1 AAAA * Eq Gt Lt
        [!]: Has duplicates (annotated by [*])
        [*]: Is a duplicate of [!]
    */
    const BH_STR_A: &[u8] = &[1, 2, 1, 2, 1, 2, 1];
    const BH_STR_B: &[u8] = &[3, 4, 3, 4, 3, 4, 3];
    const BH_STR_C: &[u8] = &[5, 6, 5, 6, 5, 6, 5];
    const BH_STR_D: &[u8] = &[7, 8, 7, 8, 7, 8, 7];
    const BH_STRS: [&[u8]; 4] = [BH_STR_A, BH_STR_B, BH_STR_C, BH_STR_D];
    const BLOCK_HASH_PAIRS: [(&[u8], &[u8], &[u8], &[u8], bool, bool, bool); 12] = [
        // 0: Fuzzy hash 1, Block hash 1
        // 1: Fuzzy hash 1, Block hash 2
        // 2: Fuzzy hash 2, Block hash 1
        // 3: Fuzzy hash 2, Block hash 2
        // 4: Makes a comparison candidate on BlockSizeRelation::NearEq
        // 5: Makes a comparison candidate on BlockSizeRelation::NearGt
        // 6: Makes a comparison candidate on BlockSizeRelation::NearLt
        (BH_STR_A, BH_STR_B, BH_STR_C, BH_STR_D, false, false, false),
        (BH_STR_A, BH_STR_B, BH_STR_C, BH_STR_B, true,  false, false),
        (BH_STR_A, BH_STR_B, BH_STR_C, BH_STR_A, false, true,  false),
        (BH_STR_A, BH_STR_A, BH_STR_C, BH_STR_A, true,  true,  false),
        (BH_STR_A, BH_STR_B, BH_STR_B, BH_STR_D, false, false, true ),
        (BH_STR_A, BH_STR_B, BH_STR_B, BH_STR_B, true,  false, true ),
        (BH_STR_A, BH_STR_B, BH_STR_B, BH_STR_A, false, true,  true ),
        (BH_STR_A, BH_STR_A, BH_STR_A, BH_STR_A, true,  true,  true ),
        (BH_STR_A, BH_STR_B, BH_STR_A, BH_STR_D, true,  false, false),
        (BH_STR_A, BH_STR_B, BH_STR_A, BH_STR_B, true,  false, false),
        (BH_STR_A, BH_STR_B, BH_STR_A, BH_STR_A, true,  true,  false),
        (BH_STR_A, BH_STR_A, BH_STR_A, BH_STR_D, true,  false, true ),
    ];
    for (idx_1, &bh_str_1) in BH_STRS.iter().enumerate() {
        use crate::compare::position_array::{
            BlockHashPositionArray,
            BlockHashPositionArrayData,
            BlockHashPositionArrayImpl
        };
        let mut target = BlockHashPositionArray::new();
        target.init_from(bh_str_1);
        // Make sure that all block hashes are valid (and normalized).
        assert!(target.is_valid_and_normalized(), "failed on idx_1={:?}", idx_1);
        // Make sure that only comparing with itself finds a common substring.
        for (idx_2, &bh_str_2) in BH_STRS.iter().enumerate() {
            assert_eq!(idx_1 == idx_2, target.has_common_substring(bh_str_2),
                "failed on idx_1={:?}, idx_2={:?}", idx_1, idx_2);
        }
    }
    let mut target_s = FuzzyHashCompareTarget::new();
    let mut target_l = FuzzyHashCompareTarget::new();
    for (pair_idx, &(bh_1_1, bh_1_2, bh_2_1, bh_2_2, cand_eq, cand_gt, cand_lt))
        in BLOCK_HASH_PAIRS.iter().enumerate()
    {
        for bs1 in 0..block_size::NUM_VALID {
            // Hash 1: (BS1):[bh_1_1]:[bh_1_2]
            let log_block_size_1 = bs1 as u8;
            let block_size_1 = block_size::from_log(log_block_size_1).unwrap();
            let hash1_s =
                FuzzyHash::new_from_internals(block_size_1, bh_1_1, bh_1_2);
            let hash1_l = hash1_s.to_long_form();
            target_s.init_from(&hash1_s);
            target_l.init_from(&hash1_l);
            assert!(target_s.full_eq(&target_l), "failed on pair_idx={:?}, bs1={:?}", pair_idx, bs1);
            let target: &FuzzyHashCompareTarget = &target_s;
            for bs2 in 0..block_size::NUM_VALID {
                // Hash 2: (BS2):[bh_2_1]:[bh_2_2]
                let log_block_size_2 = bs2 as u8;
                let block_size_2 = block_size::from_log(log_block_size_2).unwrap();
                let hash2_s =
                    FuzzyHash::new_from_internals(block_size_2, bh_2_1, bh_2_2);
                let hash2_l = hash2_s.to_long_form();
                match block_size::compare_sizes(log_block_size_1, log_block_size_2) {
                    BlockSizeRelation::Far => {
                        assert!(!target.is_comparison_candidate(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert!(!target.is_comparison_candidate(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                    }
                    BlockSizeRelation::NearEq => {
                        assert_eq!(cand_eq, target.is_comparison_candidate(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_eq, target.is_comparison_candidate(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_eq, target.is_comparison_candidate_near_eq(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_eq, target.is_comparison_candidate_near_eq(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_eq, target.is_comparison_candidate_near_eq_internal(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_eq, target.is_comparison_candidate_near_eq_internal(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        #[cfg(feature = "unchecked")]
                        unsafe {
                            assert_eq!(cand_eq, target.is_comparison_candidate_near_eq_unchecked(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                            assert_eq!(cand_eq, target.is_comparison_candidate_near_eq_unchecked(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        }
                    }
                    BlockSizeRelation::NearGt => {
                        assert_eq!(cand_gt, target.is_comparison_candidate(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_gt, target.is_comparison_candidate(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_gt, target.is_comparison_candidate_near_gt(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_gt, target.is_comparison_candidate_near_gt(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_gt, target.is_comparison_candidate_near_gt_internal(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_gt, target.is_comparison_candidate_near_gt_internal(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        #[cfg(feature = "unchecked")]
                        unsafe {
                            assert_eq!(cand_gt, target.is_comparison_candidate_near_gt_unchecked(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                            assert_eq!(cand_gt, target.is_comparison_candidate_near_gt_unchecked(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        }
                    }
                    BlockSizeRelation::NearLt => {
                        assert_eq!(cand_lt, target.is_comparison_candidate(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_lt, target.is_comparison_candidate(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_lt, target.is_comparison_candidate_near_lt(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_lt, target.is_comparison_candidate_near_lt(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_lt, target.is_comparison_candidate_near_lt_internal(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        assert_eq!(cand_lt, target.is_comparison_candidate_near_lt_internal(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        #[cfg(feature = "unchecked")]
                        unsafe {
                            assert_eq!(cand_lt, target.is_comparison_candidate_near_lt_unchecked(&hash2_s), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                            assert_eq!(cand_lt, target.is_comparison_candidate_near_lt_unchecked(&hash2_l), "failed on pair_idx={:?}, bs1={:?}, bs2={:?}", pair_idx, bs1, bs2);
                        }
                    }
                }
            }
        }
    }
}


#[cfg(feature = "alloc")]
#[test]
fn impl_debug() {
    use super::position_array::tests::{
        EXPECTED_DEBUG_REPR_EMPTY,
        EXPECTED_DEBUG_REPR_NORMALIZED_1,
        EXPECTED_DEBUG_REPR_NORMALIZED_2,
    };
    // Test empty hash
    let mut hash = FuzzyHashCompareTarget::new();
    assert_eq!(
        format!("{:?}", hash),
        format!("FuzzyHashCompareTarget {{ \
                blockhash1: {}, \
                blockhash2: {}, \
                len_blockhash1: 0, \
                len_blockhash2: 0, \
                log_blocksize: 0 \
            }}",
            EXPECTED_DEBUG_REPR_EMPTY,
            EXPECTED_DEBUG_REPR_EMPTY
        )
    );
    // Test debug output of BlockHashPositionArray and its representation.
    assert_eq!(format!("{:?}", hash.blockhash1), EXPECTED_DEBUG_REPR_EMPTY);
    assert_eq!(format!("{:?}", hash.blockhash2), EXPECTED_DEBUG_REPR_EMPTY);
    // Test "3072:AAAABCDEFG:HIJKLMMMM"
    // (normalized into "3072:AAABCDEFG:HIJKLMMM")
    let s = b"3072:AAAABCDEFG:HIJKLMMMM";
    hash.init_from(&FuzzyHash::from_bytes(s).unwrap());
    assert_eq!(
        format!("{:?}", hash),
        format!("FuzzyHashCompareTarget {{ \
                blockhash1: {}, \
                blockhash2: {}, \
                len_blockhash1: 9, \
                len_blockhash2: 8, \
                log_blocksize: 10 \
            }}",
            EXPECTED_DEBUG_REPR_NORMALIZED_1,
            EXPECTED_DEBUG_REPR_NORMALIZED_2
        )
    );
    // Test debug output of BlockHashPositionArray and its representation.
    assert_eq!(format!("{:?}", hash.blockhash1), EXPECTED_DEBUG_REPR_NORMALIZED_1);
    assert_eq!(format!("{:?}", hash.blockhash2), EXPECTED_DEBUG_REPR_NORMALIZED_2);
}
