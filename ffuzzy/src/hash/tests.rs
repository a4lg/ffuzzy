// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::any::type_name;
use core::cmp::Ordering;
use std::collections::HashSet;
use collect_slice::CollectSlice;

use crate::base64::BASE64_INVALID;
use crate::hash::{
    FuzzyHashData,
    FuzzyHash, RawFuzzyHash, LongFuzzyHash, LongRawFuzzyHash,
    FuzzyHashOperationError
};
use crate::hash::block::{
    block_hash, block_size, BlockSizeRelation,
    BlockHashSize as BHS, BlockHashSizes as BHSs,
    ConstrainedBlockHashSize as CBHS, ConstrainedBlockHashSizes as CBHSs
};
use crate::hash::parser_state::{
    ParseError, ParseErrorKind, ParseErrorOrigin
};
use crate::hash::test_utils::test_blockhash_contents_all;
use crate::test_utils::{assert_fits_in, test_auto_clone};


macro_rules! call_for_fuzzy_hash_type {
    { $test: ident ($($tokens:tt)*) ; } => {
        $test::<{block_hash::FULL_SIZE}, {block_hash::HALF_SIZE},  true>($($tokens)*);
        $test::<{block_hash::FULL_SIZE}, {block_hash::HALF_SIZE}, false>($($tokens)*);
        $test::<{block_hash::FULL_SIZE}, {block_hash::FULL_SIZE},  true>($($tokens)*);
        $test::<{block_hash::FULL_SIZE}, {block_hash::FULL_SIZE}, false>($($tokens)*);
    }
}

macro_rules! call_for_fuzzy_hash_sizes {
    { $test: ident ($($tokens:tt)*) ; } => {
        $test::<{block_hash::FULL_SIZE}, {block_hash::HALF_SIZE}>($($tokens)*);
        $test::<{block_hash::FULL_SIZE}, {block_hash::FULL_SIZE}>($($tokens)*);
    };
}

#[test]
fn check_call_for_fuzzy_hash_type_and_sizes() {
    let mut params_type  = HashSet::new();
    let mut params_sizes = HashSet::new();
    // Mark parameters as tested (make sure that no duplication happens).
    fn test_body_for_type<const S1: usize, const S2: usize, const NORM: bool>(params: &mut HashSet<(usize, usize, bool)>) {
        assert!(params.insert((S1, S2, NORM)));
    }
    fn test_body_for_sizes<const S1: usize, const S2: usize>(params: &mut HashSet<(usize, usize)>) {
        assert!(params.insert((S1, S2)));
    }
    call_for_fuzzy_hash_type!  { test_body_for_type(&mut params_type); }
    call_for_fuzzy_hash_sizes! { test_body_for_sizes(&mut params_sizes); }
    // Make sure that all possible combinations are tested.
    for &s1 in &[block_hash::FULL_SIZE] {
        for &s2 in &[block_hash::HALF_SIZE, block_hash::FULL_SIZE] {
            for &norm in &[false, true] {
                assert!(params_type.remove(&(s1, s2, norm)));
            }
            assert!(params_sizes.remove(&(s1, s2)));
        }
    }
    assert!(params_type.is_empty());
    assert!(params_sizes.is_empty());
}


#[test]
fn fuzzy_hash_operation_error_impls() {
    // Test Clone
    test_auto_clone::<FuzzyHashOperationError>(&FuzzyHashOperationError::BlockHashOverflow);
    // Test Display
    assert_eq!(format!("{}", FuzzyHashOperationError::BlockHashOverflow),     "overflow will occur while copying the block hash");
    assert_eq!(format!("{}", FuzzyHashOperationError::StringizationOverflow), "overflow will occur while converting to the string representation");
}


#[test]
fn data_model_new() {
    assert_eq!(block_size::MIN, 3);
    #[allow(clippy::clone_on_copy)]
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        let mut hashes = vec![
            FuzzyHashData::<S1, S2, NORM>::new(),
            FuzzyHashData::<S1, S2, NORM>::default(),
            str::parse::<FuzzyHashData<S1, S2, NORM>>("3::").unwrap(),
            FuzzyHashData::<S1, S2, NORM>::from_bytes(b"3::").unwrap(),
        ];
        hashes.push(hashes[0].clone());
        for (test_num, h) in hashes.iter().enumerate() {
            let hash0 = &hashes[0];
            assert!(h.is_valid(), "failed ({}) on typename={:?}", test_num, typename);
            assert!(h.full_eq(hash0), "failed ({}) on typename={:?}", test_num, typename);
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
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
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8], bh1_norm: &[u8], bh2_norm: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let sizes = type_name::<BHSs<S1, S2>>();
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        fn bh_to_array<const N: usize>(bh: &[u8]) -> Option<[u8; N]> {
            let mut bh_array = [0u8; N];
            if bh.len() > N { return None; } // Return None on overflow
            bh_array[..bh.len()].copy_from_slice(&bh[..bh.len()]);
            Some(bh_array)
        }
        // Initialize raw block hash representations (raw/normalized)
        let bh1_raw = bh_to_array::<S1>(bh1);
        let bh2_raw = bh_to_array::<S2>(bh2);
        let bh1_norm_raw = bh_to_array::<S1>(bh1_norm);
        let bh2_norm_raw = bh_to_array::<S2>(bh2_norm);
        for log_block_size in block_size::RANGE_LOG_VALID {
            let bs = block_size::from_log_internal(log_block_size);
            #[allow(clippy::clone_on_copy)]
            fn init_and_check_hash<const S1: usize, const S2: usize, const NORM: bool>(
                log_block_size: u8, bs: u32, bh1: &[u8], bh2: &[u8], bh1_raw: &[u8; S1], bh2_raw: &[u8; S2]
            ) -> FuzzyHashData<S1, S2, NORM>
            where
                BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
            {
                let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
                let len_bh1_raw = u8::try_from(bh1.len()).unwrap();
                let len_bh2_raw = u8::try_from(bh2.len()).unwrap();
                // Construct the fuzzy hash using various ways
                let mut hashes = vec![
                    {
                        let mut hash = FuzzyHashData::<S1, S2, NORM>::new();
                        hash.init_from_internals_raw_internal(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw);
                        hash
                    },
                    {
                        let mut hash = FuzzyHashData::<S1, S2, NORM>::new();
                        hash.init_from_internals_raw(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw);
                        hash
                    },
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals_raw_internal(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw),
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals_raw(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw),
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals_near_raw_internal(log_block_size, bh1, bh2),
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals_near_raw(log_block_size, bh1, bh2),
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals_internal(bs, bh1, bh2),
                    FuzzyHashData::<S1, S2, NORM>::new_from_internals(bs, bh1, bh2),
                ];
                hashes.push(hashes[0].clone());
                #[cfg(feature = "unchecked")]
                unsafe {
                    hashes.extend(&[
                        {
                            let mut hash = FuzzyHashData::<S1, S2, NORM>::new();
                            hash.init_from_internals_raw_unchecked(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw);
                            hash
                        },
                        FuzzyHashData::<S1, S2, NORM>::new_from_internals_raw_unchecked(log_block_size, bh1_raw, bh2_raw, len_bh1_raw, len_bh2_raw),
                        FuzzyHashData::<S1, S2, NORM>::new_from_internals_near_raw_unchecked(log_block_size, bh1, bh2),
                        FuzzyHashData::<S1, S2, NORM>::new_from_internals_unchecked(bs, bh1, bh2),
                    ]);
                }
                // and check their equality
                for (test_num, hash) in hashes.iter().enumerate() {
                    assert!(hashes[0].full_eq(hash), "failed ({}) on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", test_num, typename, log_block_size, bh1, bh2);
                }
                // Check direct correspondence to raw values
                let hash = &hashes[0];
                assert_eq!(hash.block_hash_1(), bh1, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_hash_2(), bh2, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_hash_1_as_array(), bh1_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_hash_2_as_array(), bh2_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_hash_1_len(), bh1.len(), "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_hash_2_len(), bh2.len(), "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.block_size(), bs, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.log_block_size(), log_block_size, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                // Check raw values
                assert_eq!(hash.blockhash1, *bh1_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.blockhash2, *bh2_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.len_blockhash1, len_bh1_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.len_blockhash2, len_bh2_raw, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                assert_eq!(hash.log_blocksize, log_block_size, "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                // Check validness
                assert!(hash.is_valid(), "failed on typename={:?}, log_block_size={}, bh1={:?}, bh2={:?}", typename, log_block_size, bh1, bh2);
                *hash
            }
            let hash_norm: Option<FuzzyHashData<S1, S2, true>> =
                (bh2_norm.len() <= FuzzyHashData::<S1, S2, true>::MAX_BLOCK_HASH_SIZE_2 && is_normalized)
                    .then(|| init_and_check_hash::<S1, S2, true>(log_block_size, bs, bh1_norm, bh2_norm, &bh1_norm_raw.unwrap(), &bh2_norm_raw.unwrap()));
            let hash_raw: Option<FuzzyHashData<S1, S2, false>> =
                (bh2.len() <= FuzzyHashData::<S1, S2, false>::MAX_BLOCK_HASH_SIZE_2)
                    .then(|| init_and_check_hash::<S1, S2, false>(log_block_size, bs, bh1, bh2, &bh1_raw.unwrap(), &bh2_raw.unwrap()));
            if let Some(hash_norm) = hash_norm {
                // The type enforces "normalized fuzzy hashes" to be normalized.
                assert!(hash_norm.is_normalized(), "failed on sizes={:?}, log_block_size={}, bh1={:?}, bh2={:?}", sizes, log_block_size, bh1, bh2);
            }
            if let Some(hash_raw) = hash_raw {
                // Considered normalized only if the original block hashes are already normalized.
                assert_eq!(is_normalized, hash_raw.is_normalized(), "failed on sizes={:?}, log_block_size={}, bh1={:?}, bh2={:?}", sizes, log_block_size, bh1, bh2);
                // Because of length constraints, there must be a normalized fuzzy hash
                // when the block hashes are already normalized (this is a requirement of the normalized form).
                assert_eq!(is_normalized, hash_norm.is_some(), "failed on sizes={:?}, log_block_size={}, bh1={:?}, bh2={:?}", sizes, log_block_size, bh1, bh2);
                if let Some(hash_norm) = hash_norm {
                    // Transplant the data and compare (equals only if the input block hashes are already normalized).
                    let hash_raw_2 = FuzzyHashData::<S1, S2, false>::new_from_internals_raw_internal(
                        hash_norm.log_block_size(),
                        hash_norm.block_hash_1_as_array(),
                        hash_norm.block_hash_2_as_array(),
                        hash_norm.block_hash_1_len() as u8,
                        hash_norm.block_hash_2_len() as u8);
                    assert_eq!(is_normalized, hash_raw.full_eq(&hash_raw_2), "failed on sizes={:?}, log_block_size={}, bh1={:?}, bh2={:?}", sizes, log_block_size, bh1, bh2);
                }
            }
        }
    }
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1, bh2, bh1_norm, bh2_norm); }
    });
}

fn make_fuzzy_hash_bytes(
    out: &mut [u8; crate::MAX_LEN_IN_STR], log_block_size: u8, block_hash_1: &[u8], block_hash_2: &[u8]
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
        2. Direct Mapping to the Internal Data (again, more complete but for fewer targets)
            *   block_hash_1
            *   block_hash_2
            *   log_block_size
        3. Normalization (partial; related to the input normalization)
            *   is_normalized
    */
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8], bh1_norm: &[u8], bh2_norm: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let sizes = type_name::<BHSs<S1, S2>>();
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in block_size::RANGE_LOG_VALID {
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            // TODO: Consider removing it once either FuzzyHashStringBytes are separately tested or it is replaced by something else.
            assert_eq!(is_normalized, bytes_norm == bytes_raw, "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            // Initialize hashes from the string (with some validation)
            fn init_and_check_hash<const S1: usize, const S2: usize, const NORM: bool>(
                input: &[u8], is_input_normalized: bool,
                log_block_size: u8, bh1_expected: &[u8], bh2_expected: &[u8] // used only if the parser succeeds
            ) -> Option<FuzzyHashData<S1, S2, NORM>>
            where
                BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
            {
                let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
                let hash_opt = FuzzyHashData::<S1, S2, NORM>::from_bytes(input).ok();
                if let Some(hash) = hash_opt {
                    let bytes_str = core::str::from_utf8(input).unwrap();
                    let hash_normalized = NORM || is_input_normalized;
                    assert!(hash.is_valid(), "failed on typename={:?}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.is_normalized(), hash_normalized, "failed on typename={:?}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.log_block_size(), log_block_size, "failed on typename={:?}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.block_hash_1(), bh1_expected, "failed on typename={:?}, bytes_str={:?}", typename, bytes_str);
                    assert_eq!(hash.block_hash_2(), bh2_expected, "failed on typename={:?}, bytes_str={:?}", typename, bytes_str);
                }
                hash_opt
            }
            let opt_hash_norm          = init_and_check_hash::<S1, S2,  true>(bytes_norm, true || is_normalized, log_block_size, bh1_norm, bh2_norm);
            let opt_hash_norm_from_raw = init_and_check_hash::<S1, S2,  true>(bytes_raw, false || is_normalized, log_block_size, bh1_norm, bh2_norm);
            let opt_hash_raw           = init_and_check_hash::<S1, S2, false>(bytes_raw, false || is_normalized, log_block_size, bh1, bh2);
            let opt_hash_raw_from_norm = init_and_check_hash::<S1, S2, false>(bytes_norm, true || is_normalized, log_block_size, bh1_norm, bh2_norm);
            /*
                Implication Chart (guaranteed by this crate):
                    raw           -> (raw_from_norm, norm, norm_from_raw)
                    norm          -> raw_from_norm
                    raw_from_norm -> norm  (or norm <-> raw_from_norm)
                    norm_from_raw -> norm
                Implication Chart (current implementation, not tested here):
                    norm          -> norm_from_raw  (or norm <-> norm_from_raw)
            */
            assert_eq!(opt_hash_raw_from_norm.is_some(), opt_hash_norm.is_some(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            if opt_hash_raw.is_some() {
                assert!(opt_hash_norm.is_some(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                // opt_hash_raw_from_norm.is_some() is checked by two tests above.
                assert!(opt_hash_norm_from_raw.is_some(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            }
            /*
                Note:
                opt_hash_norm and opt_hash_norm_from_raw are always the same in the current implementation
                but this is not guaranteed (if opt_hash_norm_from_raw is None, opt_hash_norm is not necessarily None).
                However, if opt_hash_norm_from_raw is Some, opt_hash_norm is also always Some.
            */
            if opt_hash_norm_from_raw.is_some() {
                assert!(opt_hash_norm.is_some(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            }
        }
    }
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1, bh2, bh1_norm, bh2_norm); }
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
        2. Mostly lossless conversion (except normalization)
            *   from
            *   from_raw_form
        3. Lossless conversion (with possible failure)
            *   try_from (long -> short)
            *   try_into_mut_short
    */
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        for log_block_size in block_size::RANGE_LOG_VALID {
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            // Make fuzzy hashes
            let opt_hash_s_n: Option<FuzzyHash> = FuzzyHash::from_bytes(bytes_raw).ok().or(FuzzyHash::from_bytes(bytes_norm).ok());
            let opt_hash_s_r: Option<RawFuzzyHash> = RawFuzzyHash::from_bytes(bytes_raw).ok();
            let opt_hash_l_n: Option<LongFuzzyHash> = LongFuzzyHash::from_bytes(bytes_raw).ok().or(LongFuzzyHash::from_bytes(bytes_norm).ok());
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
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8], bh1_norm: &[u8], bh2_norm: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let sizes = type_name::<BHSs<S1, S2>>();
        let is_normalized = bh1 == bh1_norm && bh2 == bh2_norm;
        for log_block_size in block_size::RANGE_LOG_VALID {
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            let bytes_str = core::str::from_utf8(bytes_raw).unwrap();
            // Initialize fuzzy hashes
            fn init_and_check_hash<const S1: usize, const S2: usize, const NORM: bool>(bytes: &[u8], is_input_normalized: bool, bytes_str: &str) -> Option<FuzzyHashData<S1, S2, NORM>>
                where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
            {
                let sizes = type_name::<BHSs<S1, S2>>();
                let opt = FuzzyHashData::<S1, S2, NORM>::from_bytes(bytes).ok();
                if let Some(hash) = opt {
                    assert_eq!(hash.is_normalized(), NORM || is_input_normalized, "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                }
                opt
            }
            let opt_hash_norm          = init_and_check_hash::<S1, S2,  true>(bytes_norm, true || is_normalized, bytes_str);
            let opt_hash_norm_from_raw = init_and_check_hash::<S1, S2,  true>(bytes_raw, false || is_normalized, bytes_str);
            let opt_hash_raw           = init_and_check_hash::<S1, S2, false>(bytes_raw, false || is_normalized, bytes_str);
            let opt_hash_raw_from_norm = init_and_check_hash::<S1, S2, false>(bytes_norm, true || is_normalized, bytes_str);
            // Equivalence with other normalized hashes.
            if let Some(hash_norm_from_raw) = opt_hash_norm_from_raw {
                // norm_from_raw -> norm
                let hash_norm = opt_hash_norm.unwrap();
                assert!(hash_norm.full_eq(&hash_norm_from_raw), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            }
            if let Some(hash_norm) = opt_hash_norm {
                // norm -> raw_from_norm
                // Transplant the data and check.
                let hash_raw_from_norm = opt_hash_raw_from_norm.unwrap();
                let hash_raw_transplanted = FuzzyHashData::<S1, S2, false>::new_from_internals_raw(
                    hash_norm.log_block_size(),
                    hash_norm.block_hash_1_as_array(),
                    hash_norm.block_hash_2_as_array(),
                    hash_norm.block_hash_1_len() as u8,
                    hash_norm.block_hash_2_len() as u8);
                assert!(hash_raw_from_norm.full_eq(&hash_raw_transplanted), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
            }
            // Explicit Normalization and Conversion between Normalized and Raw Forms
            if let Some(hash_raw) = opt_hash_raw {
                // raw -> (raw_from_norm, norm[, norm_from_raw])
                let hash_raw_from_norm = opt_hash_raw_from_norm.unwrap();
                let hash_norm = opt_hash_norm.unwrap();
                let mut hashes_raw  = Vec::<FuzzyHashData<S1, S2, false>>::new();
                let mut hashes_norm = Vec::<FuzzyHashData<S1, S2, true>>::new();
                // normalize_in_place (raw)
                hashes_raw.push({
                    let mut hash = hash_raw;
                    hash.normalize_in_place();
                    hash
                });
                // normalize_in_place (normalized) - just no-op
                hashes_norm.push({
                    let mut hash = hash_norm;
                    hash.normalize_in_place();
                    hash
                });
                hashes_norm.push(hash_raw.normalize());
                hashes_norm.push(hash_norm.normalize()); // just clone
                hashes_raw.push(hash_raw.clone_normalized());
                hashes_norm.push(hash_norm.clone_normalized()); // just clone
                hashes_raw.push(FuzzyHashData::<S1, S2, false>::from(hash_norm)); // no change
                hashes_norm.push(FuzzyHashData::<S1, S2, true>::from(hash_raw));  // with normalization
                hashes_raw.push(hash_norm.to_raw_form()); // no change
                hashes_norm.push(FuzzyHashData::<S1, S2, true>::from_raw_form(&hash_raw)); // with normalization
                // Comparison
                for (test_num, hash) in hashes_raw.iter().enumerate() {
                    assert!(hash.is_valid(), "failed ({}) on sizes={:?}, bytes_str={:?}", test_num, sizes, bytes_str);
                    assert!(hash.full_eq(&hash_raw_from_norm), "failed ({}) on sizes={:?}, bytes_str={:?}", test_num, sizes, bytes_str);
                }
                for (test_num, hash) in hashes_norm.iter().enumerate() {
                    assert!(hash.is_valid(), "failed ({}) on sizes={:?}, bytes_str={:?}", test_num, sizes, bytes_str);
                    assert!(hash.full_eq(&hash_norm), "failed ({}) on sizes={:?}, bytes_str={:?}", test_num, sizes, bytes_str);
                }
            }
        }
    }
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1, bh2, bh1_norm, bh2_norm); }
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
    fn is_ch_okay_for_output_byte(ch: u8) -> bool {
        // We expect *here* that the character is an ASCII-printable except ','.
        ch.is_ascii() && !ch.is_ascii_control() && ch != b','
    }
    const NULL_CH: u8 = 0xa9; // Latin-1 copyright mark, not a valid character in the fuzzy hash.
    assert!(!is_ch_okay_for_output_byte(NULL_CH));
    // Test block hash contents.
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8], bh1_norm: &[u8], bh2_norm: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        for log_block_size in block_size::RANGE_LOG_VALID {
            // Make input bytes
            let bobj_norm = FuzzyHashStringBytes::new(log_block_size, bh1_norm, bh2_norm);
            let bobj_raw  = FuzzyHashStringBytes::new(log_block_size, bh1, bh2);
            let bytes_norm = bobj_norm.as_bytes();
            let bytes_raw  = bobj_raw.as_bytes();
            #[allow(unused_variables, unused_mut, clippy::useless_vec)]
            fn init_and_check_hash<const S1: usize, const S2: usize, const NORM: bool>(input: &[u8], bytes_expected: &[u8], bh1_expected: &[u8], bh2_expected: &[u8])
                where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
            {
                let sizes = type_name::<BHSs<S1, S2>>();
                let hash_opt = FuzzyHashData::<S1, S2, NORM>::from_bytes(input).ok();
                if let Some(hash) = hash_opt {
                    let bytes_str = core::str::from_utf8(input).unwrap();
                    // Maximum length in the string representation
                    assert!(hash.len_in_str() <= FuzzyHashData::<S1, S2, NORM>::MAX_LEN_IN_STR, "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    if  hash.log_blocksize as usize == block_size::NUM_VALID - 1 &&
                        bh1_expected.len() == FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1 &&
                        bh2_expected.len() == FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2
                    {
                        assert!(hash.len_in_str() == FuzzyHashData::<S1, S2, NORM>::MAX_LEN_IN_STR, "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    }
                    // Check store_into_bytes
                    // 1.  Less than len_in_str (would cause StringizationOverflow)
                    // 2.  Exactly   len_in_str
                    // 3.  More than len_in_str (exactly the same result to 2. is expected)
                    let mut str_buffer_1 = [NULL_CH; crate::MAX_LEN_IN_STR + 1];
                    let mut str_buffer_2 = [NULL_CH; crate::MAX_LEN_IN_STR + 1];
                    assert_eq!(hash.store_into_bytes(&mut str_buffer_1[..hash.len_in_str() - 1]), Err(FuzzyHashOperationError::StringizationOverflow), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert_eq!(str_buffer_1, [NULL_CH; crate::MAX_LEN_IN_STR + 1], "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert_eq!(hash.store_into_bytes(&mut str_buffer_1[..hash.len_in_str()]).unwrap(), hash.len_in_str(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert!(str_buffer_1[hash.len_in_str()..].iter().all(|&x| x == NULL_CH), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert_eq!(hash.store_into_bytes(&mut str_buffer_2).unwrap(), hash.len_in_str(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert!(str_buffer_2[hash.len_in_str()..].iter().all(|&x| x == NULL_CH), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    assert_eq!(str_buffer_1, str_buffer_2, "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    // Check store_into_bytes and len_in_str
                    let stored_bytes = &str_buffer_1[..hash.len_in_str()];
                    // Check minimum string requirements
                    assert!(stored_bytes.iter().all(|&x| is_ch_okay_for_output_byte(x)), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                    // Converting back to the original hash preserves the value.
                    let mut hashes_back = vec![FuzzyHashData::<S1, S2, NORM>::from_bytes(stored_bytes).unwrap()];
                    // Check String
                    #[cfg(feature = "alloc")]
                    {
                        // from_bytes and from_str are equivalent.
                        let hash_alt = str::parse::<FuzzyHashData<S1, S2, NORM>>(bytes_str).unwrap();
                        assert!(hash.full_eq(&hash_alt), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                        // to_string, String::from and Display matches and contents are expected.
                        let s = hash.to_string();
                        assert_eq!(s, alloc::string::String::from(hash), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                        assert_eq!(s, format!("{}", hash), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                        assert_eq!(s.len(), hash.len_in_str(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                        assert_eq!(bytes_expected, s.as_bytes(), "failed on sizes={:?}, bytes_str={:?}", sizes, bytes_str);
                        // Converting back to the original hash preserves the value.
                        hashes_back.push(FuzzyHashData::<S1, S2, NORM>::from_bytes(s.as_bytes()).unwrap());
                        hashes_back.push(str::parse::<FuzzyHashData<S1, S2, NORM>>(s.as_str()).unwrap());
                    }
                    // Converting back to the original hash preserves the value.
                    for (test_num, hash_back) in hashes_back.iter().enumerate() {
                        assert!(hash.full_eq(hash_back), "failed ({}) on sizes={:?}, bytes_str={:?}", test_num, sizes, bytes_str);
                    }
                }
            }
            init_and_check_hash::<S1, S2,  true>(bytes_norm, bytes_norm, bh1_norm, bh2_norm);
            init_and_check_hash::<S1, S2,  true>(bytes_raw,  bytes_norm, bh1_norm, bh2_norm);
            init_and_check_hash::<S1, S2, false>(bytes_raw,  bytes_raw,  bh1, bh2);
            init_and_check_hash::<S1, S2, false>(bytes_norm, bytes_norm, bh1_norm, bh2_norm);
        }
    }
    test_blockhash_contents_all(&mut |bh1, bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1, bh2, bh1_norm, bh2_norm); }
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
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        for bs1 in block_size::RANGE_LOG_VALID {
            // [BS1]:A:
            let lhs = FuzzyHashData::<S1, S2, NORM>::new_from_internals(block_size::from_log_internal(bs1), &[0], &[]);
            assert!(lhs.is_valid(), "failed on typename={:?}, bs1={}", typename, bs1);
            for bs2 in block_size::RANGE_LOG_VALID {
                // [BS2]::A
                let rhs = FuzzyHashData::<S1, S2, NORM>::new_from_internals(block_size::from_log_internal(bs2), &[], &[0]);
                assert!(rhs.is_valid(), "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_ne!(lhs, rhs, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                // Use cmp_by_block_size (call with two different conventions).
                let ord = FuzzyHashData::<S1, S2, NORM>::cmp_by_block_size(&lhs, &rhs);
                match ord {
                    Ordering::Equal => {
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp_by_block_size(&rhs, &lhs), Ordering::Equal, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert!(bs1 == bs2, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        // [BS]:A: > [BS]::A (because of the dictionary order)
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&lhs, &rhs), Ordering::Greater, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&rhs, &lhs), Ordering::Less,    "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    Ordering::Less => {
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp_by_block_size(&rhs, &lhs), Ordering::Greater, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert!(bs1 < bs2, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&lhs, &rhs), Ordering::Less,    "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&rhs, &lhs), Ordering::Greater, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                    Ordering::Greater => {
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp_by_block_size(&rhs, &lhs), Ordering::Less, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert!(bs1 > bs2, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&lhs, &rhs), Ordering::Greater, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                        assert_eq!(FuzzyHashData::<S1, S2, NORM>::cmp(&rhs, &lhs), Ordering::Less,    "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                    }
                }
                assert_eq!(ord, lhs.cmp_by_block_size(&rhs), "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                // Use compare_block_sizes.
                let rel = FuzzyHashData::<S1, S2, NORM>::compare_block_sizes(lhs, rhs);
                // Test consistency between the block_size module and self comparison.
                assert_eq!(FuzzyHashData::<S1, S2, NORM>::is_block_sizes_near(lhs, rhs), block_size::is_near(lhs.log_block_size(), rhs.log_block_size()),       "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(FuzzyHashData::<S1, S2, NORM>::is_block_sizes_near_lt(lhs, rhs), block_size::is_near_lt(lhs.log_block_size(), rhs.log_block_size()), "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(FuzzyHashData::<S1, S2, NORM>::is_block_sizes_near_eq(lhs, rhs), block_size::is_near_eq(lhs.log_block_size(), rhs.log_block_size()), "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                assert_eq!(FuzzyHashData::<S1, S2, NORM>::is_block_sizes_near_gt(lhs, rhs), block_size::is_near_gt(lhs.log_block_size(), rhs.log_block_size()), "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2);
                match rel {
                    BlockSizeRelation::Far =>    { assert_ne!(ord, Ordering::Equal,   "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2); }
                    BlockSizeRelation::NearLt => { assert_eq!(ord, Ordering::Less,    "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2); }
                    BlockSizeRelation::NearEq => { assert_eq!(ord, Ordering::Equal,   "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2); }
                    BlockSizeRelation::NearGt => { assert_eq!(ord, Ordering::Greater, "failed on typename={:?}, bs1={}, bs2={}", typename, bs1, bs2); }
                }
            }
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
}


fn check_validness_and_debug<const S1: usize, const S2: usize, const NORM: bool>(hash: FuzzyHashData<S1, S2, NORM>)
    where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
{
    const EXPECTED_ILL_FORMED_PREFIX: &str = "FuzzyHashData { ILL_FORMED: true,";
    let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
    if !hash.is_valid() {
        assert!(format!("{:?}", hash).starts_with(EXPECTED_ILL_FORMED_PREFIX), "failed on typename={:?}", typename);
    }
}

#[test]
fn data_model_corruption_common() {
    // Common prerequisites
    assert_fits_in!(block_hash::MAX_SEQUENCE_SIZE + 1, u8);
    /*
        1. Validity
            *   is_valid
        2. Debug output (when invalid)
            *   fmt (Debug)
    */
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        // Prerequisites
        assert!(block_hash::MAX_SEQUENCE_SIZE < FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1, "failed on typename={:?}", typename);
        assert!(block_hash::MAX_SEQUENCE_SIZE < FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2, "failed on typename={:?}", typename);
        assert_fits_in!(FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1 + 1, u8, "failed on typename={:?}", typename);
        assert_fits_in!(FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2 + 1, u8, "failed on typename={:?}", typename);
        // Check validness in various cases
        let hash = FuzzyHashData::<S1, S2, NORM>::new(); // valid
        // Invalid block size
        {
            let mut hash = hash;
            for log_block_size in u8::MIN..=u8::MAX {
                hash.log_blocksize = log_block_size;
                assert_eq!(hash.is_valid(), block_size::is_log_valid(log_block_size), "failed on typename={:?}", typename);
                check_validness_and_debug(hash);
            }
        }
        // Corrupt block hash 1 length
        for len_blockhash in u8::MIN..=u8::MAX {
            let mut hash = hash;
            hash.len_blockhash1 = len_blockhash;
            // Fill with valid values first
            (0..len_blockhash).collect_slice(&mut hash.blockhash1);
            // Validness depends on the block hash length we set
            assert_eq!(hash.is_valid(), len_blockhash <= FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1 as u8, "failed on typename={:?}", typename);
            check_validness_and_debug(hash);
        }
        // Corrupt block hash 2 length
        for len_blockhash in u8::MIN..=u8::MAX {
            let mut hash = hash;
            hash.len_blockhash2 = len_blockhash;
            // Fill with valid values first
            (0..len_blockhash).collect_slice(&mut hash.blockhash2);
            // Validness depends on the block hash length we set
            assert_eq!(hash.is_valid(), len_blockhash <= FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2 as u8, "failed on typename={:?}", typename);
            check_validness_and_debug(hash);
        }
        // Corrupt block hash 1 contents (inside/outside the block hash)
        for block_hash_len in 1..=FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1 {
            let mut hash = hash;
            hash.len_blockhash1 = block_hash_len as u8;
            // Fill with valid values first
            (0..).collect_slice(&mut hash.blockhash1[..block_hash_len]);
            assert!(hash.is_valid(), "failed on typename={:?}", typename);
            // Put an invalid character in the block hash.
            for corrupted_index in 0..block_hash_len {
                let mut hash = hash;
                hash.blockhash1[corrupted_index] = BASE64_INVALID;
                assert!(!hash.is_valid(), "failed on typename={:?}", typename);
                check_validness_and_debug(hash);
            }
            // Put a non-zero character outside the block hash.
            for corrupted_index in block_hash_len..FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                hash.blockhash1[corrupted_index] = 1;
                assert!(!hash.is_valid(), "failed on typename={:?}", typename);
                check_validness_and_debug(hash);
            }
        }
        // Corrupt block hash 2 contents (inside/outside the block hash)
        for block_hash_len in 1..=FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2 {
            let mut hash = hash;
            hash.len_blockhash2 = block_hash_len as u8;
            // Fill with valid values first
            (0..).collect_slice(&mut hash.blockhash2[..block_hash_len]);
            assert!(hash.is_valid(), "failed on typename={:?}", typename);
            // Put an invalid character in the block hash.
            for corrupted_index in 0..block_hash_len {
                let mut hash = hash;
                hash.blockhash2[corrupted_index] = BASE64_INVALID;
                assert!(!hash.is_valid(), "failed on typename={:?}", typename);
                check_validness_and_debug(hash);
            }
            // Put a non-zero character outside the block hash.
            for corrupted_index in block_hash_len..FuzzyHashData::<S1, S2, NORM>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                hash.blockhash2[corrupted_index] = 1;
                assert!(!hash.is_valid(), "failed on typename={:?}", typename);
                check_validness_and_debug(hash);
            }
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
}

#[test]
fn data_model_corruption_normalization() {
    fn test_body<const S1: usize, const S2: usize>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, true>>();
        // Block hash 1 normalization
        {
            let mut hash = FuzzyHashData::<S1, S2, true>::new();
            // block hash "AAA" (max sequence size): valid
            hash.len_blockhash1 = block_hash::MAX_SEQUENCE_SIZE as u8;
            assert!(hash.is_valid(), "failed on typename={:?}", typename);
            // block hash "AAAA" (max sequence size + 1): invalid
            hash.len_blockhash1 = block_hash::MAX_SEQUENCE_SIZE as u8 + 1;
            assert!(!hash.is_valid(), "failed on typename={:?}", typename);
            check_validness_and_debug(hash);
        }
        // Block hash 2 normalization
        {
            let mut hash = FuzzyHashData::<S1, S2, true>::new();
            // block hash "AAA" (max sequence size): valid
            hash.len_blockhash2 = block_hash::MAX_SEQUENCE_SIZE as u8;
            assert!(hash.is_valid(), "failed on typename={:?}", typename);
            // block hash "AAAA" (max sequence size + 1): invalid
            hash.len_blockhash2 = block_hash::MAX_SEQUENCE_SIZE as u8 + 1;
            assert!(!hash.is_valid(), "failed on typename={:?}", typename);
            check_validness_and_debug(hash);
        }
    }
    call_for_fuzzy_hash_sizes! { test_body(); }
}

#[test]
fn data_model_eq_and_full_eq() {
    /*
        Equality (when corrupted):
        *   eq
        *   full_eq
    */
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        let hash = FuzzyHashData::<S1, S2, NORM>::new(); // valid
        // Write a non-zero value to "out of block hash" location.
        let mut hash_corrupted_1 = hash;
        hash_corrupted_1.blockhash1[0] = 1;
        let mut hash_corrupted_2 = hash;
        hash_corrupted_2.blockhash2[0] = 1;
        // Now those two hashes are corrupted.
        assert!(!hash_corrupted_1.is_valid(), "failed on typename={:?}", typename);
        assert!(!hash_corrupted_2.is_valid(), "failed on typename={:?}", typename);
        // But, default comparison results in "equal" because of ignoring
        // certain bytes.
        assert_eq!(hash, hash_corrupted_1, "failed on typename={:?}", typename);
        assert_eq!(hash, hash_corrupted_2, "failed on typename={:?}", typename);
        // Still, full_eq will return false.
        assert!(!hash.full_eq(&hash_corrupted_1), "failed on typename={:?}", typename);
        assert!(!hash.full_eq(&hash_corrupted_2), "failed on typename={:?}", typename);
        assert!(!hash_corrupted_1.full_eq(&hash), "failed on typename={:?}", typename);
        assert!(!hash_corrupted_2.full_eq(&hash), "failed on typename={:?}", typename);
        assert!(!hash_corrupted_1.full_eq(&hash_corrupted_2), "failed on typename={:?}", typename);
        assert!(!hash_corrupted_2.full_eq(&hash_corrupted_1), "failed on typename={:?}", typename);
    }
    call_for_fuzzy_hash_type! { test_body(); }
}


#[test]
fn data_model_normalized_windows() {
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, true>>();
        if bh2.len() > S2 { return; }
        let hash = FuzzyHashData::<S1, S2, true>::new_from_internals_near_raw(0, bh1, bh2);
        // For each block hash, windows will return nothing as long as
        // the block hash is shorter than block_hash::MIN_LCS_FOR_COMPARISON.
        assert_eq!(hash.block_hash_1_windows().next().is_none(), hash.block_hash_1_len() < block_hash::MIN_LCS_FOR_COMPARISON, "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        assert_eq!(hash.block_hash_2_windows().next().is_none(), hash.block_hash_2_len() < block_hash::MIN_LCS_FOR_COMPARISON, "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        // Check window contents (block hash 1 / 2)
        if hash.block_hash_1_len() >= block_hash::MIN_LCS_FOR_COMPARISON {
            let mut windows = hash.block_hash_1_windows();
            let block_hash_1 = hash.block_hash_1();
            for offset in 0..=(hash.block_hash_1_len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                assert_eq!(windows.next().unwrap(), &block_hash_1[offset..offset + block_hash::MIN_LCS_FOR_COMPARISON], "failed on typename={:?}, bh1={:?}, bh2={:?}, offset={}", typename, bh1, bh2, offset);
            }
            assert!(windows.next().is_none(), "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        }
        if hash.block_hash_2_len() >= block_hash::MIN_LCS_FOR_COMPARISON {
            let mut windows = hash.block_hash_2_windows();
            let block_hash_2 = hash.block_hash_2();
            for offset in 0..=(hash.block_hash_2_len() - block_hash::MIN_LCS_FOR_COMPARISON) {
                assert_eq!(windows.next().unwrap(), &block_hash_2[offset..offset + block_hash::MIN_LCS_FOR_COMPARISON], "failed on typename={:?}, bh1={:?}, bh2={:?}, offset={}", typename, bh1, bh2, offset);
            }
            assert!(windows.next().is_none(), "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        }
    }
    test_blockhash_contents_all(&mut |_bh1, _bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1_norm, bh2_norm); }
    });
}

#[test]
fn data_model_normalized_numeric_windows() {
    fn test_body<const S1: usize, const S2: usize>(bh1: &[u8], bh2: &[u8])
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, true>>();
        if bh2.len() > S2 { return; }
        let hash = FuzzyHashData::<S1, S2, true>::new_from_internals_near_raw(0, bh1, bh2);
        // For each block hash, windows will return nothing as long as
        // the block hash is shorter than block_hash::MIN_LCS_FOR_COMPARISON.
        assert_eq!(hash.block_hash_1_numeric_windows().next().is_none(), hash.block_hash_1_len() < block_hash::MIN_LCS_FOR_COMPARISON, "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        assert_eq!(hash.block_hash_2_numeric_windows().next().is_none(), hash.block_hash_2_len() < block_hash::MIN_LCS_FOR_COMPARISON, "failed on typename={:?}, bh1={:?}, bh2={:?}", typename, bh1, bh2);
        // Block hash 1 / 2
        for (offset, (window, window_as_num)) in itertools::zip_eq(hash.block_hash_1_windows(), hash.block_hash_1_numeric_windows()).enumerate() {
            // Because NumericWindows reuses the previous numeric window to generate
            // the next one, we need to compare the result (window_as_num) with
            // the value created from scratch (calculated_window_as_num).
            let calculated_window_as_num = window.iter().fold(0u64, |x, &ch| (x << block_hash::NumericWindows::ILOG2_OF_ALPHABETS) + ch as u64);
            assert_eq!(calculated_window_as_num, window_as_num, "failed on typename={:?}, bh1={:?}, bh2={:?}, offset={}", typename, bh1, bh2, offset);
        }
        for (offset, (window, window_as_num)) in itertools::zip_eq(hash.block_hash_2_windows(), hash.block_hash_2_numeric_windows()).enumerate() {
            let calculated_window_as_num = window.iter().fold(0u64, |x, &ch| (x << block_hash::NumericWindows::ILOG2_OF_ALPHABETS) + ch as u64);
            assert_eq!(calculated_window_as_num, window_as_num, "failed on typename={:?}, bh1={:?}, bh2={:?}, offset={}", typename, bh1, bh2, offset);
        }
    }
    test_blockhash_contents_all(&mut |_bh1, _bh2, bh1_norm, bh2_norm| {
        call_for_fuzzy_hash_sizes! { test_body(bh1_norm, bh2_norm); }
    });
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
pub(crate) const PARSER_ERR_CASES: &[(&str, Result<(), ParseError>, Result<(), ParseError>)] = &[
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
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        for &(hash_str, result_short, result_long) in PARSER_ERR_CASES {
            let err = if FuzzyHashData::<S1, S2, NORM>::IS_LONG_FORM { result_long } else { result_short };
            let mut index1 = usize::MIN;
            let mut index2 = usize::MAX;
            assert_eq!(FuzzyHashData::<S1, S2, NORM>::from_bytes(hash_str.as_bytes()).map(|_| ()), err, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
            assert_eq!(FuzzyHashData::<S1, S2, NORM>::from_bytes_with_last_index(hash_str.as_bytes(), &mut index1).map(|_| ()), err, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
            assert_eq!(FuzzyHashData::<S1, S2, NORM>::from_bytes_with_last_index(hash_str.as_bytes(), &mut index2).map(|_| ()), err, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
            match err {
                Ok(_) => {
                    assert_eq!(index1, index2, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
                    // If the index is not that of the end of the string...
                    if index1 != hash_str.len() {
                        // It must point to the leftmost ',' character.
                        assert!(hash_str.find(',') == Some(index1), "failed on typename={:?}, hash_str={:?}", typename, hash_str);
                    }
                }
                Err(_) => {
                    assert_eq!(index1, usize::MIN, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
                    assert_eq!(index2, usize::MAX, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
                }
            }
            assert_eq!(str::parse::<FuzzyHashData<S1, S2, NORM>>(hash_str).map(|_| ()), err, "failed on typename={:?}, hash_str={:?}", typename, hash_str);
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
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
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        for (log_block_size, &str_block_size) in block_size::BLOCK_SIZES_STR.iter().enumerate() {
            let bs: u32 = str::parse(str_block_size).unwrap();
            let block_size_bytes = str_block_size.as_bytes();
            // For each block_size::BLOCK_SIZES_STR entry "[BS]", make "[BS]::" and parse as a fuzzy hash.
            let mut buf = [0u8; crate::MAX_LEN_IN_STR];
            buf[..block_size_bytes.len()].clone_from_slice(block_size_bytes);
            buf[block_size_bytes.len() + 0] = b':';
            buf[block_size_bytes.len() + 1] = b':';
            // Parse using from_bytes
            let hash = FuzzyHashData::<S1, S2, NORM>::from_bytes(&buf[..block_size_bytes.len() + 2]).unwrap();
            assert!(hash.is_valid(), "failed on typename={:?}, log_block_size={}", typename, log_block_size);
            // Check log_block_size() and block_size()
            assert_eq!(hash.log_block_size(), log_block_size as u8, "failed on typename={:?}, log_block_size={}", typename, log_block_size);
            assert_eq!(hash.block_size(), bs, "failed on typename={:?}, log_block_size={}", typename, log_block_size);
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
}


#[test]
fn parsed_data_example() {
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        let hash = str::parse::<FuzzyHashData<S1, S2, NORM>>("3:ABCD:abcde").unwrap();
        assert!(hash.is_valid(), "failed on typename={:?}", typename);
        // Check internal data
        assert_eq!(hash.block_size(), 3, "failed on typename={:?}", typename);
        assert_eq!(hash.log_block_size(), 0, "failed on typename={:?}", typename);
        assert_eq!(hash.block_hash_1_len(), 4, "failed on typename={:?}", typename);
        assert_eq!(hash.block_hash_2_len(), 5, "failed on typename={:?}", typename);
        // Check its contents
        // 'A': 0, 'a': 26 (on Base64 index)
        assert_eq!(hash.block_hash_1(), [0, 1, 2, 3], "failed on typename={:?}", typename);
        assert_eq!(hash.block_hash_2(), [26, 27, 28, 29, 30], "failed on typename={:?}", typename);
    }
    call_for_fuzzy_hash_type! { test_body(); }
}


#[test]
fn normalization_examples() {
    // Prerequisites (partial)
    assert_eq!(block_hash::MAX_SEQUENCE_SIZE, 3);
    // Test body
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        const NORM0: &str = "3:ABBCCCDDDDEEEEE:555554444333221";
        const NORM1: &str = "3:ABBCCCDDDEEE:555444333221";
        let norm0 = if NORM { NORM1 } else { NORM0 };
        assert_eq!(str::parse::<FuzzyHashData<S1, S2, NORM>>(NORM1).unwrap().to_string(), NORM1, "failed on typename={:?}", typename);
        assert_eq!(str::parse::<FuzzyHashData<S1, S2, NORM>>(NORM0).unwrap().to_string(), norm0, "failed on typename={:?}", typename);
    }
    call_for_fuzzy_hash_type! { test_body(); }
}


#[test]
fn cover_hash() {
    fn coverage_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        let mut hashes = HashSet::<FuzzyHashData<S1, S2, NORM>>::new();
        assert!( hashes.insert(FuzzyHashData::<S1, S2, NORM>::new()), "failed on typename={:?}", typename);
        assert!(!hashes.insert(FuzzyHashData::<S1, S2, NORM>::new()), "failed on typename={:?}", typename);
    }
    call_for_fuzzy_hash_type! { coverage_body(); }
}


#[test]
fn ord_and_sorting() {
    // Sorted by block hash order (Base64 indices and length).
    // Note that 'A' has Base64 index zero and FuzzyHashData zero-fills
    // each tail of block hashes (making the behavior more deterministic).
    const SORTED_DICT: &[&str] = &[
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
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        let mut hashes = Vec::<FuzzyHashData<S1, S2, NORM>>::new();
        for log_block_size in block_size::RANGE_LOG_VALID {
            for &bs1 in SORTED_DICT {
                for &bs2 in SORTED_DICT {
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
                assert_eq!(h1.cmp(h2), i1.cmp(&i2), "failed on typename={:?}, i1={}, i2={}, h1={:?}, h2={:?}", typename, i1, i2, h1, h2);
            }
        }
        // Sorting the list makes the order the same as the original.
        let cloned = hashes.clone();
        hashes.reverse();
        hashes.sort();
        assert_eq!(hashes, cloned, "failed on typename={:?}", typename);
    }
    call_for_fuzzy_hash_type! { test_body(); }
}

#[test]
fn ord_by_block_size_examples() {
    /*
        Ordering (full and only block sizes):
        *   cmp
        *   cmp_by_block_size
    */
    const STRS_UNSORTED: &[&str] = &[
        "12:a:",
        "12:z:",
        "12288:a:",
        "12288:z:",
        "3:z:",
        "3:a:",
        "6144:z:",
        "6144:a:",
    ];
    const STRS_SORTED_ALL: &[&str] = &[
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
    const STRS_SORTED_BLOCK_SIZE: &[&str] = &[
        "3:z:",
        "3:a:",
        "12:a:",
        "12:z:",
        "6144:z:",
        "6144:a:",
        "12288:a:",
        "12288:z:",
    ];
    fn test_body<const S1: usize, const S2: usize, const NORM: bool>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, NORM>>();
        // Construct sorted hashes list
        let hashes_orig: Vec<FuzzyHashData<S1, S2, NORM>> = STRS_UNSORTED.iter().map(|&s| str::parse(s).unwrap()).collect();
        assert!(hashes_orig.iter().all(|x| x.is_valid()), "failed on typename={:?}", typename);
        // Perform and check sorting by all fields (note that main ordering is tested separately)
        let mut hashes = hashes_orig.clone();
        hashes.sort_by(FuzzyHashData::<S1, S2, NORM>::cmp);
        for index in 0..hashes.len() {
            assert_eq!(hashes[index].to_string(), STRS_SORTED_ALL[index], "failed on typename={:?}, index={}", typename, index);
        }
        // Perform and check sorting only by block size
        let mut hashes = hashes_orig;
        hashes.sort_by(FuzzyHashData::<S1, S2, NORM>::cmp_by_block_size);
        for index in 0..hashes.len() {
            assert_eq!(hashes[index].to_string(), STRS_SORTED_BLOCK_SIZE[index], "failed on typename={:?}, index={}", typename, index);
        }
    }
    call_for_fuzzy_hash_type! { test_body(); }
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
    fn test_body<const S1: usize, const S2: usize>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, true>>();
        // Test examples from FuzzyHashData (block sizes are the same)
        {
            const S_A: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
            const S_B: &str = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:H5d+X36WnL5d+X3v5d+X315d+X3+";
            let h_a = str::parse::<FuzzyHashData<S1, S2, true>>(S_A).unwrap();
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            assert!(block_size::is_near_eq(h_a.log_block_size(), h_b.log_block_size()), "failed on typename={:?}", typename);
            assert_eq!(h_a.compare(h_b), 94, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_a), 94, "failed on typename={:?}", typename);
        }
        // ... with only first block hash
        {
            const S_A: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
            const S_B: &str = "6144:SAsMYod+X3oI+YEWnnsMYod+X3oI+Y5sMYod+X3oI+YLsMYod+X3oI+YQ:";
            let h_a = str::parse::<FuzzyHashData<S1, S2, true>>(S_A).unwrap();
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            assert_eq!(h_a.compare(h_b), 94, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_a), 94, "failed on typename={:?}", typename);
        }
        // ... with only second block hash
        {
            const S_A: &str = "6144::Z5d+X395d+X3X5d+X315d+X3+";
            const S_B: &str = "6144::H5d+X36WnL5d+X3v5d+X315d+X3+";
            let h_a = str::parse::<FuzzyHashData<S1, S2, true>>(S_A).unwrap();
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            assert_eq!(h_a.compare(h_b), 85, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_a), 85, "failed on typename={:?}", typename);
        }
    }
    call_for_fuzzy_hash_sizes! { test_body(); }
}

#[test]
fn compare_fuzzy_hash_data_examples_eq_near_but_not_eq() {
    fn test_body<const S1: usize, const S2: usize>()
        where BHS<S1>: CBHS, BHS<S2>: CBHS, BHSs<S1, S2>: CBHSs
    {
        let typename = type_name::<FuzzyHashData<S1, S2, true>>();
        // Test examples from FuzzyHashData (block sizes near but not equal)
        {
            const S_A: &str = "3072:S+IiyfkMY+BES09JXAnyrZalI+YuyfkMY+BES09JXAnyrZalI+YQ:S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
            const S_B: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:Z5d+X395d+X3X5d+X315d+X3+";
            const S_C: &str = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:1+Jr+d++H+5+e";
            let h_a = str::parse::<FuzzyHashData<S1, S2, true>>(S_A).unwrap();
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            let h_c = str::parse::<FuzzyHashData<S1, S2, true>>(S_C).unwrap();
            assert!(block_size::is_near_lt(h_a.log_block_size(), h_b.log_block_size()), "failed on typename={:?}", typename);
            assert!(block_size::is_near_lt(h_b.log_block_size(), h_c.log_block_size()), "failed on typename={:?}", typename);
            assert_eq!(h_a.compare(h_b), 72, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_c), 88, "failed on typename={:?}", typename);
            assert_eq!(h_a.compare(h_c),  0, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_a), 72, "failed on typename={:?}", typename);
            assert_eq!(h_c.compare(h_b), 88, "failed on typename={:?}", typename);
            assert_eq!(h_c.compare(h_a),  0, "failed on typename={:?}", typename);
        }
        // ... with only block hashes compared (A and B)
        {
            const S_A: &str = "3072::S+InsMYod+X3oI+YLsMYod+X3oI+YQ";
            const S_B: &str = "6144:SIsMYod+X3oI+YnsMYod+X3oI+YZsMYod+X3oI+YLsMYod+X3oI+YQ:";
            let h_a = str::parse::<FuzzyHashData<S1, S2, true>>(S_A).unwrap();
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            assert_eq!(h_a.compare(h_b), 72, "failed on typename={:?}", typename);
            assert_eq!(h_b.compare(h_a), 72, "failed on typename={:?}", typename);
        }
        // ... with only block hashes compared (B and C)
        {
            const S_B: &str = "6144::Z5d+X395d+X3X5d+X315d+X3+";
            const S_C: &str = "12288:Z5d+X3pz5d+X3985d+X3X5d+X315d+X3+:";
            let h_b = str::parse::<FuzzyHashData<S1, S2, true>>(S_B).unwrap();
            let h_c = str::parse::<FuzzyHashData<S1, S2, true>>(S_C).unwrap();
            assert_eq!(h_b.compare(h_c), 88, "failed on typename={:?}", typename);
            assert_eq!(h_c.compare(h_b), 88, "failed on typename={:?}", typename);
        }
    }
    call_for_fuzzy_hash_sizes! { test_body(); }
}
