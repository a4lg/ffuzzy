// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::str::FromStr;
#[cfg(feature = "alloc")]
use alloc::format;

use crate::base64::BASE64_INVALID;
use crate::hash::{FuzzyHashData, LongFuzzyHash, LongRawFuzzyHash};
use crate::hash::block::{BlockSize, BlockHash};
use crate::hash::parser_state::{ParseError, ParseErrorKind, ParseErrorOrigin};
use crate::hash_dual::{DualFuzzyHash, LongDualFuzzyHash, RleEncoding};
use crate::test_utils::{assert_fits_in, test_for_each_type};


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
        };
    }
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn test_datamodel_generic() {
    /*
        Tested methods:
        1. Initialization from Internal Data (only valid cases)
            *   init_from_raw_form_internals_raw_internal
            *   init_from_raw_form_internals_raw_unchecked
            *   new_from_raw_form_internals_raw_internal
            *   new_from_raw_form_internals_raw_unchecked
            *   init_from_raw_form_internals_raw
            *   new_from_raw_form_internals_raw
            *   clone
        2. Direct Mapping to Internal Fuzzy Hash
            *   log_block_size
            *   block_size
    */
    macro_rules! test {($ty: ty) => {
        for log_block_size in 0..BlockSize::NUM_VALID {
            for len_blockhash1 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                assert_fits_in!(len_blockhash1, u8);
                assert!(len_blockhash1 <= BlockHash::FULL_SIZE);
                let mut blockhash1 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_1]; // zero fill is mandatory
                // Fill with sequences so that no normalization occurs.
                for i in 0..len_blockhash1 {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    blockhash1[i] = i as u8;
                }
                for len_blockhash2 in 0..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                    assert_fits_in!(len_blockhash2, u8);
                    assert!(len_blockhash2 <= BlockHash::FULL_SIZE);
                    let mut blockhash2 = [0u8; <$ty>::MAX_BLOCK_HASH_SIZE_2]; // zero fill is mandatory
                    // Fill with sequences so that no normalization occurs.
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
                        hash1.init_from_raw_form_internals_raw(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw
                        );
                        let hash2: $ty = <$ty>::new_from_raw_form_internals_raw(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw
                        );
                        let mut hash3: $ty = <$ty>::new();
                        hash3.init_from_raw_form_internals_raw_internal(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw);
                        let hash4: $ty = <$ty>::new_from_raw_form_internals_raw_internal(
                            log_block_size_raw,
                            &blockhash1,
                            &blockhash2,
                            len_blockhash1_raw,
                            len_blockhash2_raw
                        );
                        let hash5: $ty = hash1.clone();
                        assert_eq!(hash1, hash2);
                        assert_eq!(hash1, hash3);
                        assert_eq!(hash1, hash4);
                        assert_eq!(hash1, hash5);
                        assert!(hash1.norm_hash.full_eq(&hash2.norm_hash));
                        assert!(hash1.norm_hash.full_eq(&hash3.norm_hash));
                        assert!(hash1.norm_hash.full_eq(&hash4.norm_hash));
                        assert!(hash1.norm_hash.full_eq(&hash5.norm_hash));
                        #[cfg(feature = "unsafe")]
                        unsafe {
                            let mut hash_u1 = <$ty>::new();
                            hash_u1.init_from_raw_form_internals_raw_unchecked(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                            let hash_u2 = <$ty>::new_from_raw_form_internals_raw_unchecked(
                                log_block_size_raw,
                                &blockhash1,
                                &blockhash2,
                                len_blockhash1_raw,
                                len_blockhash2_raw
                            );
                            assert_eq!(hash1, hash_u1);
                            assert_eq!(hash1, hash_u2);
                            assert!(hash1.norm_hash.full_eq(&hash_u1.norm_hash));
                            assert!(hash1.norm_hash.full_eq(&hash_u2.norm_hash));
                        }
                        hash1
                    };
                    // Check validity
                    assert!(hash.is_valid());
                    assert!(hash.norm_hash.is_valid());
                    // Check whether we have no RLE compression encodings
                    assert_eq!(hash.rle_block1, [0u8; <$ty>::RLE_BLOCK_SIZE_1]);
                    assert_eq!(hash.rle_block2, [0u8; <$ty>::RLE_BLOCK_SIZE_2]);
                    // Check raw values
                    assert_eq!(hash.norm_hash.blockhash1, blockhash1);
                    assert_eq!(hash.norm_hash.blockhash2, blockhash2);
                    assert_eq!(hash.norm_hash.len_blockhash1, len_blockhash1_raw);
                    assert_eq!(hash.norm_hash.len_blockhash2, len_blockhash2_raw);
                    assert_eq!(hash.norm_hash.log_blocksize, log_block_size_raw);
                    // Check direct correspondence to raw values
                    assert_eq!(hash.norm_hash.block_hash_1(), blockhash1_slice);
                    assert_eq!(hash.norm_hash.block_hash_2(), blockhash2_slice);
                    assert_eq!(hash.norm_hash.block_hash_1_as_array(), &blockhash1);
                    assert_eq!(hash.norm_hash.block_hash_2_as_array(), &blockhash2);
                    assert_eq!(hash.norm_hash.block_hash_1_len(), len_blockhash1);
                    assert_eq!(hash.norm_hash.block_hash_2_len(), len_blockhash2);
                    assert_eq!(hash.log_block_size(), log_block_size_raw);
                    assert_eq!(hash.log_block_size(), hash.norm_hash.log_block_size());
                    assert_eq!(hash.block_size(), hash.norm_hash.block_size());
                }
            }
        }
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn test_datamodel_blockhash_contents() {
    /*
        Tested methods:
        1. Initialization from existing hashes
            *   init_from_raw_form
            *   from_raw_form
            *   from_normalized
            *   from
        2. Initialization from strings (only valid cases)
            *   from_str
            *   from_bytes
        3. Conversion
            *   to_raw_form
            *   to_normalized
            *   as_ref_normalized
        4. Normalization
            *   is_normalized
            *   normalize_in_place
        5. Stringization
            *   to_raw_form_string
            *   to_normalized_string
    */
    crate::hash::test_utils::test_blockhash_contents_all(&|bh1, bh2, bh1_norm, bh2_norm| {
        let is_norm = bh1.len() == bh1_norm.len() && bh2.len() == bh2_norm.len();
        let mut buf_raw  = [0u8; LongDualFuzzyHash::MAX_LEN_IN_STR];
        let mut buf_norm = [0u8; LongDualFuzzyHash::MAX_LEN_IN_STR];
        let raw_hash =
            LongRawFuzzyHash::new_from_internals(BlockSize::MIN, bh1, bh2);
        let norm_hash =
            LongFuzzyHash::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
        raw_hash.store_into_bytes(&mut buf_raw).unwrap();
        norm_hash.store_into_bytes(&mut buf_norm).unwrap();
        let str_raw = core::str::from_utf8(&buf_raw[..raw_hash.len_in_str()]).unwrap();
        let str_norm = core::str::from_utf8(&buf_norm[..norm_hash.len_in_str()]).unwrap();

        macro_rules! test {($ty: ty) => {
            type FuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
            type RawFuzzyHashType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, false>;
            if bh2.len() > <$ty>::MAX_BLOCK_HASH_SIZE_2 {
                break;
            }
            let raw_hash_from_str = RawFuzzyHashType::from_str(str_raw).unwrap();
            let norm_hash_from_str = FuzzyHashType::from_str(str_norm).unwrap();
            assert!(raw_hash_from_str.is_valid());
            assert!(norm_hash_from_str.is_valid());
            let raw_hash = RawFuzzyHashType::new_from_internals(BlockSize::MIN, bh1, bh2);
            let norm_hash = FuzzyHashType::new_from_internals(BlockSize::MIN, bh1_norm, bh2_norm);
            assert!(raw_hash.is_valid());
            assert!(norm_hash.is_valid());
            assert_eq!(raw_hash, raw_hash_from_str);
            assert_eq!(norm_hash, norm_hash_from_str);
            // Check dual hash to raw/normalized hash operations
            let dual_hash = {
                let mut dual_hash1 = <$ty>::new();
                assert!(dual_hash1.is_valid());
                dual_hash1.init_from_raw_form(&raw_hash);
                assert!(dual_hash1.is_valid());
                let dual_hash2 = <$ty>::from_raw_form(&raw_hash);
                assert_eq!(dual_hash1, dual_hash2);
                let dual_hash3 = <$ty>::from(raw_hash);
                assert_eq!(dual_hash1, dual_hash3);
                let dual_hash4 = <$ty>::from_str(str_raw).unwrap();
                assert_eq!(dual_hash1, dual_hash4);
                let dual_hash5 = <$ty>::from_bytes(str_raw.as_bytes()).unwrap();
                assert_eq!(dual_hash1, dual_hash5);
                dual_hash1
            };
            let new_raw_hash = dual_hash.to_raw_form();
            let mut new_raw_hash_2 = RawFuzzyHashType::new();
            dual_hash.into_mut_raw_form(&mut new_raw_hash_2);
            let new_norm_hash = *dual_hash.as_ref_normalized();
            let new_norm_hash_2 = dual_hash.to_normalized();
            assert!(new_raw_hash.is_valid());
            assert!(new_raw_hash_2.is_valid());
            assert!(new_norm_hash.is_valid());
            assert!(new_norm_hash_2.is_valid());
            assert_eq!(raw_hash, new_raw_hash);
            assert_eq!(raw_hash, new_raw_hash_2);
            assert_eq!(norm_hash, new_norm_hash);
            assert_eq!(norm_hash, new_norm_hash_2);
            // ... possibly with normalization
            assert_eq!(dual_hash.is_normalized(), is_norm);
            assert_eq!(raw_hash.is_normalized(), is_norm);
            let norm_dual_hash = {
                let mut norm_dual_hash1 = dual_hash;
                norm_dual_hash1.normalize_in_place();
                assert!(norm_dual_hash1.is_valid());
                let norm_dual_hash2 = <$ty>::from_normalized(&norm_hash);
                assert_eq!(norm_dual_hash1, norm_dual_hash2);
                let norm_dual_hash3 = <$ty>::from(norm_hash);
                assert_eq!(norm_dual_hash1, norm_dual_hash3);
                let norm_dual_hash4 = <$ty>::from_str(str_norm).unwrap();
                assert_eq!(norm_dual_hash1, norm_dual_hash4);
                let norm_dual_hash5 = <$ty>::from_bytes(str_norm.as_bytes()).unwrap();
                assert_eq!(norm_dual_hash1, norm_dual_hash5);
                norm_dual_hash1
            };
            assert!(norm_dual_hash.is_valid());
            assert!(norm_dual_hash.is_normalized());
            let new_norm_hash_as_norm = *norm_dual_hash.as_ref_normalized();
            let new_norm_hash_as_norm_2 = norm_dual_hash.to_normalized();
            let new_norm_hash_as_raw = norm_dual_hash.to_raw_form();
            assert!(new_norm_hash_as_norm.is_valid());
            assert!(new_norm_hash_as_norm_2.is_valid());
            assert!(new_norm_hash_as_raw.is_valid());
            assert_eq!(norm_hash, new_norm_hash_as_norm);
            assert_eq!(norm_hash, new_norm_hash_as_norm_2);
            assert_eq!(norm_hash.to_raw_form(), new_norm_hash_as_raw);
            // Check stringization
            #[cfg(feature = "alloc")]
            {
                let dual_hash = <$ty>::from_raw_form(&raw_hash);
                assert_eq!(dual_hash.to_raw_form_string(), raw_hash.to_string());
                assert_eq!(dual_hash.to_normalized_string(), norm_hash.to_string());
                assert_eq!(dual_hash.to_raw_form_string(), str_raw);
                assert_eq!(dual_hash.to_normalized_string(), str_norm);
                assert_eq!(norm_dual_hash.to_raw_form_string(), norm_hash.to_string());
                assert_eq!(norm_dual_hash.to_normalized_string(), norm_hash.to_string());
                assert_eq!(norm_dual_hash.to_raw_form_string(), str_norm);
                assert_eq!(norm_dual_hash.to_normalized_string(), str_norm);
            }
        }}
        test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
    });
}


#[test]
fn test_datamodel_corruption() {
    /*
        Tested methods:
        1. Validity
            *   is_valid
        2. Debug output (when invalid)
            *   fmt (Debug)
    */
    macro_rules! test {($ty: ty) => {
        macro_rules! hash_is_valid {
            ($hash: expr) => {
                assert!($hash.is_valid());
                assert!($hash.norm_hash.is_valid());
            }
        }
        macro_rules! internal_hash_is_invalid {
            ($hash: expr) => {
                assert!(!$hash.is_valid());
                assert!(!$hash.norm_hash.is_valid());
                #[cfg(feature = "alloc")]
                {
                    assert!(format!("{:?}", $hash).starts_with("FuzzyHashDualData { ILL_FORMED: true,"));
                    assert!(format!("{:?}", $hash.norm_hash).starts_with("FuzzyHashData { ILL_FORMED: true,"));
                }
            };
        }
        let hash: $ty = <$ty>::new();
        hash_is_valid!(hash);
        // Internal (Normalized) Hash: Invalid block size
        {
            let mut hash = hash;
            hash.norm_hash.log_blocksize = BlockSize::NUM_VALID as u8;
            internal_hash_is_invalid!(hash);
        }
        // Internal (Normalized) Hash: Corrupt block hash 1 size
        {
            let mut hash = hash;
            hash.norm_hash.len_blockhash1 = <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8;
            // Fill with valid pattern
            for (i, ch) in hash.norm_hash.blockhash1.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *ch = i as u8;
            }
            hash_is_valid!(hash); // Maximum length (inclusive)
            assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_1 + 1, u8);
            hash.norm_hash.len_blockhash1 = <$ty>::MAX_BLOCK_HASH_SIZE_1 as u8 + 1;
            internal_hash_is_invalid!(hash); // Maximum length + 1 (invalid)
        }
        // Internal (Normalized) Hash: Corrupt block hash 2 size
        {
            let mut hash = hash;
            hash.norm_hash.len_blockhash2 = <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8;
            // Fill with valid pattern
            for (i, ch) in hash.norm_hash.blockhash2.iter_mut().enumerate() {
                assert!(i < BlockHash::ALPHABET_SIZE);
                *ch = i as u8;
            }
            hash_is_valid!(hash); // Maximum length (inclusive)
            assert_fits_in!(<$ty>::MAX_BLOCK_HASH_SIZE_2 + 1, u8);
            hash.norm_hash.len_blockhash2 = <$ty>::MAX_BLOCK_HASH_SIZE_2 as u8 + 1;
            internal_hash_is_invalid!(hash); // Maximum length + 1 (invalid)
        }
        // Internal (Normalized) Hash: Corrupt block hash 1 contents (in the block hash)
        {
            for block_hash_1_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                assert_fits_in!(block_hash_1_len, u8);
                hash.norm_hash.len_blockhash1 = block_hash_1_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.norm_hash.blockhash1[..block_hash_1_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put an invalid character in the block hash.
                for i in 0..block_hash_1_len {
                    let mut hash = hash;
                    hash.norm_hash.blockhash1[i] = BASE64_INVALID;
                    internal_hash_is_invalid!(hash);
                }
            }
        }
        // Internal (Normalized) Hash: Corrupt block hash 2 contents (in the block hash)
        {
            for block_hash_2_len in 1..=<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                assert_fits_in!(block_hash_2_len, u8);
                hash.norm_hash.len_blockhash2 = block_hash_2_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.norm_hash.blockhash2[..block_hash_2_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put an invalid character in the block hash.
                for i in 0..block_hash_2_len {
                    let mut hash = hash;
                    hash.norm_hash.blockhash2[i] = BASE64_INVALID;
                    internal_hash_is_invalid!(hash);
                }
            }
        }
        // Internal (Normalized) Hash: Corrupt block hash 1 contents (out of the block hash)
        {
            for block_hash_1_len in 1..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                let mut hash = hash;
                assert_fits_in!(block_hash_1_len, u8);
                hash.norm_hash.len_blockhash1 = block_hash_1_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.norm_hash.blockhash1[..block_hash_1_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put a non-zero character outside the block hash.
                for i in block_hash_1_len..<$ty>::MAX_BLOCK_HASH_SIZE_1 {
                    let mut hash = hash;
                    hash.norm_hash.blockhash1[i] = 1;
                    internal_hash_is_invalid!(hash);
                }
            }
        }
        // Internal (Normalized) Hash: Corrupt block hash 2 contents (out of the block hash)
        {
            for block_hash_2_len in 0..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                let mut hash = hash;
                assert_fits_in!(block_hash_2_len, u8);
                hash.norm_hash.len_blockhash2 = block_hash_2_len as u8;
                // Fill with valid values first
                for (i, ch) in hash.norm_hash.blockhash2[..block_hash_2_len].iter_mut().enumerate() {
                    assert!(i < BlockHash::ALPHABET_SIZE);
                    *ch = i as u8;
                }
                hash_is_valid!(hash);
                // Put a non-zero character outside the block hash.
                for i in block_hash_2_len..<$ty>::MAX_BLOCK_HASH_SIZE_2 {
                    let mut hash = hash;
                    hash.norm_hash.blockhash2[i] = 1;
                    internal_hash_is_invalid!(hash);
                }
            }
        }
        // Internal (Normalized) Hash: Break block hash 1 normalization
        {
            assert!(BlockHash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_1); // prerequisite
            let mut hash = hash;
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE, u8);
            hash.norm_hash.len_blockhash1 = BlockHash::MAX_SEQUENCE_SIZE as u8;
            hash_is_valid!(hash); // block hash 1 "AAA" (max sequence size): valid
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE + 1, u8);
            hash.norm_hash.len_blockhash1 = BlockHash::MAX_SEQUENCE_SIZE as u8 + 1;
            internal_hash_is_invalid!(hash); // block hash 1 "AAAA" (max sequence size + 1): invalid
        }
        // Internal (Normalized) Hash: Break block hash 2 normalization
        {
            assert!(BlockHash::MAX_SEQUENCE_SIZE < <$ty>::MAX_BLOCK_HASH_SIZE_2); // prerequisite
            let mut hash = hash;
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE, u8);
            hash.norm_hash.len_blockhash2 = BlockHash::MAX_SEQUENCE_SIZE as u8;
            hash_is_valid!(hash); // block hash 2 "AAA" (max sequence size): valid
            assert_fits_in!(BlockHash::MAX_SEQUENCE_SIZE + 1, u8);
            hash.norm_hash.len_blockhash2 = BlockHash::MAX_SEQUENCE_SIZE as u8 + 1;
            internal_hash_is_invalid!(hash); // block hash 2 "AAAA" (max sequence size + 1): invalid
        }
        /*
            WARNING:
            Following tests HEAVILY depends on current RLE block design
            and ssdeep constants.
        */
        macro_rules! hash_is_invalid {
            ($hash: expr) => {
                assert!(!$hash.is_valid());
                #[cfg(feature = "alloc")]
                {
                    assert!(format!("{:?}", $hash).starts_with("FuzzyHashDualData { ILL_FORMED: true,"));
                }
            };
        }
        // Make dummy hash
        let mut hash: $ty = <$ty>::new();
        hash.norm_hash.blockhash1[0..7].clone_from_slice(&[1, 1, 1, 2, 3, 3, 3]);
        hash.norm_hash.blockhash2[0..7].clone_from_slice(&[4, 4, 4, 5, 6, 6, 6]);
        hash.norm_hash.len_blockhash1 = 7;
        hash.norm_hash.len_blockhash2 = 7;
        hash_is_valid!(hash);
        // RLE block is currently filled with zeroes.
        assert!(hash.rle_block1.iter().all(|x| *x == 0));
        assert!(hash.rle_block2.iter().all(|x| *x == 0));
        // RLE Block: Non-zero RLE block after termination (block hash 1)
        {
            for i in 1..<$ty>::RLE_BLOCK_SIZE_1 {
                for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                    let mut hash = hash;
                    hash.rle_block1[i] = 1 | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);
                }
            }
        }
        // RLE Block: Non-zero RLE block after termination (block hash 2)
        {
            for i in 1..<$ty>::RLE_BLOCK_SIZE_2 {
                for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                    let mut hash = hash;
                    hash.rle_block2[i] = 1 | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);
                }
            }
        }
        // RLE Block: Position exceeds the block hash size (block hash 1)
        {
            let mut hash = hash;
            for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                hash.rle_block1[0] = 6 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash);
            }
            assert_eq!(hash.norm_hash.len_blockhash1, 7);
            for i in hash.norm_hash.len_blockhash1..=RleEncoding::MASK_POSITION {
                for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                    hash.rle_block1[0] = i | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);
                }
            }
        }
        // RLE Block: Position exceeds the block hash size (block hash 2)
        {
            let mut hash = hash;
            for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                hash.rle_block2[0] = 6 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash);
            }
            assert_eq!(hash.norm_hash.len_blockhash2, 7);
            for i in hash.norm_hash.len_blockhash2..=RleEncoding::MASK_POSITION {
                for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                    hash.rle_block2[0] = i | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);
                }
            }
        }
        // RLE Block: Position is not the tail of identical character sequence (1)
        {
            let mut hash = hash;
            for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                if l != 0 {
                    hash.rle_block1[0] = 0 | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);   // "**B"
                }
                hash.rle_block1[0] = 1 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "*BB"
                hash.rle_block1[0] = 2 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash); // "BBB" (valid)
                hash.rle_block1[0] = 3 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "BBC"
                hash.rle_block1[0] = 4 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "BCD"
                hash.rle_block1[0] = 5 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "CDD"
                hash.rle_block1[0] = 6 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash); // "DDD" (valid)
            }
        }
        // RLE Block: Position is not the tail of identical character sequence (2)
        {
            let mut hash = hash;
            for l in 0..RleEncoding::MAX_RUN_LENGTH as u8 {
                if l != 0 {
                    hash.rle_block2[0] = 0 | (l << RleEncoding::BITS_POSITION);
                    hash_is_invalid!(hash);   // "**E"
                }
                hash.rle_block2[0] = 1 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "*EE"
                hash.rle_block2[0] = 2 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash); // "EEE" (valid)
                hash.rle_block2[0] = 3 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "EEF"
                hash.rle_block2[0] = 4 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "EFG"
                hash.rle_block2[0] = 5 | (l << RleEncoding::BITS_POSITION);
                hash_is_invalid!(hash);   // "FGG"
                hash.rle_block2[0] = 6 | (l << RleEncoding::BITS_POSITION);
                hash_is_valid!(hash); // "GGG" (valid)
            }
        }
        // RLE Block: Must be sorted by position (block hash 1)
        {
            let mut hash = hash;
            // "BBBCDDD" -> "BBBBCDDDD"
            hash.rle_block1[0] = 2;
            hash.rle_block1[1] = 6;
            hash_is_valid!(hash);
            // Now swap the order (making the RLE block invalid)
            hash.rle_block1[0] = 6;
            hash.rle_block1[1] = 2;
            hash_is_invalid!(hash);
        }
        // RLE Block: Must be sorted by position (block hash 2)
        {
            let mut hash = hash;
            // "EEEFGGG" -> "EEEEFGGGG"
            hash.rle_block2[0] = 2;
            hash.rle_block2[1] = 6;
            hash_is_valid!(hash);
            // Now swap the order (making the RLE block invalid)
            hash.rle_block2[0] = 6;
            hash.rle_block2[1] = 2;
            hash_is_invalid!(hash);
        }
        // RLE Block: Canonicality on extension using multiple RLE encodings (1)
        {
            assert_eq!(RleEncoding::BITS_POSITION, 6);
            assert_eq!(RleEncoding::MAX_RUN_LENGTH, 4);
            let mut hash = hash;
            // Extend five characters
            hash.rle_block1[0] = 0xc2; // RLE(2, 4)
            hash.rle_block1[1] = 0x02; // RLE(2, 1)
            hash_is_valid!(hash);
            // Non-canonical encodings
            hash.rle_block1[0] = 0x02; // RLE(2, 1)
            hash.rle_block1[1] = 0xc2; // RLE(2, 4)
            hash_is_invalid!(hash);
            hash.rle_block1[0] = 0x42; // RLE(2, 2)
            hash.rle_block1[1] = 0x82; // RLE(2, 3)
            hash_is_invalid!(hash);
            hash.rle_block1[0] = 0x82; // RLE(2, 3)
            hash.rle_block1[1] = 0x42; // RLE(2, 2)
            hash_is_invalid!(hash);
            // Back to valid one (rle_block1[1] does not have maximum length)
            hash.rle_block1[0] = 0xc2; // RLE(2, 4)
            hash.rle_block1[1] = 0x02; // RLE(2, 1)
            hash_is_valid!(hash);
            // Test extension with another position
            hash.rle_block1[2] = 0x06; // RLE(2, 1)
            hash_is_valid!(hash);
        }
        // RLE Block: Canonicality on extension using multiple RLE encodings (2)
        {
            assert_eq!(RleEncoding::BITS_POSITION, 6);
            assert_eq!(RleEncoding::MAX_RUN_LENGTH, 4);
            let mut hash = hash;
            // Extend five characters
            hash.rle_block2[0] = 0xc2; // RLE(2, 4)
            hash.rle_block2[1] = 0x02; // RLE(2, 1)
            hash_is_valid!(hash);
            // Non-canonical encodings
            hash.rle_block2[0] = 0x02; // RLE(2, 1)
            hash.rle_block2[1] = 0xc2; // RLE(2, 4)
            hash_is_invalid!(hash);
            hash.rle_block2[0] = 0x42; // RLE(2, 2)
            hash.rle_block2[1] = 0x82; // RLE(2, 3)
            hash_is_invalid!(hash);
            hash.rle_block2[0] = 0x82; // RLE(2, 3)
            hash.rle_block2[1] = 0x42; // RLE(2, 2)
            hash_is_invalid!(hash);
            // Back to valid one (rle_block2[1] does not have maximum length)
            hash.rle_block2[0] = 0xc2; // RLE(2, 4)
            hash.rle_block2[1] = 0x02; // RLE(2, 1)
            hash_is_valid!(hash);
            // Test extension with another position
            hash.rle_block2[2] = 0x06; // RLE(2, 1)
            hash_is_valid!(hash);
        }
        // RLE Block: Maximum extension exceeds maximum length on current config (1)
        {
            assert_eq!(RleEncoding::BITS_POSITION, 6);
            assert_eq!(RleEncoding::MAX_RUN_LENGTH, 4);
            let mut hash = hash;
            // On the current design, it exceeds maximum length by 7 (len_blockhash1).
            hash.rle_block1.fill(0xc2); // Fill with RLE(2, 4)
            hash_is_invalid!(hash); // +7
            // Decrease the trailing RLE block 7 times
            // (until the hash becomes valid).
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x82;
            hash_is_invalid!(hash); // +6
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x42;
            hash_is_invalid!(hash); // +5
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x02;
            hash_is_invalid!(hash); // +4
            hash.rle_block1[hash.rle_block1.len() - 1] = 0x00;
            hash.rle_block1[hash.rle_block1.len() - 2] = 0xc2;
            hash_is_invalid!(hash); // +3
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x82;
            hash_is_invalid!(hash); // +2
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x42;
            hash_is_invalid!(hash); // +1
            hash.rle_block1[hash.rle_block1.len() - 2] = 0x02;
            hash_is_valid!(hash); // +0
        }
        // RLE Block: Maximum extension exceeds maximum length on current config (2)
        {
            assert_eq!(RleEncoding::BITS_POSITION, 6);
            assert_eq!(RleEncoding::MAX_RUN_LENGTH, 4);
            let mut hash = hash;
            // On the current design, it exceeds maximum length by 7 (len_blockhash2).
            hash.rle_block2.fill(0xc2); // Fill with RLE(2, 4)
            hash_is_invalid!(hash); // +7
            // Decrease the trailing RLE block 7 times
            // (until the hash becomes valid).
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x82;
            hash_is_invalid!(hash); // +6
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x42;
            hash_is_invalid!(hash); // +5
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x02;
            hash_is_invalid!(hash); // +4
            hash.rle_block2[hash.rle_block2.len() - 1] = 0x00;
            hash.rle_block2[hash.rle_block2.len() - 2] = 0xc2;
            hash_is_invalid!(hash); // +3
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x82;
            hash_is_invalid!(hash); // +2
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x42;
            hash_is_invalid!(hash); // +1
            hash.rle_block2[hash.rle_block2.len() - 2] = 0x02;
            hash_is_valid!(hash); // +0
        }
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn test_example_long_and_short() {
    // Block hash 1: BlockHash::FULL_SIZE
    // Block hash 2: BlockHash::HALF_SIZE + 1 (will overflow on DualFuzzyHash)
    let hash_str = "3\
        :0123456789012345678901234567890123456789012345678901234567890123\
        :012345678901234567890123456789012";
    assert_eq!(
        DualFuzzyHash::from_str(hash_str),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 32))
    );
    assert!(LongDualFuzzyHash::from_str(hash_str).is_ok());
    // Block hash 1: BlockHash::FULL_SIZE
    // Block hash 2: BlockHash::FULL_SIZE + 1 (will also overflow on LongDualFuzzyHash)
    let hash_str = "3\
        :0123456789012345678901234567890123456789012345678901234567890123\
        :01234567890123456789012345678901234567890123456789012345678901234";
    assert_eq!(
        DualFuzzyHash::from_str(hash_str),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 32))
    );
    assert_eq!(
        LongDualFuzzyHash::from_str(hash_str),
        Err(ParseError(ParseErrorKind::BlockHashIsTooLong, ParseErrorOrigin::BlockHash2, 2 + 64 + 1 + 64))
    );
}

#[test]
fn test_parse_failure() {
    macro_rules! test {($ty: ty) => {
        assert_eq!(
            <$ty>::from_bytes(b""),
            Err(ParseError(ParseErrorKind::UnexpectedEndOfString, ParseErrorOrigin::BlockSize, 0))
        );
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[test]
fn test_parsed_block_size() {
    /*
        Tested methods:
        1. String Parser (only valid cases)
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
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}


#[test]
fn test_as_ref() {
    macro_rules! test {($ty: ty) => {
        type NormalizedType = FuzzyHashData<{<$ty>::MAX_BLOCK_HASH_SIZE_1}, {<$ty>::MAX_BLOCK_HASH_SIZE_2}, true>;
        let hash = <$ty>::new();
        let norm_hash_1: &NormalizedType = &hash.norm_hash;
        let norm_hash_2: &NormalizedType = hash.as_ref();
        let norm_hash_3: &NormalizedType = hash.as_ref_normalized();
        let p1 = norm_hash_1 as *const NormalizedType;
        let p2 = norm_hash_2 as *const NormalizedType;
        let p3 = norm_hash_3 as *const NormalizedType;
        assert_eq!(p1, p2);
        assert_eq!(p1, p3);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[cfg(feature = "std")]
#[test]
fn cover_hash() {
    macro_rules! test {($ty: ty) => {
        let mut hashes = std::collections::HashSet::<$ty>::new();
        assert!(hashes.insert(<$ty>::new()));
        assert!(!hashes.insert(<$ty>::new()));
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[cfg(feature = "std")]
#[test]
fn test_ord() {
    use core::cmp::Ordering;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::collections::HashSet;
    // Sorted by block hash order (Base64 indices and length).
    // Each internal vector indicates that they are equivalent
    // after performing normalization.
    // Note that 'A' has Base64 index zero and FuzzyHashData zero-fills
    // each tail of block hashes (making the behavior more deterministic).
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
            for bh_entry in bh {
                assert!(strings.insert(*bh_entry));
            }
        }
    }
    macro_rules! test {($ty: ty) => {
        // Construct sorted hashes list
        let mut hashes: Vec<$ty> = Vec::new();
        for i in 0u8..=2 {
            for bh1 in &sorted_dict {
                for bh2 in &sorted_dict {
                    for bh1_entry in bh1 {
                        for bh2_entry in bh2 {
                            let mut s = BlockSize::from_log_unchecked(i).to_string();
                            s += ":";
                            s += *bh1_entry;
                            s += ":";
                            s += *bh2_entry;
                            hashes.push(<$ty>::from_str(s.as_str()).unwrap());
                        }
                    }
                }
            }
        }
        // Test consistency between Vec order and comparison results
        for (i1, h1) in hashes.iter().enumerate() {
            for (i2, h2) in hashes.iter().enumerate() {
                match h1.as_ref_normalized().cmp(h2.as_ref_normalized()) {
                    Ordering::Equal => {
                        // Because "equal" elements (by normalized hashes) are
                        // surrounded by "lesser" elements and "greater" elements,
                        // they will make a consecutive "block".
                        // Just check whether direct comparison between h1 and h2
                        // can be used to determine whether the hashes are the same.
                        assert_eq!(h1.cmp(&h2) == Ordering::Equal, i1 == i2);
                    },
                    Ordering::Greater => {
                        // Make sure that the result is the same as direct comparison between h1 and h2.
                        assert_eq!(h1.cmp(&h2), Ordering::Greater);
                        // Check sorted indexes
                        assert!(i1 > i2);
                    },
                    Ordering::Less => {
                        // Make sure that the result is the same as direct comparison between h1 and h2.
                        assert_eq!(h1.cmp(&h2), Ordering::Less);
                        // Check sorted indexes
                        assert!(i1 < i2);
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
        assert_eq!(hashes, cloned);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[cfg(feature = "alloc")]
#[test]
fn test_debug() {
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
    let hash = DualFuzzyHash::from_str("3\
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
    let hash = DualFuzzyHash::from_str("3\
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
    let hash = LongDualFuzzyHash::from_str("3\
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
    let mut hash = DualFuzzyHash::from_str("3\
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
    let mut hash = DualFuzzyHash::from_str("3\
        :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        :BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    hash.rle_block1[15] = RleEncoding::encode(2, 4);
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

// Each block hash repeats 4 times (thus normalization causes block hash changes)
#[cfg(feature = "alloc")]
const TEST_VECTOR_SHORT_FHASH_NORM_0: &str = "6:11112222333344445555:aaaabbbbccccddddeeee";
// Each block hash repeats 3 times (normalization does not change the contents)
#[cfg(feature = "alloc")]
const TEST_VECTOR_SHORT_FHASH_NORM_1: &str = "6:111222333444555:aaabbbcccdddeee";

#[cfg(feature = "alloc")]
#[test]
fn test_display() {
    macro_rules! test {($ty: ty) => {
        let hash = <$ty>::from_str(TEST_VECTOR_SHORT_FHASH_NORM_0).unwrap();
        assert_eq!(
            format!("{}", hash),
            format!("{{{}|{}}}", TEST_VECTOR_SHORT_FHASH_NORM_1, TEST_VECTOR_SHORT_FHASH_NORM_0)
        );
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}

#[cfg(feature = "alloc")]
#[test]
fn test_to_string() {
    macro_rules! test {($ty: ty) => {
        let hash = <$ty>::from_str(TEST_VECTOR_SHORT_FHASH_NORM_0).unwrap();
        assert_eq!(hash.to_raw_form_string(), TEST_VECTOR_SHORT_FHASH_NORM_0);
        assert_eq!(hash.to_normalized_string(), TEST_VECTOR_SHORT_FHASH_NORM_1);
    }}
    test_for_each_type!(test, [DualFuzzyHash, LongDualFuzzyHash]);
}
