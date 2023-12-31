// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use crate::compare::FuzzyHashCompareTarget;
use crate::compare::position_array::{
    BlockHashPositionArray,
    BlockHashPositionArrayRef,
    BlockHashPositionArrayMutRef,
    BlockHashPositionArrayData,
    BlockHashPositionArrayImpl,
    BlockHashPositionArrayImplMut,
    BlockHashPositionArrayImplInternal,
    BlockHashPositionArrayImplMutInternal,
    block_hash_position_array_element,
};
#[cfg(feature = "unchecked")]
use crate::compare::position_array::BlockHashPositionArrayImplUnchecked;
use crate::hash::block::block_hash;
use crate::hash::test_utils::test_blockhash_content_all;
use crate::test_utils::test_recommended_default;
use crate::utils::u64_lsb_ones;


#[test]
fn test_has_sequences() {
    // All zero
    assert!(block_hash_position_array_element::has_sequences(0, 0));
    for len in 1u32..=100 {
        assert!(!block_hash_position_array_element::has_sequences(0, len),
            "failed on len={}", len);
    }
    // All one
    assert!(block_hash_position_array_element::has_sequences(u64::MAX, 0));
    for len in 1u32..=64 {
        assert!(block_hash_position_array_element::has_sequences(u64::MAX, len),
            "failed on len={}", len);
    }
    assert!(!block_hash_position_array_element::has_sequences(u64::MAX, 65));
    // Test pattern: stripes
    const STRIPE_1: u64 = 0b_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010_1010;
    const STRIPE_2: u64 = 0b_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101_0101;
    for stripe in [STRIPE_1, STRIPE_2] {
        assert_eq!(u64::MAX, stripe | stripe.rotate_left(1),
            "failed on stripe=0b{:064b}", stripe);
        assert_eq!(u64::MAX, stripe ^ stripe.rotate_left(1),
            "failed on stripe=0b{:064b}", stripe);
        assert_eq!(0, stripe & stripe.rotate_left(1),
            "failed on stripe=0b{:064b}", stripe);
    }
    for len in 0u32..=1 {
        assert!(block_hash_position_array_element::has_sequences(STRIPE_1, len),
            "failed on len={}", len);
        assert!(block_hash_position_array_element::has_sequences(STRIPE_2, len),
            "failed on len={}", len);
    }
    for len in 2u32..=100 {
        assert!(!block_hash_position_array_element::has_sequences(STRIPE_1, len),
            "failed on len={}", len);
        assert!(!block_hash_position_array_element::has_sequences(STRIPE_2, len),
            "failed on len={}", len);
    }
    // Test pattern: specific length (≧ 2) sequences
    for len in 2u32..=64 {
        let base = u64_lsb_ones(len);
        let mut aggr_bits: u64 = 0;
        for shift in 0..=(u64::BITS - len) {
            let seq = base << shift;
            aggr_bits |= seq;
            assert_eq!(seq >> shift, base,
                "failed on len={}, shift={}", len, shift);
            for test_len in 1u32..=100 {
                // Subpattern 1: pure bits
                let target = seq;
                assert_eq!(
                    block_hash_position_array_element::has_sequences(target, test_len),
                    test_len <= len,
                    "failed on len={}, shift={}", len, shift
                );
                // Subpattern 2 and 3: stripes
                for stripe in [STRIPE_1, STRIPE_2] {
                    let mut target = stripe;
                    target &= !(seq << 1);
                    target &= !(seq >> 1);
                    target |= seq;
                    if test_len < 2 {
                        // Matches to stripe itself
                        assert!(block_hash_position_array_element::has_sequences(target, test_len),
                            "failed on len={}, shift={}, stripe=0b{:064b}", len, shift, stripe);
                    }
                    else {
                        // Possibly matches to the sequence
                        assert_eq!(
                            block_hash_position_array_element::has_sequences(target, test_len),
                            test_len <= len,
                            "failed on len={}, shift={}, stripe=0b{:064b}", len, shift, stripe
                        );
                    }
                }
            }
        }
        // check whether the loop above touched all bits.
        assert_eq!(aggr_bits, u64::MAX, "failed on len={}", len);
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
            assert_eq!(has_seq, block_hash_position_array_element::has_sequences(target, len),
                "failed on len={}, offset={}", len, offset);
            if has_seq {
                for test_len in 0..len {
                    assert!(block_hash_position_array_element::has_sequences(target, test_len),
                        "failed on len={}, offset={}, test_len={}", len, offset, test_len);
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
                    assert_eq!(test_len <= max_seq_len, block_hash_position_array_element::has_sequences(target, test_len),
                        "failed on len={}, offset={}, test_len={}", len, offset, test_len);
                }
            }
            for test_len in (len + 1)..=100 {
                assert!(!block_hash_position_array_element::has_sequences(target, test_len),
                    "failed on len={}, offset={}, test_len={}", len, offset, test_len);
            }
        }
    }
}


#[test]
fn position_array_impls() {
    test_recommended_default!(BlockHashPositionArray);
}

#[test]
fn position_array_usage() {
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


/// Position array representation of the empty string.
pub(crate) const EXPECTED_DEBUG_REPR_EMPTY: &str = "[\
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
]";

/// Position array representation of `"AAABCDEFG"` (normalized).
pub(crate) const EXPECTED_DEBUG_REPR_NORMALIZED_1: &str = "[\
    7, 8, 16, 32, 64, 128, 256, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
]";  // 7 == 1 + 2 + 4

/// Position array representation of `"HIJKLMMM"` (normalized).
pub(crate) const EXPECTED_DEBUG_REPR_NORMALIZED_2: &str = "[\
    0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 224, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
]";  // 224 == 32 + 64 + 128

/// Position array representation of `"AAAABCDEFG"` (not normalized).
pub(crate) const EXPECTED_DEBUG_REPR_RAW_1: &str = "[\
    15, 16, 32, 64, 128, 256, 512, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
]";  // 15 == 1 + 2 + 4 + 8

/// Position array representation of `"HIJKLMMMM"` (not normalized).
pub(crate) const EXPECTED_DEBUG_REPR_RAW_2: &str = "[\
    0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 480, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\
]";  // 480 == 32 + 64 + 128 + 256

#[test]
fn position_array_impl_debug() {
    let mut pa = BlockHashPositionArray::new();
    assert_eq!(
        format!("{:?}", pa),
        format!("BlockHashPositionArray {{ \
            representation: {}, \
            len: 0 \
        }}", EXPECTED_DEBUG_REPR_EMPTY)
    );
    // Test "[BLOCKHASH]:AAABCDEFG:HIJKLMMM" (normalized)
    pa.init_from(&[0, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        format!("{:?}", pa),
        format!("BlockHashPositionArray {{ \
            representation: {}, \
            len: 9 \
        }}", EXPECTED_DEBUG_REPR_NORMALIZED_1)
    );  // 7 == 1 + 2 + 4
    pa.init_from(&[7, 8, 9, 10, 11, 12, 12, 12]);
    assert_eq!(
        format!("{:?}", pa),
        format!("BlockHashPositionArray {{ \
            representation: {}, \
            len: 8 \
        }}", EXPECTED_DEBUG_REPR_NORMALIZED_2)
    );  // 224 == 32 + 64 + 128
    // Test "[BLOCKHASH]:AAAABCDEFG:HIJKLMMMM" (not normalized)
    // BlockHashPositionArray itself does not do the normalization.
    pa.init_from(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        format!("{:?}", pa),
        format!("BlockHashPositionArray {{ \
            representation: {}, \
            len: 10 \
        }}", EXPECTED_DEBUG_REPR_RAW_1)
    );  // 15 == 1 + 2 + 4 + 8
    pa.init_from(&[7, 8, 9, 10, 11, 12, 12, 12, 12]);
    assert_eq!(
        format!("{:?}", pa),
        format!("BlockHashPositionArray {{ \
            representation: {}, \
            len: 9 \
        }}", EXPECTED_DEBUG_REPR_RAW_2)
    );  // 480 == 32 + 64 + 128 + 256
}


cfg_if::cfg_if! {
    if #[cfg(not(feature = "unchecked"))] {
        /// Composite trait for dynamic dispatching-based tests.
        trait CompositeImpl : BlockHashPositionArrayImpl + BlockHashPositionArrayImplInternal {}
        /// Auto implementation of [`CompositeImpl`].
        impl<T> CompositeImpl for T
        where
            T : BlockHashPositionArrayImpl + BlockHashPositionArrayImplInternal
        {}
    }
    else {
        /// Composite trait for dynamic dispatching-based tests.
        trait CompositeImpl : BlockHashPositionArrayImpl + BlockHashPositionArrayImplInternal + BlockHashPositionArrayImplUnchecked {}
        /// Auto implementation of [`CompositeImpl`].
        impl<T> CompositeImpl for T
        where
            T : BlockHashPositionArrayImpl + BlockHashPositionArrayImplInternal + BlockHashPositionArrayImplUnchecked
        {}
    }
}


/// Check one block hash with [`BlockHashPositionArray`] using `test_func`.
fn check_one_bhpa(bh: &[u8], test_func: &mut dyn FnMut(&dyn CompositeImpl)) {
    let mut value = BlockHashPositionArray::new();
    value.init_from(bh);
    test_func(&value);
}

/// Check one block hash with [`BlockHashPositionArrayRef`] using `test_func`.
fn check_one_bhpa_ref(bh: &[u8], test_func: &mut dyn FnMut(&dyn CompositeImpl)) {
    let mut value = BlockHashPositionArray::new();
    value.init_from(bh);
    let value_ref = BlockHashPositionArrayRef(&value.representation, &value.len);
    test_func(&value_ref);
}

/// Check one block hash with [`BlockHashPositionArrayMutRef`] using `test_func`.
fn check_one_bhpa_mut_ref(bh: &[u8], test_func: &mut dyn FnMut(&dyn CompositeImpl)) {
    let mut value = BlockHashPositionArray::new();
    value.init_from(bh);
    let value_ref = BlockHashPositionArrayMutRef(&mut value.representation, &mut value.len);
    test_func(&value_ref);
}


fn check_data_model_basic(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    // Test block hash contents
    test_blockhash_content_all(&mut |bh, bh_norm| {
        let is_already_normalized = bh == bh_norm;
        /*
            Basic operations, validness and normalization:
            *   is_empty
            *   is_valid
            *   is_valid_and_normalized
            *   is_equiv (compare with itself and non-normalized form)
            *   is_equiv_internal  (likewise)
            *   is_equiv_unchecked (likewise)
        */
        // Initialize with not normalized block hash.
        wrapper(bh, &mut |value| {
            assert_eq!(value.is_empty(), bh.is_empty(), "failed on bh={:?}", bh);
            assert!(value.is_valid(), "failed on bh={:?}", bh);
            assert!(value.is_equiv(bh), "failed on bh={:?}", bh);
            assert!(value.is_equiv_internal(bh), "failed on bh={:?}", bh);
            assert_eq!(value.is_valid_and_normalized(), is_already_normalized, "failed on bh={:?}", bh);
            #[cfg(feature = "unchecked")]
            unsafe {
                assert!(value.is_equiv_unchecked(bh), "failed on bh={:?}", bh);
            }
        });
        // Initialize with normalized block hash.
        wrapper(bh_norm, &mut |value| {
            assert_eq!(value.is_empty(), bh_norm.is_empty(), "failed on bh={:?}", bh);
            assert!(value.is_valid(), "failed on bh={:?}", bh);
            assert!(value.is_equiv(bh_norm), "failed on bh={:?}", bh);
            assert!(value.is_equiv_internal(bh_norm), "failed on bh={:?}", bh);
            assert!(value.is_valid_and_normalized(), "failed on bh={:?}", bh);
            assert_eq!(value.is_equiv(bh), is_already_normalized, "failed on bh={:?}", bh);
            assert_eq!(value.is_equiv_internal(bh), is_already_normalized, "failed on bh={:?}", bh);
            #[cfg(feature = "unchecked")]
            unsafe {
                assert!(value.is_equiv_unchecked(bh_norm), "failed on bh={:?}", bh);
                assert_eq!(value.is_equiv_unchecked(bh), is_already_normalized, "failed on bh={:?}", bh);
            }
        });
    });
}

#[test]
fn data_model_basic_bhpa() {
    check_data_model_basic(&mut check_one_bhpa);
}
#[test]
fn data_model_basic_bhpa_ref() {
    check_data_model_basic(&mut check_one_bhpa_ref);
}
#[test]
fn data_model_basic_bhpa_mut_ref() {
    check_data_model_basic(&mut check_one_bhpa_mut_ref);
}


fn check_data_model_inequality(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    // Prerequisite for inequality test:
    assert_eq!(block_hash::ALPHABET_SIZE % 2, 0);
    // Test inequality
    test_blockhash_content_all(&mut |bh, bh_norm| {
        /*
            Inequality (compare with different string):
            *   is_equiv
            *   is_equiv_internal
            *   is_equiv_unchecked
        */
        let mut test = |bh: &[u8]| {
            wrapper(bh, &mut |value: &dyn CompositeImpl| {
                if bh.is_empty() { return; }
                let mut bh_mod = [0u8; block_hash::FULL_SIZE];
                let bh_mod = bh_mod[0..bh.len()].as_mut();
                bh_mod.copy_from_slice(bh);
                for i in 0..bh.len() {
                    // Modify the original block hash.
                    bh_mod[i] ^= 1; // requires that ALPHABET_SIZE is an even number.
                    assert!(!value.is_equiv(bh_mod), "failed on bh={:?}, i={}", bh, i);
                    assert!(!value.is_equiv_internal(bh_mod), "failed on bh={:?}, i={}", bh, i);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert!(!value.is_equiv_unchecked(bh_mod), "failed on bh={:?}, i={}", bh, i);
                    }
                    // Change back to the original.
                    bh_mod[i] ^= 1;
                    assert!(value.is_equiv_internal(bh_mod), "failed on bh={:?}, i={}", bh, i);
                }
            });
        };
        test(bh);
        test(bh_norm);
    });
}

#[test]
fn data_model_inequality_bhpa() {
    check_data_model_inequality(&mut check_one_bhpa);
}
#[test]
fn data_model_inequality_bhpa_ref() {
    check_data_model_inequality(&mut check_one_bhpa_ref);
}
#[test]
fn data_model_inequality_bhpa_mut_ref() {
    check_data_model_inequality(&mut check_one_bhpa_mut_ref);
}


fn check_substring_itself(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    test_blockhash_content_all(&mut |bh, bh_norm| {
        /*
            Substring (check with itself and subsets):
            *   has_common_substring
            *   has_common_substring_internal
            *   has_common_substring_unchecked
        */
        let mut test = |bh: &[u8]| {
            wrapper(bh, &mut |value: &dyn CompositeImpl| {
                // False if another string is too short.
                for len in 1..block_hash::MIN_LCS_FOR_COMPARISON {
                    for window in bh.windows(len) {
                        assert!(!value.has_common_substring(window),
                            "failed on bh={:?}, window={:?}", bh, window);
                        assert!(!value.has_common_substring_internal(window),
                            "failed on bh={:?}, window={:?}", bh, window);
                        #[cfg(feature = "unchecked")]
                        unsafe {
                            assert!(!value.has_common_substring_unchecked(window),
                                "failed on bh={:?}, window={:?}", bh, window);
                        }
                    }
                }
                // True if another string is a subset with enough length.
                for len in block_hash::MIN_LCS_FOR_COMPARISON..=bh.len() {
                    for window in bh.windows(len) {
                        assert!(value.has_common_substring(window),
                            "failed on bh={:?}, window={:?}", bh, window);
                        assert!(value.has_common_substring_internal(window),
                            "failed on bh={:?}, window={:?}", bh, window);
                        #[cfg(feature = "unchecked")]
                        unsafe {
                            assert!(value.has_common_substring_unchecked(window),
                                "failed on bh={:?}, window={:?}", bh, window);
                        }
                    }
                }
            });
        };
        test(bh);
        test(bh_norm);
    });
}

#[test]
fn substring_itself_bhpa() {
    check_substring_itself(&mut check_one_bhpa);
}
#[test]
fn substring_itself_bhpa_ref() {
    check_substring_itself(&mut check_one_bhpa_ref);
}
#[test]
fn substring_itself_bhpa_mut_ref() {
    check_substring_itself(&mut check_one_bhpa_mut_ref);
}


fn check_substring_fail_example(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    /*
        Substring (check with the "no match" example):
        *   has_common_substring
        *   has_common_substring_internal
        *   has_common_substring_unchecked
    */
    const STR1: &[u8] = &[0, 1, 2, 3, 4, 5, 6];
    const STR2: &[u8] = &[6, 5, 4, 3, 2, 1, 0];
    /*
        Prerequisites:
        1.  They must have the size of block_hash::MIN_LCS_FOR_COMPARISON
            (for minimum example required for branch coverage)
        2.  They must be different (has_common_substring must return false)
        3.  They must share the alphabets
            (for better branch coverage)
    */
    assert!(STR1.len() == block_hash::MIN_LCS_FOR_COMPARISON);
    assert!(STR2.len() == block_hash::MIN_LCS_FOR_COMPARISON);
    assert_ne!(STR1, STR2);
    #[cfg(feature = "std")]
    {
        let alphabets =
            std::collections::HashSet::<u8>::from_iter(STR1.iter().cloned());
        assert!(STR2.iter().all(|x| alphabets.contains(x)));
    }
    // Test has_common_substring failure
    wrapper(STR1, &mut |value: &dyn CompositeImpl| {
        assert!(!value.has_common_substring(STR2));
        assert!(!value.has_common_substring_internal(STR2));
        #[cfg(feature = "unchecked")]
        unsafe {
            assert!(!value.has_common_substring_unchecked(STR2));
        }
    });
}

#[test]
fn substring_fail_example_bhpa() {
    check_substring_fail_example(&mut check_one_bhpa);
}
#[test]
fn substring_fail_example_bhpa_ref() {
    check_substring_fail_example(&mut check_one_bhpa_ref);
}
#[test]
fn substring_fail_example_bhpa_mut_ref() {
    check_substring_fail_example(&mut check_one_bhpa_mut_ref);
}


fn check_edit_distance_itself(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    test_blockhash_content_all(&mut |bh, bh_norm| {
        /*
            Edit_distance (itself):
            *   edit_distance
            *   edit_distance_internal
            *   edit_distance_unchecked
        */
        let mut test = |bh: &[u8]| {
            wrapper(bh, &mut |value: &dyn CompositeImpl| {
                // Compare with itself.
                assert_eq!(value.edit_distance(bh), 0, "failed on bh={:?}", bh);
                assert_eq!(value.edit_distance_internal(bh), 0, "failed on bh={:?}", bh);
                #[cfg(feature = "unchecked")]
                unsafe {
                    assert_eq!(value.edit_distance_unchecked(bh), 0, "failed on bh={:?}", bh);
                }
            });
        };
        test(bh);
        test(bh_norm);
    });
}

#[test]
fn edit_distance_itself_bhpa() {
    check_edit_distance_itself(&mut check_one_bhpa);
}
#[test]
fn edit_distance_itself_bhpa_ref() {
    check_edit_distance_itself(&mut check_one_bhpa_ref);
}
#[test]
fn edit_distance_itself_bhpa_mut_ref() {
    check_edit_distance_itself(&mut check_one_bhpa_mut_ref);
}


fn check_scoring_with_itself(wrapper: &mut impl FnMut(&[u8], &mut dyn FnMut(&dyn CompositeImpl))) {
    test_blockhash_content_all(&mut |_bh, bh_norm| {
        /*
            Scoring (with itself):
            *   score_strings_raw
            *   score_strings_raw_internal
            *   score_strings_raw_unchecked

            Note: raw similarity score with itself should always return 100
            unless the block hash is too small (in this case, it should be 0).
        */
        wrapper(bh_norm, &mut |value| {
            let len_norm = u8::try_from(bh_norm.len()).unwrap();
            let expected_score = if bh_norm.len() >= block_hash::MIN_LCS_FOR_COMPARISON { 100 } else { 0 };
            assert_eq!(value.score_strings_raw(bh_norm), expected_score,
                "failed on bh_norm={:?}", bh_norm);
            assert_eq!(value.score_strings_raw_internal(bh_norm), expected_score,
                "failed on bh_norm={:?}", bh_norm);
            #[cfg(feature = "unchecked")]
            unsafe {
                assert_eq!(value.score_strings_raw_unchecked(bh_norm), expected_score,
                    "failed on bh_norm={:?}", bh_norm);
            }
            assert_eq!(
                value.score_strings(bh_norm, FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER),
                expected_score,
                "failed on bh_norm={:?}", bh_norm
            );
            // Test with score capping
            if bh_norm.len() >= block_hash::MIN_LCS_FOR_COMPARISON {
                for log_block_size in 0..FuzzyHashCompareTarget::LOG_BLOCK_SIZE_CAPPING_BORDER {
                    let score_cap = FuzzyHashCompareTarget::score_cap_on_block_hash_comparison_internal(
                        log_block_size,
                        len_norm,
                        len_norm
                    ).min(100);
                    let capped_score = expected_score.min(score_cap);
                    assert_eq!(value.score_strings(bh_norm, log_block_size), capped_score,
                        "failed on bh_norm={:?}, log_block_size={}", bh_norm, log_block_size);
                    assert_eq!(value.score_strings_internal(bh_norm, log_block_size), capped_score,
                        "failed on bh_norm={:?}, log_block_size={}", bh_norm, log_block_size);
                    #[cfg(feature = "unchecked")]
                    unsafe {
                        assert_eq!(value.score_strings_unchecked(bh_norm, log_block_size), capped_score,
                            "failed on bh_norm={:?}, log_block_size={}", bh_norm, log_block_size);
                    }
                }
            }
        });
    });
}

#[test]
fn scoring_with_itself_bhpa() {
    check_scoring_with_itself(&mut check_one_bhpa);
}
#[test]
fn scoring_with_itself_bhpa_ref() {
    check_scoring_with_itself(&mut check_one_bhpa_ref);
}
#[test]
fn scoring_with_itself_bhpa_mut_ref() {
    check_scoring_with_itself(&mut check_one_bhpa_mut_ref);
}


fn check_data_model_corruption<T>(value: &mut T)
where
    T: BlockHashPositionArrayImplMut + BlockHashPositionArrayImplMutInternal
{
    // Prerequisites
    assert_eq!(block_hash::FULL_SIZE, 64);
    assert_eq!(block_hash::ALPHABET_SIZE, 64);
    // Not Corrupted
    {
        value.clear();
        assert!(value.is_valid());
        assert!(value.is_valid_and_normalized());
    }
    // Block hash length (and some of its contents)
    {
        value.clear();
        assert!(value.is_valid());
        assert!(value.is_valid_and_normalized());
        // Just changing the length will make this invalid
        // because there's "no character" at position 0.
        for len in 1..=u8::MAX {
            *value.len_mut() = len;
            assert!(!value.is_valid(),
                "failed on len={}", len);
            assert!(!value.is_valid_and_normalized(),
                "failed on len={}", len);
        }
        // Setting same character sequence with matching length will make this valid.
        for len in 1u8..=64 {
            let target_value = u64_lsb_ones(len as u32);
            *value.len_mut() = len;
            for i in 0..(*value.representation_mut()).len() {
                (*value.representation_mut())[i] = target_value;
                assert!(value.is_valid(),
                    "failed on len={}, i={}", len, i);
                assert_eq!(value.is_valid_and_normalized(), (len as usize) <= block_hash::MAX_SEQUENCE_SIZE,
                    "failed on len={}, i={}", len, i);
                (*value.representation_mut())[i] = 0;
                assert!(!value.is_valid(),
                    "failed on len={}, i={}", len, i);
                assert!(!value.is_valid_and_normalized(),
                    "failed on len={}, i={}", len, i);
            }
        }
        *value.len_mut() = 64;
        (*value.representation_mut())[0] = u64::MAX;
        assert!(value.is_valid());
        assert!(!value.is_valid_and_normalized());
        for len in (64 + 1)..=u8::MAX {
            *value.len_mut() = len;
            assert!(!value.is_valid(),
                "failed on len={}", len);
            assert!(!value.is_valid_and_normalized(),
                "failed on len={}", len);
        }
    }
    // Block hash contents (outside the valid hash)
    {
        for len in 0..=block_hash::FULL_SIZE {
            value.clear();
            assert!(value.is_valid(),
                "failed on len={}", len);
            assert!(value.is_valid_and_normalized(),
                "failed on len={}", len);
            for i in 0..len {
                (*value.representation_mut())[i] = 1 << i;
            }
            *value.len_mut() = len as u8;
            assert!(value.is_valid(),
                "failed on len={}", len);
            assert!(value.is_valid_and_normalized(),
                "failed on len={}", len);
            for invalid_pos in (len as u32)..u64::BITS {
                let bitpos = 1u64 << invalid_pos;
                for ch in 0..(*value.representation_mut()).len() {
                    (*value.representation_mut())[ch] |= bitpos;
                    assert!(!value.is_valid(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    assert!(!value.is_valid_and_normalized(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    (*value.representation_mut())[ch] &= !bitpos;
                    assert!(value.is_valid(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    assert!(value.is_valid_and_normalized(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                }
            }
        }
    }
    // Block hash contents (inside the valid hash)
    {
        for len in 0..=block_hash::FULL_SIZE {
            value.clear();
            assert!(value.is_valid(),
                "failed on len={}", len);
            assert!(value.is_valid_and_normalized(),
                "failed on len={}", len);
            for i in 0..len {
                (*value.representation_mut())[i] = 1 << i;
            }
            *value.len_mut() = len as u8;
            assert!(value.is_valid(),
                "failed on len={}", len);
            assert!(value.is_valid_and_normalized(),
                "failed on len={}", len);
            // If the position array either:
            // *   have "duplicate characters" in some position or
            // *   have "no characters" in some position,
            // it is invalid.
            for invalid_pos in 0..len {
                let bitpos = 1u64 << (invalid_pos as u32);
                for ch in 0..(*value.representation_mut()).len() {
                    (*value.representation_mut())[ch] ^= bitpos;
                    assert!(!value.is_valid(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    assert!(!value.is_valid_and_normalized(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    (*value.representation_mut())[ch] ^= bitpos;
                    assert!(value.is_valid(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                    assert!(value.is_valid_and_normalized(),
                        "failed on len={}, invalid_pos={}, ch={}", len, invalid_pos, ch);
                }
            }
        }
    }
}

#[test]
fn data_model_corruption_bhpa() {
    let mut pa = BlockHashPositionArray::new();
    assert!(pa.is_valid());
    check_data_model_corruption(&mut pa);
}

#[test]
fn data_model_corruption_bhpa_mut_ref() {
    let mut representation = [0; block_hash::ALPHABET_SIZE];
    let mut len = 0;
    let mut pa = BlockHashPositionArrayMutRef(&mut representation, &mut len);
    assert!(pa.is_valid());
    check_data_model_corruption(&mut pa);
}


fn has_common_substring_naive(
    str1: &[u8],
    str2: &[u8]
) -> bool
{
    use std::collections::HashSet;
    const TARGET_LEN: usize = block_hash::MIN_LCS_FOR_COMPARISON;
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

#[test]
fn test_has_common_substring_naive() {
    // Prerequisites
    assert_eq!(block_hash::MIN_LCS_FOR_COMPARISON, 7);
    // Basic tests
    assert!(!has_common_substring_naive(b"", b""));
    assert!(!has_common_substring_naive(b"ABCDEF", b"ABCDEF"));
    // Common substring: "ABCDEFG"
    assert!(has_common_substring_naive(b"ABCDEFG", b"ABCDEFG"));
    // Common substring: "ABCDEFG"
    assert!(has_common_substring_naive(b"00000ABCDEFG", b"ABCDEFG11111"));
    // From an example of block_hash::MIN_LCS_FOR_COMPARISON.
    assert!(has_common_substring_naive(b"+r/kcOpEYXB+0ZJ", b"7ocOpEYXB+0ZF29"));
    // Corrupt an example above (NOT to match).
    assert!(!has_common_substring_naive(b"+r/kcOpEYXX+0ZJ", b"7ocOpEYXB+0ZF29"));
}

#[cfg(feature = "tests-slow")]
#[test]
fn verify_has_common_substring_by_real_blockhash_vectors() {
    use core::str::FromStr;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::vec::Vec;
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
                pa.has_common_substring(bh2.as_slice()),
                "failed on bh1={:?}, bh2={:?}", bh1, bh2
            );
        }
    }
}

#[cfg(feature = "tests-slow")]
#[test]
fn verify_edit_distance_by_real_blockhash_vectors() {
    use core::str::FromStr;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::vec::Vec;
    use crate::compare::position_array::{BlockHashPositionArray, BlockHashPositionArrayImpl};
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
            // Make position array (blockhash1) from given block hash (bh1).
            pa.init_from(bh1.as_slice());
            let dist_from_dp_impl =
                crate::compare::test_utils::edit_distn(bh1.as_slice(), bh2.as_slice()) as u32;
            let dist_from_fast_impl = pa.edit_distance(bh2.as_slice());
            // Test whether the results of a port of old implementation
            // and the fast implementation matches.
            assert_eq!(dist_from_dp_impl, dist_from_fast_impl,
                "failed on bh1={:?}, bh2={:?}", bh1, bh2);
        }
    }
}
