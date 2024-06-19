// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-tests-start

use crate::hash::block::block_hash;

fn test_blockhash_content_no_sequences(variant: bool, test_func: &mut impl FnMut(&[u8], &[u8])) {
    for len in 0..=block_hash::FULL_SIZE {
        let mut bh = [0u8; block_hash::FULL_SIZE];
        for (i, ch) in bh[..len].iter_mut().enumerate() {
            *ch = (if !variant {
                i
            } else {
                block_hash::ALPHABET_SIZE - 1 - i
            }) as u8;
        }
        test_func(&bh[0..len], &bh[0..len]);
    }
}

pub(crate) fn test_blockhash_contents_no_sequences(
    test_func: &mut impl FnMut(&[u8], &[u8], &[u8], &[u8]),
) {
    // Generated block hashes:
    // 1.  "A", "AB", "ABC",... "ABCDEFG..."... (forward from the first Base64 alphabet)
    // 2.  "/", "/+", "/+9",... "/+98765..."... (backward from the last Base64 alphabet)
    test_blockhash_content_no_sequences(false, &mut |bh1, bh1_norm| {
        test_blockhash_content_no_sequences(true, &mut |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

fn test_blockhash_content_one_sequence(filler: u8, test_func: &mut impl FnMut(&[u8], &[u8])) {
    for len in 0..=block_hash::FULL_SIZE {
        let len_norm = usize::min(len, block_hash::MAX_SEQUENCE_SIZE);
        let mut bh = [0u8; block_hash::FULL_SIZE];
        let mut bh_norm = [0u8; block_hash::FULL_SIZE];
        bh[0..len].fill(filler);
        bh_norm[0..len_norm].fill(filler);
        test_func(&bh[0..len], &bh_norm[0..len_norm]);
    }
}

fn test_blockhash_contents_one_sequence(test_func: &mut impl FnMut(&[u8], &[u8], &[u8], &[u8])) {
    // Generated block hashes:
    // 1.  "B", "BB", "BBB",...
    // 2.  "C", "CC", "CCC",...
    test_blockhash_content_one_sequence(1u8, &mut |bh1, bh1_norm| {
        test_blockhash_content_one_sequence(2u8, &mut |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

fn test_blockhash_content_division(
    len: usize,
    variant: bool,
    test_func: &mut impl FnMut(&[u8], &[u8]),
) {
    assert!(len <= block_hash::FULL_SIZE);
    let sz = len as u32;
    for div in 1..=sz {
        let mut bh = [0u8; block_hash::FULL_SIZE];
        let mut bh_norm = [0u8; block_hash::FULL_SIZE];
        let mut bh_len_norm = 0usize;
        for i in 0..div {
            let i0 = (i * sz / div) as usize;
            let i1 = ((i + 1) * sz / div) as usize;
            let seq_len_norm = usize::min(i1 - i0, block_hash::MAX_SEQUENCE_SIZE);
            let fill_ch = (if !variant {
                i
            } else {
                (block_hash::ALPHABET_SIZE as u32) - 1 - i
            }) as u8;
            bh[i0..i1].fill(fill_ch);
            bh_norm[bh_len_norm..bh_len_norm + seq_len_norm].fill(fill_ch);
            bh_len_norm += seq_len_norm;
        }
        test_func(&bh[0..len], &bh_norm[0..bh_len_norm]);
    }
}

fn test_blockhash_contents_division(
    max_bh2: usize,
    test_func: &mut impl FnMut(&[u8], &[u8], &[u8], &[u8]),
) {
    // Generated block hashes:
    // 1.  "AAA...AAA", "AAA...BBB", "AAA...BBB...CCC",... "ABC...9+/"
    //     (divide the block hash quasi-equally to N sequences)
    // 2.  "///...///", "///...+++", "///...+++...999",... "/+9876..."
    //     (likewise but from the last Base64 character and with variable length
    //      [either HALF_SIZE or FULL_SIZE])
    test_blockhash_content_division(block_hash::FULL_SIZE, false, &mut |bh1, bh1_norm| {
        test_blockhash_content_division(max_bh2, true, &mut |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

pub(crate) fn test_blockhash_contents_all(test_func: &mut impl FnMut(&[u8], &[u8], &[u8], &[u8])) {
    test_blockhash_contents_no_sequences(test_func);
    test_blockhash_contents_one_sequence(test_func);
    test_blockhash_contents_division(block_hash::FULL_SIZE, test_func);
    test_blockhash_contents_division(block_hash::HALF_SIZE, test_func);
}

pub(crate) fn test_blockhash_content_all(test_func: &mut impl FnMut(&[u8], &[u8])) {
    test_blockhash_content_no_sequences(false, test_func);
    test_blockhash_content_one_sequence(1u8, test_func);
    test_blockhash_content_division(block_hash::FULL_SIZE, false, test_func);
    test_blockhash_content_division(block_hash::HALF_SIZE, false, test_func);
}
