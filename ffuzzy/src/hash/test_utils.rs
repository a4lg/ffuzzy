// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

use crate::hash::block::block_hash;


const NUM_SLOW_SEQUENCES: usize = 4;

#[test]
fn test_common_prerequisites() {
    // Generic requirements
    assert!(block_hash::ALPHABET_SIZE <= block_hash::FULL_SIZE);
    // test_blockhash_content_multiple_sequences
    assert!(block_hash::ALPHABET_SIZE > NUM_SLOW_SEQUENCES);
}


fn test_blockhash_content_no_sequences(variant: bool, test_func: impl Fn(&[u8], &[u8])) {
    for len in 0..=block_hash::FULL_SIZE {
        let mut bh = [0u8; block_hash::FULL_SIZE];
        for (i, ch) in bh[..len].iter_mut().enumerate() {
            *ch = (if !variant { i } else { block_hash::ALPHABET_SIZE - 1 - i }) as u8;
        }
        test_func(&bh[0..len], &bh[0..len]);
    }
}

pub(crate) fn test_blockhash_contents_no_sequences(test_func: impl Fn(&[u8], &[u8], &[u8], &[u8])) {
    // Generated block hashes:
    // 1.  "A", "AB", "ABC",... "ABCDEFG..."... (forward from the first Base64 alphabet)
    // 2.  "/", "/+", "/+9",... "/+98765..."... (backward from the last Base64 alphabet)
    test_blockhash_content_no_sequences(false, |bh1, bh1_norm| {
        test_blockhash_content_no_sequences(true, |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

fn test_blockhash_content_one_sequence(filler: u8, test_func: impl Fn(&[u8], &[u8])) {
    for len in 0..=block_hash::FULL_SIZE {
        let len_norm = usize::min(len, block_hash::MAX_SEQUENCE_SIZE);
        let mut bh = [0u8; block_hash::FULL_SIZE];
        let mut bh_norm = [0u8; block_hash::FULL_SIZE];
        bh[0..len].fill(filler);
        bh_norm[0..len_norm].fill(filler);
        test_func(&bh[0..len], &bh_norm[0..len_norm]);
    }
}

fn test_blockhash_contents_one_sequence(test_func: impl Fn(&[u8], &[u8], &[u8], &[u8])) {
    // Generated block hashes:
    // 1.  "B", "BB", "BBB",...
    // 2.  "C", "CC", "CCC",...
    test_blockhash_content_one_sequence(1u8, |bh1, bh1_norm| {
        test_blockhash_content_one_sequence(2u8, |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

fn test_blockhash_content_division(len: usize, variant: bool, test_func: impl Fn(&[u8], &[u8])) {
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
            let fill_ch = (if !variant { i } else { (block_hash::ALPHABET_SIZE as u32) - 1 - i }) as u8;
            bh[i0..i1].fill(fill_ch);
            bh_norm[bh_len_norm..bh_len_norm+seq_len_norm].fill(fill_ch);
            bh_len_norm += seq_len_norm;
        }
        test_func(&bh[0..len], &bh_norm[0..bh_len_norm]);
    }
}

fn test_blockhash_contents_division(max_bh2: usize, test_func: impl Fn(&[u8], &[u8], &[u8], &[u8])) {
    // Generated block hashes:
    // 1.  "AAA...AAA", "AAA...BBB", "AAA...BBB...CCC",... "ABC...9+/"
    //     (divide the block hash quasi-equally to N sequences)
    // 2.  "///...///", "///...+++", "///...+++...999",... "/+9876..."
    //     (likewise but from the last Base64 character and with variable length
    //      [either HALF_SIZE or FULL_SIZE])
    test_blockhash_content_division(block_hash::FULL_SIZE, false, |bh1, bh1_norm| {
        test_blockhash_content_division(max_bh2, true, |bh2, bh2_norm| {
            test_func(bh1, bh2, bh1_norm, bh2_norm);
        });
    });
}

#[cfg(feature = "tests-slow")]
fn test_blockhash_content_multiple_sequences(test_func: impl Fn(&[u8], &[u8])) {
    // Generated sequences of block hash:
    // "BCDE", "BCDEE",... "BCDDE", "BCDDEE",... "BBB...BCDE"
    // ("B" * l1 :: "C" * l2 :: "D" * l3 :: "E" * l4 for l1..l4 > 0 and sum(l1..l4) <= FULL_SIZE)
    const NUM_SEQUENCES: usize = NUM_SLOW_SEQUENCES;
    for l1 in 1..=(block_hash::FULL_SIZE - (NUM_SEQUENCES - 1)) {
        let s1 = usize::min(l1, block_hash::MAX_SEQUENCE_SIZE);
        let total = l1;
        for l2 in 1..=(block_hash::FULL_SIZE - total - (NUM_SEQUENCES - 2)) {
            let s2 = usize::min(l2, block_hash::MAX_SEQUENCE_SIZE);
            let total = total + l2;
            for l3 in 1..=(block_hash::FULL_SIZE - total - (NUM_SEQUENCES - 3)) {
                let s3 = usize::min(l3, block_hash::MAX_SEQUENCE_SIZE);
                let total = total + l3;
                for l4 in 1..=(block_hash::FULL_SIZE - total - (NUM_SEQUENCES - 4)) {
                    let s4 = usize::min(l4, block_hash::MAX_SEQUENCE_SIZE);
                    let total = total + l4;
                    // Make raw four sequences
                    let mut seq = [0u8; block_hash::FULL_SIZE];
                    seq[0..l1].fill(1);
                    seq[l1..l1+l2].fill(2);
                    seq[l1+l2..l1+l2+l3].fill(3);
                    seq[l1+l2+l3..l1+l2+l3+l4].fill(4);
                    // Make normalized four sequences
                    let mut seq_norm = [0u8; block_hash::FULL_SIZE];
                    let total_norm = s1 + s2 + s3 + s4;
                    seq_norm[0..s1].fill(1);
                    seq_norm[s1..s1+s2].fill(2);
                    seq_norm[s1+s2..s1+s2+s3].fill(3);
                    seq_norm[s1+s2+s3..s1+s2+s3+s4].fill(4);
                    test_func(&seq[0..total], &seq_norm[0..total_norm]);
                }
            }
        }
    }
}

#[cfg(feature = "tests-slow")]
fn test_blockhash_contents_multiple_sequences(test_func: impl Fn(&[u8], &[u8], &[u8], &[u8])) {
    // Because arbitrary division takes some time, we use single loop
    // (unlike double loop on others)
    test_blockhash_content_multiple_sequences(|bh, bh_norm| {
        test_func(bh, &[], bh_norm, &[]);
        test_func(&[], bh, &[], bh_norm);
    });
}


pub(crate) fn test_blockhash_contents_all(test_func: &impl Fn(&[u8], &[u8], &[u8], &[u8])) {
    test_blockhash_contents_no_sequences(test_func);
    test_blockhash_contents_one_sequence(test_func);
    test_blockhash_contents_division(block_hash::FULL_SIZE, test_func);
    test_blockhash_contents_division(block_hash::HALF_SIZE, test_func);
    #[cfg(feature = "tests-slow")]
    {
        test_blockhash_contents_multiple_sequences(test_func);
    }
}

pub(crate) fn test_blockhash_content_all(test_func: &impl Fn(&[u8], &[u8])) {
    test_blockhash_content_no_sequences(false, test_func);
    test_blockhash_content_one_sequence(1u8, test_func);
    test_blockhash_content_division(block_hash::FULL_SIZE, false, test_func);
    test_blockhash_content_division(block_hash::HALF_SIZE, false, test_func);
    #[cfg(feature = "tests-slow")]
    {
        test_blockhash_content_multiple_sequences(test_func);
    }
}
