// SPDX-License-Identifier: BSL-1.0 OR GPL-2.0-only OR GPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2014 kikairoya <kikairoya@gmail.com>
// SPDX-FileCopyrightText: Copyright (C) 2014 Jesse Kornblum <research@jessekornblum.com>
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>
#![cfg(any(all(test, feature = "tests-slow"), doc))]

/// Computes the edit distance between two given strings.
///
/// Both `s1` and `s2` are [`slice`]s of [`u8`].
///
/// Specifically, it computes the Longest Common Subsequence (LCS)
/// distance, allowing character insertion and deletion as two primitive
/// operations (in cost 1).
///
/// This is a port of the `edit_distn` function
/// from libfuzzy's `edit_dist.c`.
#[allow(dead_code)]
pub(crate) fn edit_distn(s1: &[u8], s2: &[u8]) -> usize {
    let mut t1 = std::vec::Vec::from_iter((0usize..).take(s2.len() + 1));
    let mut t2 = std::vec::Vec::from_iter(core::iter::repeat(0usize).take(s2.len() + 1));
    for (i1, s1ch) in s1.iter().enumerate() {
        t2[0] = i1 + 1;
        for (i2, s2ch) in s2.iter().enumerate() {
            // Costs of character addition and deletion
            let cost_a = t2[i2] + 1;
            let cost_d = t1[i2 + 1] + 1;
            // Replacement cost below: 2 for LCS distance, 1 for Levenshtein distance
            let cost_r = t1[i2] + if *s1ch == *s2ch { 0 } else { 2 };
            t2[i2 + 1] = usize::min(usize::min(cost_a, cost_d), cost_r);
        }
        core::mem::swap(&mut t1, &mut t2);
    }
    t1[s2.len()]
}
