// SPDX-License-Identifier: BSL-1.0 OR GPL-2.0-only OR GPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2014 kikairoya <kikairoya@gmail.com>
// SPDX-FileCopyrightText: Copyright (C) 2014 Jesse Kornblum <research@jessekornblum.com>
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

//! Test utilities for [`crate::compare`](mod@crate::compare).

#![cfg(any(all(test, feature = "tests-slow"), doc))]

/// Computes the edit distance between two given strings.
///
/// Both `s1` and `s2` are [`slice`]s of [`u8`].
///
/// Specifically, it computes the Longest Common Subsequence (LCS)
/// distance, allowing character addition and deletion as two primitive
/// operations (in cost 1).
///
/// # Note
///
/// This function assumes that no arithmetic overflow occurs.
///
/// # History
///
/// This is an optimized port of the `edit_distn` function
/// from libfuzzy's `edit_dist.c`, written by kikairoya.
#[allow(dead_code)]
pub(crate) fn edit_distn(s1: &[u8], s2: &[u8]) -> usize {
    let mut row = std::vec::Vec::from_iter(0usize..=s2.len());
    for (i1, &s1ch) in s1.iter().enumerate() {
        let mut prev_l = row[0];
        row[0] = i1 + 1;
        for (i2, &s2ch) in s2.iter().enumerate() {
            let curr_l = row[i2];
            let prev_c = row[i2 + 1];
            // Costs of character addition and deletion
            let cost_a = curr_l + 1;
            let cost_d = prev_c + 1;
            // Replacement cost below: 2 for LCS distance, 1 for Levenshtein distance
            let cost_r = prev_l + if s1ch == s2ch { 0 } else { 2 };
            prev_l = prev_c;
            row[i2 + 1] = cost_a.min(cost_d.min(cost_r));
        }
    }
    row[s2.len()]
}
