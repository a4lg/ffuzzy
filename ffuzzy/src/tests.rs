// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2024, 2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate`].

#![cfg(test)]

#[cfg(not(ffuzzy_tests_without_debug_assertions))]
#[cfg_attr(feature = "unstable", coverage(off))] // To avoid llvm-cov error
#[test]
fn test_prerequisites() {
    assert!(cfg!(debug_assertions), "\
        The tests in this crate require debug assertions to be enabled (by default).  \
        To test this crate without debug assertions, add rustc flags \"--cfg ffuzzy_tests_without_debug_assertions\".\
    ");
}
