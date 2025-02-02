// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2024–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::macros`].

#![cfg(test)]

#[forbid(unsafe_code)]
#[cfg(not(ffuzzy_tests_without_debug_assertions))]
#[test]
#[should_panic]
fn violation_invariant() {
    // On tests, an invariant is just a debug_assert without an unsafe block.
    super::invariant!(false);
}
