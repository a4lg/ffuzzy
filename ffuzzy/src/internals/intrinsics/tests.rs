// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2024, 2025

//! Tests: [`crate::internals::intrinsics`].

#![cfg(test)]

use super::{likely, unlikely};

#[test]
fn test_likely_unlikely() {
    assert!(likely(true));
    assert!(!likely(false));
    assert!(unlikely(true));
    assert!(!unlikely(false));
}
