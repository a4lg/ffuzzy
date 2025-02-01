// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2013 Helmut Grohne <helmut@subdivi.de>
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

//! A 32-bit rolling hash as used in the fuzzy hash generator.

use core::ops::AddAssign;

use crate::macros::{invariant, optionally_unsafe};

/// See [`RollingHash::WINDOW_SIZE`].
pub const ROLLING_WINDOW: usize = 7;

// grcov-excl-br-start:STRUCT_MEMBER

/// Hasher which computes a variant of 32-bit rolling hash as used in ssdeep.
///
/// In ssdeep, this is the most important hash function to decide whether to
/// trigger a context update based on the last 7 bytes it met.
///
/// Specifically, [`RollingHash`] implements the rolling hash implemented in
/// ssdeep version 2.13 or later.  This is the first version that officially
/// supported ≧4GiB files and implemented a true rolling hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollingHash {
    /// Current rolling window index.
    ///
    /// **Performance Analysis:**
    /// Substituting this variable's type to `usize` (more semantically correct)
    /// resulted in some slowdown (~10%).  Keeping this state for now.
    pub(crate) index: u32,

    /// Hash component 1.
    ///
    /// This is the sum of the last [`WINDOW_SIZE`](Self::WINDOW_SIZE) bytes.
    ///
    /// In the "ssdeep-compatible" configuration, this value is in the range
    /// of `0..=1785` (`0..=(7*0xff)`).
    h1: u32,

    /// Hash component 2.
    ///
    /// This is the sum of the last [`WINDOW_SIZE`](Self::WINDOW_SIZE) bytes
    /// but the more recent byte has a higher weight (the latest byte has a
    /// weight of [`WINDOW_SIZE`](Self::WINDOW_SIZE) and the last (fading) byte
    /// has a weight of 1).
    ///
    /// In the "ssdeep-compatible" configuration, this value is in the range
    /// of `0..=7140` (`0..=(sum(1..=7)*0xff)`).
    h2: u32,

    /// Hash component 3.
    ///
    /// This is the only "big" component of the hash.
    /// Each time it processes a byte, this value is left-shifted by
    /// [`H3_LSHIFT`](Self::H3_LSHIFT) and xor-ed with the latest byte value.
    ///
    /// If it processes [`WINDOW_SIZE`](Self::WINDOW_SIZE) bytes,
    /// older bytes are shifted out (larger than its MSB).
    h3: u32,

    /// The last [`WINDOW_SIZE`](Self::WINDOW_SIZE) bytes of the processed data.
    window: [u8; ROLLING_WINDOW],
}

// grcov-excl-br-stop

impl RollingHash {
    /// The window size of the rolling hash.
    ///
    /// This is 7 bytes in ssdeep.
    pub const WINDOW_SIZE: usize = ROLLING_WINDOW;

    /// Left shift width of [`h3`](Self::h3) for each byte.
    ///
    /// This is 5 in ssdeep.
    pub(crate) const H3_LSHIFT: usize = 5;

    /// Creates a new [`RollingHash`] with the initial value.
    pub fn new() -> Self {
        RollingHash {
            index: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            window: [0; ROLLING_WINDOW],
        }
    }

    /// Updates the hash value by processing a byte.
    #[inline]
    pub fn update_by_byte(&mut self, ch: u8) -> &mut Self {
        optionally_unsafe! {
            invariant!((self.index as usize) < Self::WINDOW_SIZE);
        }
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self
            .h2
            .wrapping_add(u32::wrapping_mul(ROLLING_WINDOW as u32, ch as u32));
        self.h1 = self.h1.wrapping_add(ch as u32);
        self.h1 = self
            .h1
            .wrapping_sub(self.window[self.index as usize] as u32); // grcov-excl-br-line:ARRAY
        self.window[self.index as usize] = ch; // grcov-excl-br-line:ARRAY
        self.index += 1;
        if self.index as usize == ROLLING_WINDOW {
            self.index = 0;
        }
        self.h3 <<= Self::H3_LSHIFT;
        self.h3 ^= ch as u32;
        self
    }

    /// Updates the hash value by processing an iterator of [`u8`].
    pub fn update_by_iter(&mut self, iter: impl Iterator<Item = u8>) -> &mut Self {
        for ch in iter {
            self.update_by_byte(ch);
        }
        self
    }

    /// Updates the hash value by processing a slice of [`u8`].
    pub fn update(&mut self, buf: &[u8]) -> &mut Self {
        for &ch in buf.iter() {
            self.update_by_byte(ch);
        }
        self
    }

    /// Returns the current hash value.
    ///
    /// Note that there's no "finalization" on this rolling hash.
    /// You can even continue updating after reading the hash value.
    ///
    /// This is the sum of its three internal states (`h1`, `h2`, and `h3`).
    /// See the source code and the private documentation for
    /// its mathematical details.
    #[inline]
    pub fn value(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

impl AddAssign<&[u8]> for RollingHash {
    /// Updates the hash value by processing a slice of [`u8`].
    #[inline(always)]
    fn add_assign(&mut self, buffer: &[u8]) {
        self.update(buffer);
    }
}

impl<const N: usize> AddAssign<&[u8; N]> for RollingHash {
    /// Updates the hash value by processing an array of [`u8`].
    #[inline(always)]
    fn add_assign(&mut self, buffer: &[u8; N]) {
        self.update(&buffer[..]);
    }
}

impl AddAssign<u8> for RollingHash {
    /// Updates the hash value by processing a byte.
    #[inline(always)]
    fn add_assign(&mut self, byte: u8) {
        self.update_by_byte(byte);
    }
}

impl Default for RollingHash {
    fn default() -> Self {
        Self::new()
    }
}

mod tests;
