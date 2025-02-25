// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Copyright Andrew Tridgell <tridge@samba.org> 2002
// SPDX-FileCopyrightText: Copyright (C) 2006 ManTech International Corporation
// SPDX-FileCopyrightText: Copyright (C) 2013 Helmut Grohne <helmut@subdivi.de>
// SPDX-FileCopyrightText: Copyright (C) 2017, 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

//! Fuzzy hash generator and related states and hashes.

use core::ops::AddAssign;

use crate::internals::hash::block::{
    block_hash, block_size, BlockHashSize, BlockHashSizes, ConstrainedBlockHashSize,
    ConstrainedBlockHashSizes,
};
use crate::internals::hash::{fuzzy_raw_type, FuzzyHashData, LongRawFuzzyHash, RawFuzzyHash};
use crate::internals::intrinsics::{likely, unlikely};
use crate::internals::macros::{invariant, optionally_unsafe};

mod hashes;

pub use hashes::partial_fnv::PartialFNVHash;
pub use hashes::rolling_hash::RollingHash;

/// The invalid character for a "not filled" marker.
const BLOCKHASH_CHAR_NIL: u8 = 0xff;

// grcov-excl-br-start:STRUCT_MEMBER

/// Block hash context.
///
/// All operations are performed in [`Generator`] except initialization.
#[derive(Debug, Clone, Copy, PartialEq)]
struct BlockHashContext {
    /// Current index to update [`blockhash`](Self::blockhash).
    blockhash_index: usize,

    /// Block hash contents.
    blockhash: [u8; block_hash::FULL_SIZE],

    /// The last block hash character used when truncating.
    blockhash_ch_half: u8,

    /// Block hash updater (a FNV-1 hasher) for full block hash.
    h_full: PartialFNVHash,

    /// Block hash updater (a FNV-1 hasher) for truncated block hash.
    h_half: PartialFNVHash,
}

// grcov-excl-br-stop

impl BlockHashContext {
    /// Creates a new [`BlockHashContext`] with the initial value.
    ///
    /// It performs full initialization of the all [`BlockHashContext`] fields.
    pub fn new() -> Self {
        BlockHashContext {
            blockhash_index: 0,
            blockhash: [BLOCKHASH_CHAR_NIL; block_hash::FULL_SIZE],
            blockhash_ch_half: BLOCKHASH_CHAR_NIL,
            h_full: PartialFNVHash::new(),
            h_half: PartialFNVHash::new(),
        }
    }

    /// Performs a partial initialization.
    ///
    /// It effectively resets the state to the initial one but does not
    /// necessarily reinitialize all fields.
    pub fn reset(&mut self) {
        self.blockhash_index = 0;
        // partial initialization of the block hash buffer
        self.blockhash[block_hash::FULL_SIZE - 1] = BLOCKHASH_CHAR_NIL;
        self.blockhash_ch_half = BLOCKHASH_CHAR_NIL;
        self.h_full = PartialFNVHash::new();
        self.h_half = PartialFNVHash::new();
    }
}

// grcov-excl-br-start:STRUCT_MEMBER

/// The all internal data inside the [`Generator`] object.
///
/// The intent of this separate struct is to provide access to [`Copy`] and
/// [`PartialEq`] inside this crate but not outside.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct GeneratorInnerData {
    /// Processed input size.
    ///
    /// This value may be inaccurate if the generator has fed more than the
    /// maximum *hard* size limit (finalization should fail in that case).
    input_size: u64,

    /// Optional fixed size set by the
    /// [`set_fixed_input_size()`](Generator::set_fixed_input_size()) method.
    fixed_size: Option<u64>,

    /// Border size to consider advancing [`bhidx_start`](Self::bhidx_start)
    /// (or, to perform a block hash elimination).
    ///
    /// Directly corresponds to: [`bhidx_start`](Self::bhidx_start).
    elim_border: u64,

    /// Start of the block hash "index" to process.
    ///
    /// The "index" is equivalent to the *base-2 logarithm* form
    /// of the block size.  In [`Generator`], it is used as an actual index
    /// of [`bh_context`](Self::bh_context).
    bhidx_start: usize,

    /// End of the block hash "index" to process.
    ///
    /// See also: [`bhidx_start`](Self::bhidx_start)
    bhidx_end: usize,

    /// End of the block hash "index" to process (set by a given fixed size).
    ///
    /// See also:
    ///
    /// *   [`bhidx_start`](Self::bhidx_start)
    /// *   [`set_fixed_input_size()`](Generator::set_fixed_input_size())
    bhidx_end_limit: usize,

    /// Rolling hash mask to prevent piece split matching
    /// before the index [`bhidx_start`](Self::bhidx_start).
    ///
    /// Directly corresponds to: [`bhidx_start`](Self::bhidx_start).
    roll_mask: u32,

    /// Global rolling hash to control piece splitting.
    roll_hash: RollingHash,

    /// Block hash contexts per block size.
    bh_context: [BlockHashContext; block_size::NUM_VALID],

    /// Effectively a [`BlockHashContext::h_full`] but for the block size
    /// larger than the biggest valid block size.
    h_last: PartialFNVHash,

    /// Whether to update [`h_last`](Self::h_last).
    is_last: bool,
}

// grcov-excl-br-stop

/// Fuzzy hash generator.
///
/// This type generates fuzzy hashes from a given data.
///
/// # Default Output
///
/// ## Normalization
///
/// The output of the generator is not normalized.  If you want to convert it
/// to a normalized form, use separate methods like
/// [`RawFuzzyHash::normalize()`].
///
/// In other words, this generator (itself) does not have the direct  equivalent
/// to the `FUZZY_FLAG_ELIMSEQ` flag of libfuzzy's `fuzzy_digest` function.
///
/// ## Truncation
///
/// By default (using [`finalize()`](Self::finalize()) method), the output has a
/// short, truncated form.
///
/// By using [`finalize_without_truncation()`](Self::finalize_without_truncation()),
/// you can retrieve a non-truncated form as a result.  This is equivalent to
/// the `FUZZY_FLAG_NOTRUNC` flag of libfuzzy's `fuzzy_digest` function.
///
/// # Input Types
///
/// This type has three update methods accepting three different types:
///
/// 1.  [`update()`](Self::update())
///     (accepting a slice of [`u8`] - byte buffer)
/// 2.  [`update_by_iter()`](Self::update_by_iter())
///     (accepting an iterator of [`u8`] - stream of bytes)
/// 3.  [`update_by_byte()`](Self::update_by_byte())
///     (accepting [`u8`] - single byte)
///
/// # Input Size
///
/// The input size has a *hard* maximum limit (inclusive):
/// [`MAX_INPUT_SIZE`](Self::MAX_INPUT_SIZE) (192GiB).
/// This is due to the mathematical limit of
/// [the 32-bit rolling hash](`RollingHash`) and piece-splitting behavior.
///
/// On the other hand, if the input size is too small, the result will not be
/// meaningful enough.  This *soft* lower limit (inclusive) is declared as
/// [`MIN_RECOMMENDED_INPUT_SIZE`](Self::MIN_RECOMMENDED_INPUT_SIZE) and
/// you can check the
/// [`may_warn_about_small_input_size()`](Self::may_warn_about_small_input_size())
/// method to check whether the size is too small to be meaningful enough.
///
/// Note: even if it's doubtful to be meaningful enough, a fuzzy hash generated
/// from such a small input is still valid.  You don't have to reject them
/// just because they are too small.  This *soft* limit is for diagnostics.
///
/// If you know the total size of the input, you can improve the performance by
/// using either the [`set_fixed_input_size()`](Self::set_fixed_input_size()) method
/// or the [`set_fixed_input_size_in_usize()`](Self::set_fixed_input_size_in_usize())
/// method.
///
/// # Examples
///
/// ```rust
/// use ssdeep::{Generator, RawFuzzyHash};
///
/// let mut generator = Generator::new();
/// let buf1: &[u8]    = b"Hello, ";
/// let buf2: &[u8; 6] = b"World!";
///
/// // Optional but supplying the *total* input size first improves the performance.
/// // This is the total size of three update calls below.
/// generator.set_fixed_input_size_in_usize(buf1.len() + buf2.len() + 1).unwrap();
///
/// // Update the internal state of the generator.
/// // Of course, you can update multiple times.
/// generator.update(buf1);
/// generator.update_by_iter((*buf2).into_iter());
/// generator.update_by_byte(b'\n');
///
/// // Retrieve the fuzzy hash and convert to the string.
/// let hash: RawFuzzyHash = generator.finalize().unwrap();
/// assert_eq!(hash.to_string(), "3:aaX8v:aV");
/// ```
///
/// # Compatibility Notice
///
/// `+=` operator is going to be removed in the next major release.
#[derive(Debug, Clone)]
pub struct Generator(GeneratorInnerData);

/// The error type representing an invalid or an unsupported operation of
/// [the generator](Generator).
///
/// # Compatibility Note
///
/// Since the version 0.3, the representation of this enum is no longer
/// specified as specific representation of this enum is not important.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorError {
    /// [The fixed size](Generator::set_fixed_input_size()) has a mismatch with
    /// either the previously set value or the final input size.
    FixedSizeMismatch,

    /// [The fixed size](Generator::set_fixed_input_size()) is
    /// [too large](Generator::MAX_INPUT_SIZE).
    FixedSizeTooLarge,

    /// The total input size on finalization is
    /// [too large](Generator::MAX_INPUT_SIZE).
    InputSizeTooLarge,

    /// The output would cause a buffer overflow for a specific output type.
    ///
    /// This error only occurs when:
    ///
    /// *   Truncation is disabled,
    /// *   The output type is a short form  
    ///     (because of those conditions, it only occurs on a raw
    ///     [`Generator::finalize_raw()`] call) and
    /// *   The resulting block hash 2 is longer than that of the
    ///     short form limit ([`block_hash::HALF_SIZE`]).
    OutputOverflow,
}

impl GeneratorError {
    /// Checks whether this error is raised by one of the "size too large" cases.
    ///
    /// It returns [`true`] on either [`FixedSizeTooLarge`](Self::FixedSizeTooLarge)
    /// or [`InputSizeTooLarge`](Self::InputSizeTooLarge) variants.
    pub fn is_size_too_large_error(&self) -> bool {
        matches!(
            self,
            GeneratorError::FixedSizeTooLarge | GeneratorError::InputSizeTooLarge
        )
    }
}

impl core::fmt::Display for GeneratorError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self { // grcov-excl-br-line:MATCH_ENUM
            GeneratorError::FixedSizeMismatch => "current state mismatches to the fixed size previously set",
            GeneratorError::FixedSizeTooLarge => "fixed size is too large to generate a fuzzy hash",
            GeneratorError::InputSizeTooLarge => "input size is too large to generate a fuzzy hash",
            GeneratorError::OutputOverflow    => "output is too large for specific fuzzy hash variant",
        })
    }
}

crate::internals::macros::impl_error!(GeneratorError {});

impl Generator {
    /// Returns the preferred maximum input size at the specified block size.
    ///
    /// If the total input size exceeds this border, the double block size
    /// (*base-2 logarithm* form: `log_block_size + 1`) is preferred for
    /// the final block size (if the block hash for double block size has
    /// enough length: `block_hash::HALF_SIZE`).
    const fn guessed_preferred_max_input_size_at(log_block_size: u8) -> u64 {
        block_size::from_log_internal_const(log_block_size) as u64 * block_hash::FULL_SIZE as u64
    }

    /// The maximum input size (inclusive).
    ///
    /// ssdeep has an upper limit of 192GiB (inclusive).
    ///
    /// This is a *hard* limit.  Feeding data larger than this constant size is
    /// an invalid operation.
    pub const MAX_INPUT_SIZE: u64 =
        Self::guessed_preferred_max_input_size_at(block_size::NUM_VALID as u8 - 1);

    /// The recommended minimum input size (inclusive).
    ///
    /// This is a *soft* limit.  Although it's doubtful that the result from the
    /// input smaller than this constant size is meaningful enough,
    /// it's still valid.  It might be useful for diagnostics.
    pub const MIN_RECOMMENDED_INPUT_SIZE: u64 = 4096 + 1;

    /// Creates a new [`Generator`] object.
    pub fn new() -> Self {
        Generator(GeneratorInnerData {
            input_size: 0,
            fixed_size: None,
            elim_border: Self::guessed_preferred_max_input_size_at(0),
            bhidx_start: 0,
            bhidx_end: 1,
            bhidx_end_limit: block_size::NUM_VALID - 1,
            roll_mask: 0,
            roll_hash: RollingHash::new(),
            bh_context: [BlockHashContext::new(); block_size::NUM_VALID],
            h_last: PartialFNVHash::new(),
            is_last: false,
        })
    }

    /// Performs a partial initialization.
    ///
    /// It effectively resets the state to the initial one but does not
    /// necessarily reinitialize all internal fields.
    pub fn reset(&mut self) {
        self.0.input_size = 0;
        self.0.fixed_size = None;
        self.0.elim_border = Self::guessed_preferred_max_input_size_at(0);
        self.0.bhidx_start = 0;
        self.0.bhidx_end = 1;
        self.0.bhidx_end_limit = block_size::NUM_VALID - 1;
        self.0.roll_mask = 0;
        self.0.roll_hash = RollingHash::new();
        self.0.bh_context[0].reset();
        // skip bh_context[1..block_size::NUM_VALID] initialization
        // skip h_last initialization
        self.0.is_last = false;
    }

    /// Retrieves the input size fed to the generator object.
    #[inline(always)]
    pub fn input_size(&self) -> u64 {
        self.0.input_size
    }

    /// Checks whether a ssdeep-compatible client may raise a warning due to
    /// its small input size (less meaningful fuzzy hashes will be generated
    /// on the finalization).
    ///
    /// The result is based on either the fixed size or the current input size.
    /// So, this method should be used after calling either:
    ///
    /// *   [`set_fixed_input_size()`](Self::set_fixed_input_size())
    ///     or similar methods
    /// *   [`finalize()`](Self::finalize())
    ///     or similar methods
    ///
    /// and before resetting the state.
    #[inline]
    pub fn may_warn_about_small_input_size(&self) -> bool {
        self.0.fixed_size.unwrap_or(self.0.input_size) < Self::MIN_RECOMMENDED_INPUT_SIZE
    }

    /// Returns the suitable initial block size (equal to or greater than
    /// `start`) for the specified input size (in *base-2 logarithm* form).
    ///
    /// `start` is also in a *base-2 logarithm* form.
    ///
    /// This method returns a good candidate but not always suitable for the
    /// final fuzzy hash.  The final guess is performed in the
    /// [`guess_output_log_block_size()`](Self::guess_output_log_block_size())
    /// method.
    fn get_log_block_size_from_input_size(size: u64, start: usize) -> usize {
        let size_unit = Self::guessed_preferred_max_input_size_at(0);
        if size <= size_unit {
            return start;
        }
        let high_size = (size - 1) / size_unit; // grcov-excl-br-line:DIVZERO
        invariant!(high_size > 0);
        usize::max(
            start,
            (crate::internals::utils::u64_ilog2(high_size) + 1) as usize,
        )
    }

    /// Set the fixed input size for optimal performance.
    ///
    /// This method sets the internal upper limit of the block size to
    /// update per byte.  It improves the performance by preventing unnecessary
    /// block hash updates (that will never be used by the final fuzzy hash).
    ///
    /// This method returns an error if:
    ///
    /// 1.  `size` is larger than [`MAX_INPUT_SIZE`](Self::MAX_INPUT_SIZE)
    ///     ([`GeneratorError::FixedSizeTooLarge`]) or
    /// 2.  The fixed size is previously set but the new one is different
    ///     ([`GeneratorError::FixedSizeMismatch`]).
    pub fn set_fixed_input_size(&mut self, size: u64) -> Result<(), GeneratorError> {
        if size > Self::MAX_INPUT_SIZE {
            return Err(GeneratorError::FixedSizeTooLarge);
        }
        if let Some(expected_size) = self.0.fixed_size {
            if expected_size != size {
                return Err(GeneratorError::FixedSizeMismatch);
            }
        }
        self.0.fixed_size = Some(size);
        self.0.bhidx_end_limit = usize::min(
            block_size::NUM_VALID - 1,
            Self::get_log_block_size_from_input_size(size, 0) + 1,
        );
        Ok(())
    }

    /// Set the fixed input size for optimal performance.
    ///
    /// This is a thin wrapper of the
    /// [`set_fixed_input_size()`](Self::set_fixed_input_size()) method.
    ///
    /// Although that this implementation handles [`u64`] as the native input
    /// size type and
    /// [the file size in the Rust standard library](std::fs::Metadata::len())
    /// is represented as [`u64`], it's not rare that you want to give a
    /// [`usize`] to hash a buffer (or your program uses [`usize`] for its
    /// native size representation).
    ///
    /// It accepts `size` in [`usize`] and if this size is larger than
    /// 64-bits, an error containing [`GeneratorError::FixedSizeTooLarge`]
    /// is returned.  Other than that, this is the same as
    /// [`set_fixed_input_size()`](Self::set_fixed_input_size()).
    #[inline]
    pub fn set_fixed_input_size_in_usize(&mut self, size: usize) -> Result<(), GeneratorError> {
        // grcov-excl-br-start
        if let Ok(size) = u64::try_from(size) {
            self.set_fixed_input_size(size)
        } else {
            // grcov-excl-start: Only reproduces in 128-bit usize environments.
            Err(GeneratorError::FixedSizeTooLarge)
            // grcov-excl-stop
        }
        // grcov-excl-br-stop
    }
}

/// Template to generate [`Generator::update()`]-like methods.
///
/// *   `$self`  
///     A mutable reference to the [`Generator`] object.
/// *   `$buffer`  
///     An iterator-like object (each item is in [`u8`]) to consume.
/// *   `$proc_per_byte`  
///     Statements to run each time the generator consumes a byte
///     (e.g. on the iterator variant, advance the `input_size` variable).
macro_rules! generator_update_template {
    ($self: expr, $buffer: expr, $proc_per_byte: block) => {
        optionally_unsafe! {
            cfg_if::cfg_if! {
                if #[cfg(feature = "unsafe")] {
                    let bh = $self.bh_context.as_mut_ptr();
                    let mut bhrange0 = bh.add($self.bhidx_start);
                    let mut bhrange1 = bh.add($self.bhidx_end);
                    let mut bh: *mut BlockHashContext;
                    let mut bh_next: *mut BlockHashContext;
                }
            }

            for ch in $buffer {
                $proc_per_byte;

                $self.roll_hash.update_by_byte(ch);
                if $self.is_last {
                    $self.h_last.update_by_byte(ch);
                }

                cfg_if::cfg_if! {
                    if #[cfg(feature = "unsafe")] {
                        bh = bhrange0;
                        loop {
                            (*bh).h_full.update_by_byte(ch);
                            (*bh).h_half.update_by_byte(ch);
                            bh = bh.add(1);
                            if bh == bhrange1 {
                                break;
                            }
                        }
                    } else {
                        for bh1 in &mut $self.bh_context[$self.bhidx_start..$self.bhidx_end] {
                            bh1.h_full.update_by_byte(ch);
                            bh1.h_half.update_by_byte(ch);
                        }
                    }
                }

                let h_org = $self.roll_hash.value().wrapping_add(1);
                let mut h = h_org / block_size::MIN;
                if unlikely(h_org == 0) {
                    continue;
                }
                if likely(h & $self.roll_mask != 0) {
                    continue;
                }
                if h_org % block_size::MIN != 0 {
                    continue;
                }
                h >>= $self.bhidx_start;

                cfg_if::cfg_if! {
                    if #[cfg(feature = "unsafe")] {
                        macro_rules! bh_loop_2 {
                            ($block: block) => {
                                bh = bhrange0;
                                loop {
                                    bh_next = bh.add(1);
                                    $block
                                    bh = bh_next;
                                    if bh >= bhrange1 {
                                        break;
                                    }
                                }
                            };
                        }
                        macro_rules! bh_curr {() => { *bh }}
                        macro_rules! bh_next {() => { *bh_next }}
                    } else {
                        let mut i = $self.bhidx_start;
                        macro_rules! bh_loop_2 {
                            ($block: block) => {
                                loop {
                                    $block;
                                    i += 1;
                                    if i >= $self.bhidx_end {
                                        break;
                                    }
                                }
                            };
                        }
                        macro_rules! bh_curr {() => { $self.bh_context[i] }}
                        macro_rules! bh_next {() => { $self.bh_context[i+1] }}
                    }
                }
                bh_loop_2!({
                    if unlikely(
                        bh_curr!().blockhash_index == 0 // grcov-excl-br-line:ARRAY
                    )
                    {
                        // New block size candidate is found.
                        if $self.bhidx_end > $self.bhidx_end_limit {
                            // If this is not constrained by bhidx_end_limit
                            // (set by the fixed input size) and it has reached
                            // to the largest index, enable "last" FNV hash updates.
                            // It will be used for block hash 2 if the final block size
                            // is the maximum valid one.
                            if $self.bhidx_end_limit == block_size::NUM_VALID - 1 && !$self.is_last {
                                $self.h_last = bh_curr!().h_full; // grcov-excl-br-line:ARRAY
                                $self.is_last = true;
                            }
                        } else {
                            // Reset the block hash context and advance bhidx_end
                            // so that the generator can begin block hash context updates.
                            bh_next!().reset(); // grcov-excl-br-line:ARRAY
                            bh_next!().h_full = bh_curr!().h_full; // grcov-excl-br-line:ARRAY
                            bh_next!().h_half = bh_curr!().h_half; // grcov-excl-br-line:ARRAY
                            $self.bhidx_end += 1;
                            #[cfg(feature = "unsafe")]
                            {
                                bhrange1 = bhrange1.add(1);
                            }
                        }
                    }

                    cfg_if::cfg_if! {
                        if #[cfg(feature = "unsafe")] {
                            macro_rules! bh_curr_reused {() => { *bh }}
                        } else {
                            let bh_curr_reused = &mut $self.bh_context[i]; // grcov-excl-br-line:ARRAY
                            macro_rules! bh_curr_reused {() => { bh_curr_reused }}
                        }
                    }
                    invariant!(bh_curr_reused!().blockhash_index < block_hash::FULL_SIZE);
                    bh_curr_reused!().blockhash[bh_curr_reused!().blockhash_index] = bh_curr_reused!().h_full.value(); // grcov-excl-br-line:ARRAY
                    bh_curr_reused!().blockhash_ch_half = bh_curr_reused!().h_half.value();
                    if bh_curr_reused!().blockhash_index < block_hash::FULL_SIZE - 1 {
                        bh_curr_reused!().blockhash_index += 1;
                        bh_curr_reused!().h_full = PartialFNVHash::new();
                        if bh_curr_reused!().blockhash_index < block_hash::HALF_SIZE {
                            bh_curr_reused!().blockhash_ch_half = BLOCKHASH_CHAR_NIL;
                            bh_curr_reused!().h_half = PartialFNVHash::new();
                        }
                    } else if $self.bhidx_end - $self.bhidx_start >= 2
                        && $self.elim_border < $self.fixed_size.unwrap_or($self.input_size)
                        && bh_next!().blockhash_index >= block_hash::HALF_SIZE // grcov-excl-br-line:ARRAY
                    {
                        // (Block hash elimination)
                        // Current block hash context will be never used on the final fuzzy hash.
                        // Advance bhidx_start and prepare for the next block hash elimination.
                        $self.bhidx_start += 1;
                        #[cfg(feature = "unsafe")]
                        {
                            bhrange0 = bhrange0.add(1);
                        }
                        $self.roll_mask = $self.roll_mask.wrapping_mul(2).wrapping_add(1);
                        $self.elim_border = $self.elim_border.wrapping_mul(2);
                    }
                    // Loop between bhidx_start and the maximum matched index.
                    if (h & 1) != 0 {
                        break;
                    }
                    h >>= 1;
                });
            }
        }
    };
}

impl Generator {
    /// Process data, updating the internal state.
    #[rustfmt::skip]
    #[allow(unused_unsafe)]
    pub fn update(&mut self, buffer: &[u8]) -> &mut Self {
        self.0.input_size = if let Ok(size) = u64::try_from(buffer.len()) { // grcov-excl-br-line: else branch only in 128-bit usize environments.
            self.0.input_size.saturating_add(size)
        } else {
            // grcov-excl-start: Only reproduces in 128-bit usize environments.
            Self::MAX_INPUT_SIZE + 1
            // grcov-excl-stop
        };
        // grcov-generator-start
        generator_update_template!(self.0, buffer.iter().copied(), {});
        // grcov-generator-stop
        self
    }

    /// Process data (an iterator), updating the internal state.
    #[allow(unused_unsafe)]
    pub fn update_by_iter(&mut self, iter: impl Iterator<Item = u8>) -> &mut Self {
        // grcov-generator-start
        generator_update_template!(self.0, iter, {
            self.0.input_size = self.0.input_size.saturating_add(1);
        });
        // grcov-generator-stop
        self
    }

    /// Process a byte, updating the internal state.
    #[allow(unused_unsafe)]
    pub fn update_by_byte(&mut self, ch: u8) -> &mut Self {
        self.0.input_size = self.0.input_size.saturating_add(1);
        // grcov-generator-start
        generator_update_template!(self.0, [ch; 1], {});
        // grcov-generator-stop
        self
    }

    /// Guess the final block size based on the current internal state.
    ///
    /// First, the generator prefers the return value of
    /// [`get_log_block_size_from_input_size()`](Self::get_log_block_size_from_input_size()).
    ///
    /// But if the resulting fuzzy hash is too short, we have to half
    /// the block size until it finds a fuzzy hash of suitable length.
    /// In other words, it tries to find a block hash until:
    ///
    /// *   It find a block size so that corresponding block hash is already
    ///     at least [`block_hash::HALF_SIZE`] chars in length
    ///     (one character may be appended on the finalization process) or
    /// *   It reaches the lower bound ([`bhidx_start`](GeneratorInnerData::bhidx_start)).
    ///
    /// The resulting block size and the corresponding block hash are used as:
    ///
    /// 1.  Block size part
    /// 2.  Block hash 1
    ///
    /// For the block hash 2 part, the block hash for double block size is used.
    #[rustfmt::skip]
    fn guess_output_log_block_size(&self) -> usize {
        let mut log_block_size =
            Self::get_log_block_size_from_input_size(self.0.input_size, self.0.bhidx_start);
        log_block_size = usize::min(log_block_size, self.0.bhidx_end - 1);
        invariant!(log_block_size < self.0.bh_context.len());
        while log_block_size > self.0.bhidx_start
            && self.0.bh_context[log_block_size].blockhash_index < block_hash::HALF_SIZE // grcov-excl-br-line:ARRAY
        {
            log_block_size -= 1;
            invariant!(log_block_size < self.0.bh_context.len());
        }
        log_block_size
    }

    /// The internal implementation of [`Self::finalize_raw()`].
    #[allow(clippy::branches_sharing_code)]
    #[rustfmt::skip]
    #[inline(always)]
    fn finalize_raw_internal<const S1: usize, const S2: usize>(
        &self,
        truncate: bool,
    ) -> Result<fuzzy_raw_type!(S1, S2), GeneratorError>
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    {
        if let Some(input_size) = self.0.fixed_size {
            if input_size != self.0.input_size {
                return Err(GeneratorError::FixedSizeMismatch);
            }
        }
        if Self::MAX_INPUT_SIZE < self.0.input_size {
            return Err(GeneratorError::InputSizeTooLarge);
        }
        let log_block_size = self.guess_output_log_block_size();
        let mut fuzzy: fuzzy_raw_type!(S1, S2) = FuzzyHashData::new();
        fuzzy.log_blocksize = log_block_size as u8;
        // Copy block hash 1
        let roll_value = self.0.roll_hash.value();
        invariant!(log_block_size < self.0.bh_context.len());
        let bh_0 = &self.0.bh_context[log_block_size]; // grcov-excl-br-line:ARRAY
        {
            let mut sz = bh_0.blockhash_index;
            if bh_0.blockhash[block_hash::FULL_SIZE - 1] != BLOCKHASH_CHAR_NIL {
                sz += 1;
            }
            invariant!(sz <= fuzzy.blockhash1.len());
            invariant!(sz <= bh_0.blockhash.len());
            fuzzy.blockhash1[0..sz].clone_from_slice(&bh_0.blockhash[0..sz]); // grcov-excl-br-line:ARRAY
            fuzzy.len_blockhash1 = sz as u8;
            if roll_value != 0 {
                if sz == block_hash::FULL_SIZE {
                    fuzzy.blockhash1[block_hash::FULL_SIZE - 1] = bh_0.h_full.value(); // grcov-excl-br-line:ARRAY
                } else {
                    invariant!(sz < block_hash::FULL_SIZE);
                    fuzzy.blockhash1[sz] = bh_0.h_full.value(); // grcov-excl-br-line:ARRAY
                    fuzzy.len_blockhash1 += 1;
                }
            }
        }
        // Copy block hash 2 or adjust block hashes.
        if log_block_size < self.0.bhidx_end - 1 {
            // Copy block hash 2 (normal path)
            invariant!(log_block_size + 1 < self.0.bh_context.len());
            let bh_1 = &self.0.bh_context[log_block_size + 1]; // grcov-excl-br-line:ARRAY
            if truncate {
                let mut sz = bh_1.blockhash_index;
                if bh_1.blockhash_ch_half != BLOCKHASH_CHAR_NIL {
                    debug_assert!(sz >= block_hash::HALF_SIZE); // invariant
                    sz = block_hash::HALF_SIZE;
                    fuzzy.blockhash2[0..(sz - 1)].clone_from_slice(&bh_1.blockhash[0..(sz - 1)]); // grcov-excl-br-line:ARRAY
                    fuzzy.blockhash2[sz - 1] = { // grcov-excl-br-line:ARRAY
                        if roll_value != 0 {
                            bh_1.h_half.value()
                        } else {
                            bh_1.blockhash_ch_half
                        }
                    };
                } else {
                    invariant!(sz <= fuzzy.blockhash2.len());
                    invariant!(sz <= bh_1.blockhash.len());
                    fuzzy.blockhash2[0..sz].clone_from_slice(&bh_1.blockhash[0..sz]); // grcov-excl-br-line:ARRAY
                    if roll_value != 0 {
                        invariant!(sz < fuzzy.blockhash2.len());
                        fuzzy.blockhash2[sz] = bh_1.h_half.value(); // grcov-excl-br-line:ARRAY
                        sz += 1;
                    }
                }
                fuzzy.len_blockhash2 = sz as u8;
            } else {
                let mut sz = bh_1.blockhash_index;
                if bh_1.blockhash[block_hash::FULL_SIZE - 1] != BLOCKHASH_CHAR_NIL {
                    sz += 1;
                }
                #[allow(clippy::collapsible_if)]
                if !<fuzzy_raw_type!(S1, S2)>::IS_LONG_FORM {
                    if sz > S2 {
                        // Overflow will occur if:
                        // 1.  truncation is disabled (!truncate),
                        // 2.  the output is short and
                        // 3.  the input (block hash 2) is large enough.
                        return Err(GeneratorError::OutputOverflow);
                    }
                }
                invariant!(sz <= fuzzy.blockhash2.len());
                invariant!(sz <= bh_1.blockhash.len());
                fuzzy.blockhash2[0..sz].clone_from_slice(&bh_1.blockhash[0..sz]); // grcov-excl-br-line:ARRAY
                fuzzy.len_blockhash2 = sz as u8;
                if roll_value != 0 {
                    #[allow(clippy::collapsible_else_if)]
                    if !<fuzzy_raw_type!(S1, S2)>::IS_LONG_FORM {
                        if sz >= S2 {
                            // Overflow will occur if:
                            // 1.  truncation is disabled (!truncate),
                            // 2.  the output is short and
                            // 3.  the input (block hash 2) is large enough.
                            return Err(GeneratorError::OutputOverflow);
                        }
                        invariant!(sz < S2);
                        fuzzy.blockhash2[sz] = bh_1.h_full.value(); // grcov-excl-br-line:ARRAY
                        fuzzy.len_blockhash2 += 1;
                    } else {
                        if sz == block_hash::FULL_SIZE {
                            fuzzy.blockhash2[block_hash::FULL_SIZE - 1] = bh_1.h_full.value(); // grcov-excl-br-line:ARRAY
                        } else {
                            invariant!(sz < block_hash::FULL_SIZE);
                            fuzzy.blockhash2[sz] = bh_1.h_full.value(); // grcov-excl-br-line:ARRAY
                            fuzzy.len_blockhash2 += 1;
                        }
                    }
                }
            }
        } else if roll_value != 0 {
            debug_assert!(log_block_size == 0 || log_block_size == block_size::NUM_VALID - 1);
            if log_block_size == 0 {
                // No pieces are matched but at least one byte is processed.
                fuzzy.blockhash2[0] = bh_0.h_full.value(); // grcov-excl-br-line:ARRAY
                fuzzy.len_blockhash2 = 1;
            } else {
                // We need to handle block hash 2 for the largest valid block
                // size specially because effective block size of the block hash
                // 2 is not valid (and no regular pieces are available).
                fuzzy.blockhash2[0] = self.0.h_last.value(); // grcov-excl-br-line:ARRAY
                fuzzy.len_blockhash2 = 1;
            }
        } else {
            // We are not confident enough that we have processed a byte.
            // Note: there's an easy way to trigger this condition:
            //       feed seven zero bytes at the end.
            fuzzy.len_blockhash2 = 0;
        }
        Ok(fuzzy)
    }

    /// Retrieves the resulting fuzzy hash.
    ///
    /// Usually, you should use the [`finalize()`](Self::finalize()) method (a
    /// wrapper of this method) instead because it passes the `TRUNC` option
    /// [`true`] to this method (as the default ssdeep option).
    ///
    /// Although some methods including this is named *finalize*, you can
    /// continue feeding more data and updating the internal state without
    /// problems.  Still, it's hard to find such use cases so that using
    /// [`Generator`] like this is useful.
    pub fn finalize_raw<const TRUNC: bool, const S1: usize, const S2: usize>(
        &self,
    ) -> Result<fuzzy_raw_type!(S1, S2), GeneratorError>
    where
        BlockHashSize<S1>: ConstrainedBlockHashSize,
        BlockHashSize<S2>: ConstrainedBlockHashSize,
        BlockHashSizes<S1, S2>: ConstrainedBlockHashSizes,
    {
        self.finalize_raw_internal::<S1, S2>(TRUNC)
    }

    /// Retrieves the resulting fuzzy hash.
    ///
    /// The type of resulting fuzzy hash ([`RawFuzzyHash`]) is in
    /// a raw form (not normalized).  This is the default behavior of ssdeep.
    ///
    /// This is equivalent to calling libfuzzy's `fuzzy_digest` function
    /// with default flags.
    #[inline]
    pub fn finalize(&self) -> Result<RawFuzzyHash, GeneratorError> {
        self.finalize_raw::<true, { block_hash::FULL_SIZE }, { block_hash::HALF_SIZE }>()
    }

    /// Retrieves the resulting fuzzy hash, *not* truncating the second block hash.
    ///
    /// Note that *not* doing the truncation is usually not what you want.
    ///
    /// This is equivalent to calling libfuzzy's `fuzzy_digest` function
    /// with the flag `FUZZY_FLAG_NOTRUNC`.
    #[inline]
    pub fn finalize_without_truncation(&self) -> Result<LongRawFuzzyHash, GeneratorError> {
        self.finalize_raw::<false, { block_hash::FULL_SIZE }, { block_hash::FULL_SIZE }>()
    }
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl AddAssign<&[u8]> for Generator {
    /// Updates the hash value by processing a slice of [`u8`].
    #[inline(always)]
    fn add_assign(&mut self, buffer: &[u8]) {
        self.update(buffer);
    }
}

impl<const N: usize> AddAssign<&[u8; N]> for Generator {
    /// Updates the hash value by processing an array of [`u8`].
    #[inline(always)]
    fn add_assign(&mut self, buffer: &[u8; N]) {
        self.update(&buffer[..]);
    }
}

impl AddAssign<u8> for Generator {
    /// Updates the hash value by processing a byte.
    #[inline(always)]
    fn add_assign(&mut self, byte: u8) {
        self.update_by_byte(byte);
    }
}

/// Constant assertions related to this module.
#[doc(hidden)]
mod const_asserts {
    use static_assertions::{const_assert, const_assert_eq, const_assert_ne};

    use super::*;

    // Compare with original ssdeep constants
    // ssdeep.h: SSDEEP_MIN_FILE_SIZE
    // (note that this size is exclusive, unlike inclusive MIN_RECOMMENDED_INPUT_SIZE)
    const_assert_eq!(Generator::MIN_RECOMMENDED_INPUT_SIZE - 1, 4096);

    // BLOCKHASH_CHAR_NIL must be outside any valid characters.
    const_assert!(block_hash::ALPHABET_SIZE <= BLOCKHASH_CHAR_NIL as usize);

    // Compare with a precomputed value.
    const_assert_eq!(Generator::MAX_INPUT_SIZE, 192u64 * 1024 * 1024 * 1024);
    // and not u64::MAX
    const_assert_ne!(Generator::MAX_INPUT_SIZE, u64::MAX);

    // Rolling hash value of u32::MAX does not make a piece.
    // Because we use rolling hash value + 1 to determine piece splitting
    // (unlike the original implementation) for faster processing, we have to
    // (additionally) take care of an arithmetic overflow.
    const_assert_ne!(u32::MAX % block_size::MIN, block_size::MIN - 1);
}

mod tests;
