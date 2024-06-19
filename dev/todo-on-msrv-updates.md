# MSRV Updates and TODOs

Note that this list does not include Nightly features because the main focus of
this memo is to describe what to do when we update the minimum supported Rust
version (MSRV), which we only expect stable features.

## 1.57.0

*   `&array[..]` to `array.as_slice()`.
*   Make faulting functions to be `const` (e.g. functions with `debug_assert!`).

## 1.58.0

*   Variable names in the format string
    (e.g. `format!("{a}")` instead of `format!("{}", a)`)

## 1.60.0

*   New cargo dependency format suitable for Serde integration
*   `abs_diff` method on integer types

## 1.63.0

*   Remove unconditional `#[allow(unknown_lints)]`
    (that is a workaround for lint handling bug on Rust -1.62).

## 1.67.0

*   Remove `crate::utils::u64_ilog2` and replace to `u64::ilog2`.

## 1.73.0

*   Remove `crate::hash_dual::private::const_asserts::div_ceil` and
    replace to `usize::div_ceil`.

## 1.80.0 (Beta)

*   Start to use exclusive range patterns.

## 1.81.0 (Nightly)

*   Replace `std::error::Error` (or `core::error::Error` on `unstable`)
    to `core::error::Error` (now `std` trait is a re-report of `core`).
    The only exception would be `GeneratorOrIOError`, that is truly
    `std`-specific.
