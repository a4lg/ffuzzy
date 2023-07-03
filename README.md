# ffuzzy: ssdeep-compatible Fuzzy Hashing Library in pure Rust

[ssdeep](https://ssdeep-project.github.io/ssdeep/) is a program for computing
context triggered piecewise hashes (CTPH).  Also called fuzzy hashes, CTPH
can match inputs that have homologies.  Such inputs have sequences of identical
bytes in the same order, although bytes in between these sequences may be
different in both content and length.

You can generate / parse / compare (ssdeep-compatible) fuzzy hashes
with this crate.

Along with "easy" functions, it provides fuzzy hashing-related structs for
high performance / advanced use cases.  If you understand both the property of
fuzzy hashes and this crate well, you can cluster the fuzzy hashes over 5 times
faster than libfuzzy.


## Usage: Basic

### Hashing a File

```rust
// Required Features: "std" and "easy-functions" (default enabled)
fn main() -> Result<(), ssdeep::GeneratorOrIOError> {
    let fuzzy_hash = ssdeep::hash_file("data/examples/hello.txt")?;
    let fuzzy_hash_str = fuzzy_hash.to_string();
    assert_eq!(fuzzy_hash_str, "3:aaX8v:aV");
    Ok(())
}
```

### Comparing Two Fuzzy Hashes

```rust
// Required Feature: "easy-functions" (default enabled)
let score = ssdeep::compare(
    "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW",
    "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n"
).unwrap();
assert_eq!(score, 46);
```

## Usage: Advanced

### Hashing a Buffer

```rust
// Requires the "alloc" feature to use the `to_string()` method (default enabled).
use ssdeep::{Generator, RawFuzzyHash};

let mut generator = Generator::new();
let buf1: &[u8] = b"Hello, ";
let buf2: &[u8] = b"World!";

// Optional but supplying the *total* input size first improves the performance.
// This is the total size of three update calls below.
generator.set_fixed_input_size_in_usize(buf1.len() + buf2.len() + 1).unwrap();

// Update the internal state of the generator.
// Of course, you can call `update()`-family functions multiple times.
generator.update(buf1);
generator.update_by_iter(buf2.iter().cloned());
generator.update_by_byte(b'\n');

// Retrieve the fuzzy hash and convert to the string.
let hash: RawFuzzyHash = generator.finalize().unwrap();
assert_eq!(hash.to_string(), "3:aaX8v:aV");
```

### Comparing Fuzzy Hashes

```rust
// Requires the "alloc" feature to use the `to_string()` method (default enabled).
use ssdeep::{FuzzyHash, FuzzyHashCompareTarget};

// Those fuzzy hash strings are "normalized" so that easier to compare.
let str1 = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
let str2 = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK";
// FuzzyHash object can be used to avoid parser / normalization overhead
// and helps improving the performance.
let hash1: FuzzyHash = str::parse(str1).unwrap();
let hash2: FuzzyHash = str::parse(str2).unwrap();

// Note that converting the (normalized) fuzzy hash object back to the string
// may not preserve the original string.  To preserve the original fuzzy hash
// string too, consider using dual fuzzy hashes (such like DualFuzzyHash) that
// preserves the original string in the compressed format.
// *   str1:  "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ"
// *   hash1: "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccei:+Klhav84a5sxJ"
assert_ne!(hash1.to_string(), str1);

// If we have number of fuzzy hashes and a hash is compared more than once,
// storing those hashes as FuzzyHash objects is faster.
assert_eq!(hash1.compare(&hash2), 88);

// But there's another way of comparison.
// If you compare "a fuzzy hash" with "other many fuzzy hashes", this method
// (using FuzzyHashCompareTarget as "a fuzzy hash") is much, much faster.
let target: FuzzyHashCompareTarget = FuzzyHashCompareTarget::from(&hash1);
assert_eq!(target.compare(&hash2), 88);

// If you reuse the same `target` object repeatedly for multiple fuzzy hashes,
// `new` and `init_from` will be helpful.
let mut target: FuzzyHashCompareTarget = FuzzyHashCompareTarget::new();
target.init_from(&hash1);
assert_eq!(target.compare(&hash2), 88);
```

### Introduction to Dual Fuzzy Hashes

It only shows a property of the dual fuzzy hash.  Dual fuzzy hash objects will
be really useful on much, much complex cases.

```rust
// Requires the "alloc" feature to use the `to_string()`-like methods (default enabled).
use ssdeep::{FuzzyHash, DualFuzzyHash};

// "Normalization" would change the contents.
let str1      = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
let str2      = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK";
let str2_norm = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccex:+glvav84a5sxK";
let hash1: FuzzyHash = str::parse(str1).unwrap();
let hash2: DualFuzzyHash = str::parse(str2).unwrap();

// Note that a dual fuzzy hash object efficiently preserves both raw and
// normalized contents of the fuzzy hash.
// *   raw:        "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK"
// *   normalized: "12288:+yUwldx+C5IxJ845HYV5sxOH/cccex:+glvav84a5sxK"
assert_eq!(hash2.to_raw_form_string(),   str2);
assert_eq!(hash2.to_normalized_string(), str2_norm);

// You can use the dual fuzzy hash object
// just like regular fuzzy hashes on some methods.
assert_eq!(hash1.compare(&hash2), 88);
```


## Crate Features

*   `alloc` and `std` (default)  
    This crate supports `no_std` (by disabling both of them) and
    `alloc` and `std` are built on the minimum `no_std` implementation.
    Those features enable implementations that depend on `alloc` and `std`,
    respectively.
*   `easy-functions` (default)  
    It provides easy-to-use high-level functions.
*   `unsafe` (**fast but unsafe**)  
    This crate is optionally unsafe.  By default, this crate is built with 100%
    safe Rust (*this default might change before version 1.0* but safe Rust code
    will be preserved).  Enabling this feature enables unsafe Rust code
    (although unsafe/safe code share the most using macros).
*   `unchecked`  
    This feature exposes `unsafe` functions and methods that don't check the
    validity of the input.  This is a subset of the `unsafe` feature that
    exposes `unsafe` functionalities but does not switch the program to use the
    unsafe Rust.
*   `nightly`  
    This feature enables some features specific to the Nightly Rust.  Note that
    this feature heavily depends on the version of `rustc` and should not be
    considered stable (don't expect SemVer-compatible semantics).
*   `opt-reduce-fnv-table` (not recommended to enable this)  
    ssdeep uses partial (the lowest 6 bits of) FNV hash.  While default table
    lookup instead of full FNV hash computation is faster on most cases, it will
    not affect the performance much on some configurations.
    Enabling this option will turn off using precomputed FNV hash table (4KiB).
    Note that it's not recommended to enable this feature for memory footprint
    since a generator is about 2KiB in size and a temporary object used for
    fuzzy hash comparison is about 1KiB in size (so that reducing 4KiB does not
    benefit well).
*   `tests-slow` and `tests-very-slow`  
    They will enable "slow" (may take seconds or even a couple of minutes) and
    "very slow" (may take more than that) tests, respectively.


## History and Main Contributors of ssdeep

Andrew Tridgell made the program called
["spamsum"](https://www.samba.org/ftp/unpacked/junkcode/spamsum/)
to detect a mail similar to a known spam.

Jesse Kornblum authored the program
["ssdeep"](https://ssdeep-project.github.io/ssdeep/) based on spamsum by adding
solid engine to Andrew's work.
Jesse continued working to improve ssdeep for years.

Helmut Grohne authored his re-written and optimized, streaming fuzzy hashing
engine that enabled multi-threaded runs and a capability to process files
without seeking.

Tsukasa OI, first helped resolving the license issue on the edit distance code
(which was not open source), further optimized the engine and introduced
bit-parallel string processing functions.  He wrote ssdeep compatible engines
multiple times, including [ffuzzy++](https://github.com/a4lg/ffuzzypp).


## License (GNU GPL v2 or later)

This crate (as a whole library) is licensed under the terms of the GNU General
Public License as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

However, some portions are licensed under more permissive licenses (see the
source code for details).


## References

*   Jesse Kornblum (2006)
    "Identifying almost identical files using context triggered piecewise hashing"
    ([doi:10.1016/j.diin.2006.06.015](https://doi.org/10.1016/j.diin.2006.06.015))
