# Planned Breaking Changes

This page lists (incomplete) list of planned changes
on the next major release (most likely version 0.4).


## Major design change (and `prelude` module)

Since the next major release will heavily utilize traits and for better
ergonomics, you will want to import [`ssdeep::prelude::*`](crate::prelude).

This module is added (as an empty module) in version 0.3.13 for transition.


## Stabilization of RLE-based compression in dual fuzzy hashes

We found no issues on dual fuzzy hashes and recognized that separately storing
"reverse normalization" data is helpful on some cases.

So, the next major release will stabilize currently internal RLE-based
compression used by dual fuzzy hashes.

Also, we will attempt to reduce memory footprint and if (and only if) we are
sure that this is performant enough (considering the use cases), the compression
ratio will be improved from ≒5/8 to ≒1/2(=4/8) (with the exact same size as the
one fuzzy hash, it will be able to represent both normalized and raw contents).


## MSRV

Depending on the Rust edition target (we haven't decided yet),
MSRV on the next major release will be raised to the version specific
to that edition.

*   Edition 2021 case: at least 1.79 (most likely 1.83)  
    Rust 1.79's associated type bounds feature makes our new trait-based design
    far more easier.
*   Edition 2024 case (more likely): 1.85 (not released yet)


## Features

### Removal of `strict-parser`

Simply, the next version will make this default and there will be no option
to disable that strict behavior.

### Removal of `opt-reduce-fnv-table`

This feature is rather subtractive than recommended additive feature rules
(although not completely against it) and the change is too subtle (memory
footprint of 4KiB can be easily justified on the environment which ssdeep
hashes are generated).

So, this feature is going to be removed on the next major release.

It may return in the future when fine-tuning is absolutely necessary in this
crate (but unlikely; since considered optimal algorithms are *far* better
than past alternatives).

### Removal of `nightly` (use `unstable` instead)

Currently, the `unstable` feature is preferred to use Nightly Rust features.
`nightly` is preserved as an alias of `unstable` (although being undocumented)
but will be removed on the next major release.

### Removal of `tests-very-slow`

Since commit `96dfea7d4fd5` (a part of version 0.3.1), `tests-very-slow` was
empty for a long time.  Since there's no very time-consuming (hours-taking)
tests, this feature is going to be removed.


## Coverage: Removing grcov support

The support for grcov is going to be removed in the next major release because
(along with Nightly compiler) cargo-llvm-cov supports taking a branch coverage
and required many comments to control grcov behavior because of grcov not
knowing implicit branches (e.g. when accessing slices, defining struct
members).


## Removal (because of being deprecated)

### [`From`] implementation from Raw to Normalized variants

Because it is found that it breaks a semantic rule of the [`From`] trait,
conversion from raw fuzzy hash to normalized fuzzy hash as an implementation of
[`From`] is deprecated and will be removed on the next major release.

To convert a raw fuzzy hash to the normalized counterpart, you must use
`normalize()`-like methods (may be renamed in the next release but the
conversion feature itself will be preserved).

### `+=` operator overloads

Since it's clear that this operator overload is not helpful enough,
they are now deprecated and will be removed on the next major release.


## Removal (temporally)

### Numeric windows

[`crate::block_hash::NumericWindows`] is going to be removed temporally.

This is because the iterator which iterates more natural index values:
[`crate::block_hash::IndexWindows`] is there (note that how to access this kind
of iterator will change in an incompatible way).

[`crate::block_hash::NumericWindows`] will be back if removing it
can be a problem for some use cases.


## Removal (for other reasons)

### `FuzzyHashData::IS_*_FORM` (and related constants)

[`crate::FuzzyHashData::IS_NORMALIZED_FORM`] and
[`crate::FuzzyHashData::IS_LONG_FORM`] (and related constants) will be removed
because of consistency issues on the new trait-based design (it's easy to keep
those but traits will not have easy access to them) and
because we have a workaround.


## Going to be Private: Internal Hashes / Comparison Structures

They were useful to experiment with ssdeep internals but we could not justify
keeping them public.  If you need to use those, just vendor the source code
for your needs (they are relatively simple and will be easy to vendor them).

Two internal hashes for fuzzy hash generator is separated to new internal
modules to make vendoring the source code much easier (although not completely
separate from the rest, it should be easy to cut the dependencies).

For specific needs, a comparison target storing just one block hash (instead of
two block hashes) will be public as a new type.
