# Implementation Notes

This page lists some implementation notes for developers.


## `unsafe` Rust which looks like safe Rust

In this crate, the main motivation to use `unsafe` is to suppress array
bounds checks (that are known to be safe according to the code review or
should be safe if public functions / methods are used correctly).

However, if we use pointers, we cannot easily switch between safe and unsafe
Rust variants.  We chose to use "invariants" instead.  If Rust / LLVM knows
that an array access is safe, it skips bounds check.  So, we can put an
invariant to tell the optimizer that the array access is safe.  Despite that
generating an invariant itself is an unsafe operation, most code looks
like safe Rust.

Invariants can suppress another type of runtime check (not just array
bounds check): division by zero.

A big exception is the
[generator's main loop](crate::internals::generate::Generator::update()).
Because using pointer-based block hash context access is much efficient (we
can even reuse pointer ranges), the structure of this loop changes
significantly between both implementations.
But still, most of the code is shared.


## Methods: Non-suffixed, `unchecked` and `internal`

Non-suffixed version is the safest version for regular users and is safe (or
to be more precise, optionally unsafe).  It checks validity of
user-specified arguments properly.

Still, it can be a waste of time if the user knows what he/she's doing.

`unchecked` version is exported and is marked `unsafe`.
It doesn't check whether certain "Usage Constraints" are satisfied.
It can be useful on some specialized clustering applications.

The crate developers also know (and/or *should* know) certain constraints
are satisfied already and want to avoid `unsafe` blocks as well as excess
argument checking.

`internal` version is safe but not exported.  The crate developers must be
aware of the constraints and must satisfy them before calling.
Note that, most of `unchecked` functions are just wrappers of
`internal` functions.  If both `unchecked` and `internal` versions exist,
the only purpose of `internal` is to avoid `unsafe`.

As an exception, if a `struct` is already broken by a memory corruption
caused by something outside this crate or a misuse of `unchecked` functions,
it's not obligated to check such corruption
(the crate developers can assume that `struct` is not "very" broken).

Note that, `internal` version may be existing just to notify the developers
that there are special constraints or invariants before/after calling the
function.  On such cases, `unchecked` version may be absent and even
unprefixed version may be, too.

### Links (to non-suffixed methods)

*   [`crate::internals::compare::FuzzyHashCompareTarget::raw_score_by_edit_distance()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::score_cap_on_block_hash_comparison()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::compare_unequal_near_eq()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::compare_near_eq()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::compare_unequal_near_lt()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::compare_unequal_near_gt()`]
*   [`crate::internals::compare::FuzzyHashCompareTarget::compare_unequal()`]
*   [`crate::internals::compare::position_array::BlockHashPositionArrayImpl::is_equiv()`]
*   [`crate::internals::compare::position_array::BlockHashPositionArrayImpl::has_common_substring()`]
*   [`crate::internals::compare::position_array::BlockHashPositionArrayImpl::edit_distance()`]
*   [`crate::internals::compare::position_array::BlockHashPositionArrayImpl::score_strings_raw()`]
*   [`crate::internals::compare::position_array::BlockHashPositionArrayImpl::score_strings()`]
*   [`crate::internals::hash::FuzzyHashData::compare_unequal()`]
*   [`crate::internals::hash::FuzzyHashData::init_from_internals_raw()`]
*   [`crate::internals::hash::FuzzyHashData::new_from_internals()`]
*   [`crate::internals::hash::FuzzyHashData::new_from_internals_near_raw()`]
*   [`crate::internals::hash::FuzzyHashData::new_from_internals_raw()`]
*   [`crate::internals::hash::block::block_size::from_log()`] ([`Option`] is used instead of assertions)
*   [`crate::internals::hash::block::block_size::log_from_valid()`]
