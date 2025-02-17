// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2025

//! Internal modules.
//!
//! Previously, internal modules were declared just under the crate root.
//!
//! However, since it is known that exporting now [`crate::internals::hash`] as
//! `crate::hash` (for example) causes difficulties maintaining public names,
//! this crate now completely separates public and private parts
//! and all private parts (except root tests, crate global items and
//! documentation-only items) are implemented under this module.
//!
//! Public parts are implemented in the crate root by re-exporting
//! *all* public names.

pub mod base64;
pub mod compare;
pub mod compare_easy;
pub mod generate;
pub mod generate_easy;
pub mod generate_easy_std;
pub mod hash;
pub mod hash_dual;
pub mod intrinsics;
pub mod macros;
pub mod test_utils;
pub mod utils;
