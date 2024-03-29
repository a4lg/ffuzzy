// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

extern crate version_check as rustc;

fn main() {
    // Avoid unnecessary rebuilding.
    println!("cargo:rerun-if-changed=build.rs");

    // Method: {Integer}::ilog2
    //  log2: 1.55-1.64 ("int_log" unstable feature)
    // ilog2: 1.65-1.66 ("int_log" unstable feature)
    // ilog2: 1.67-     (stable)
    if rustc::is_min_version("1.67.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"stable\"");
    } else if rustc::is_feature_flaggable().unwrap_or(false)
        && rustc::is_min_version("1.65.0").unwrap_or(false)
    {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable\"");
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable_v2\"");
    } else if rustc::supports_feature("int_log").unwrap_or(false) {
        // Rust 1.55-
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable\"");
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable_v1\"");
    } else {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"fallback\"");
    }

    // Method: {Integer}::div_ceil
    // unstable_div_ceil: 1.56-1.58 ("int_roundings" unstable feature; not to support)
    //          div_ceil: 1.59-1.72 ("int_roundings" unstable feature)
    //          div_ceil: 1.73-     (stable)
    if rustc::is_min_version("1.73.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"stable\"");
    } else if rustc::is_feature_flaggable().unwrap_or(false)
        && rustc::is_min_version("1.59.0").unwrap_or(false)
    {
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"unstable\"");
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"unstable_v2\"");
        // Note:
        // No plan to support unstable_v1 (with the name unstable_div_ceil).
    } else {
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"fallback\"");
    }
}
