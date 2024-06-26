// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

extern crate version_check as rustc;

fn main() {
    // Avoid unnecessary rebuilding.
    println!("cargo:rerun-if-changed=build.rs");

    // Method: {Integer}::ilog2
    //  log2: 1.55-1.64 (not used; instead using our own fallback)
    // ilog2: 1.65-1.66 (not used; instead using our own fallback)
    // ilog2: 1.67-     (stable)
    println!(
        "cargo:rustc-check-cfg=cfg(\
            ffuzzy_ilog2, \
            values(\
                \"stable\", \
                \"fallback\"\
            )\
        )"
    );
    if rustc::is_min_version("1.67.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"stable\"");
    } else {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"fallback\"");
    }

    // Method: {Integer}::div_ceil
    // unstable_div_ceil: 1.56-1.58 (not used; instead using our own fallback)
    //          div_ceil: 1.59-1.72 (not used; instead using our own fallback)
    //          div_ceil: 1.73-     (stable)
    println!(
        "cargo:rustc-check-cfg=cfg(\
            ffuzzy_div_ceil, \
            values(\
                \"stable\", \
                \"fallback\"\
            )\
        )"
    );
    if rustc::is_min_version("1.73.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"stable\"");
    } else {
        println!("cargo:rustc-cfg=ffuzzy_div_ceil=\"fallback\"");
    }

    // Other cfgs (rustc-check-cfg)
    println!("cargo:rustc-check-cfg=cfg(ffuzzy_tests_without_debug_assertions)");
}
