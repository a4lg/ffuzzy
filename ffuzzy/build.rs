// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023, 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

extern crate version_check as rustc;

fn main() {
    // Avoid unnecessary rebuilding.
    println!("cargo:rerun-if-changed=build.rs");

    // Module: std::os::fd
    //  available: 1.66- (stable)
    println!(
        "cargo:rustc-check-cfg=cfg(\
            ffuzzy_os_fd, \
            values(\
                \"stable\"\
            )\
        )"
    );
    if rustc::is_min_version("1.66.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_os_fd=\"stable\"");
    }

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

    // (1) Method: core::hint::assert_unchecked
    // unstable: 1.77-1.80 (not used; instead using our own fallback)
    //   stable: 1.81-
    // (2) Module: core::error
    // unstable: 1.65-1.80 (not implemented)
    //   stable: 1.81-
    println!(
        "cargo:rustc-check-cfg=cfg(\
            ffuzzy_assume, \
            values(\
                \"stable\", \
                \"fallback\"\
            )\
        )"
    );
    println!(
        "cargo:rustc-check-cfg=cfg(\
            ffuzzy_error_in_core, \
            values(\
                \"stable\"\
            )\
        )"
    );
    if rustc::is_min_version("1.81.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=ffuzzy_assume=\"stable\"");
        println!("cargo:rustc-cfg=ffuzzy_error_in_core=\"stable\"");
    } else {
        println!("cargo:rustc-cfg=ffuzzy_assume=\"fallback\"");
    }

    // Other cfgs (rustc-check-cfg)
    println!("cargo:rustc-check-cfg=cfg(ffuzzy_tests_without_debug_assertions)");
}
