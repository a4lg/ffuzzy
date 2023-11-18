// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Result, Write};
use std::path::Path;
use std::process;

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
    }
    else if rustc::is_feature_flaggable().unwrap_or(false)
        && rustc::is_min_version("1.65.0").unwrap_or(false)
    {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable\"");
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable_v2\"");
    }
    else if rustc::supports_feature("int_log").unwrap_or(false) {
        // Rust 1.55-
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable\"");
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"unstable_v1\"");
    }
    else {
        println!("cargo:rustc-cfg=ffuzzy_ilog2=\"fallback\"");
    }

    // OUT_DIR environment variable
    let out_dir = &env::var_os("OUT_DIR")
        .unwrap_or_else(|| die("error: environment variable `OUT_DIR' not found."));

    // Generate FNV table
    generate_fnv_table(out_dir)
        .unwrap_or_else(|err| die(
            format!("${{OUT_DIR}}/fnv_table_contents.rs: {}", err).as_str()
        ));
}

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    process::exit(1)
}


fn generate_fnv_table(out_dir: &OsString) -> Result<()> {
    const ALPHABET_SIZE: usize = 64;
    const OLD_HASH_INIT: u32 = 0x28021967;
    const OLD_HASH_PRIME: u32 = 0x01000193;

    #[inline]
    fn old_fnv_hash_update(state: u32, ch: u8) -> u32 {
        // This is the port of sum_hash function in fuzzy.c (version 2.0-2.13).
        (state.wrapping_mul(OLD_HASH_PRIME)) ^ (ch as u32)
    }

    #[inline]
    fn new_fnv_hash_update(state: u8, ch: u8) -> u8 {
        (old_fnv_hash_update(state as u32, ch) % ALPHABET_SIZE as u32) as u8
    }

    let mut file = File::create(Path::new(out_dir).join("fnv_table_contents.rs"))?;
    write!(
        file,
        r#"// This is an auto-generated file.
use crate::hash::block::block_hash;

const OLD_HASH_INIT: u32 = 0x{0:08x};
pub(crate) const FNV_HASH_INIT: u8 = (OLD_HASH_INIT % block_hash::ALPHABET_SIZE as u32) as u8;
pub(crate) const _ALPHABET_SIZE: usize = 0x{2:x};

#[cfg(feature = "opt-reduce-fnv-table")]
pub(crate) const FNV_HASH_PRIME: u32 = 0x{1:08x};

#[cfg(not(feature = "opt-reduce-fnv-table"))]
pub(crate) const FNV_TABLE: [[u8; block_hash::ALPHABET_SIZE]; block_hash::ALPHABET_SIZE] = [
"#,
        OLD_HASH_INIT,
        OLD_HASH_PRIME,
        ALPHABET_SIZE
    )?;
    for state in 0..ALPHABET_SIZE as u8 {
        writeln!(file, "    [ // 0x{:02x}", state)?;
        for ch in 0..ALPHABET_SIZE as u8 {
            if ch % 16 == 0 {
                write!(file, "        ")?;
            }
            write!(file, "0x{:02x},", new_fnv_hash_update(state, ch))?;
            if ch % 16 == 16 - 1 || ch == ALPHABET_SIZE as u8 - 1 {
                writeln!(file)?;
            } else {
                write!(file, " ")?;
            }
        }
        writeln!(file, "    ],")?;
    }
    writeln!(file, "];")?;
    Ok(())
}
