// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

use std::process;

fn main() {
    for debruijn_mul in ((((1u32 << 27) / 3) | 1)..=u32::MAX).step_by(2) {
        let mut table_fill: u32 = 0;
        for i in 0..31 {
            table_fill |= 1u32 << ((3u32 << i).wrapping_mul(debruijn_mul) >> 27);
        }
        if table_fill.count_ones() == 31 {
            let mut table: [u8; 32] = [0xff; 32];
            for i in 0..31 {
                table[((3u32 << i).wrapping_mul(debruijn_mul) >> 27) as usize] = i as u8;
            }
            println!("const LOG_DEBRUIJN_CONSTANT: u32 = 0x{:08x};", debruijn_mul);
            println!("const LOG_DEBRUIJN_TABLE: [u8; 32] = [");
            for j in 0..32 {
                if j % 8 == 0 {
                    print!("   ");
                }
                print!(" 0x{:02x},", table[j]);
                if j % 8 == 7 {
                    println!("");
                }
            }
            println!("];");
            process::exit(0);
        }
    }
    process::exit(1);
}
