// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

use std::process;

fn main() {
    const MULTIPLIER: u32 = 3;
    const BITS_TO_COVER: u32 = MULTIPLIER.leading_zeros() + 1;
    const SHIFT_WIDTH: u32 = u32::BITS.leading_zeros() + 1;

    // Parameter constraints for ssdeep
    assert!(MULTIPLIER == 3);
    assert!(BITS_TO_COVER == 31);
    assert!(SHIFT_WIDTH == 27);

    // Search a variant of de Bruijn sequence
    fn debruijn_index(index: u32, debruijn_mul: u32) -> u32 {
        (MULTIPLIER << index).wrapping_mul(debruijn_mul) >> SHIFT_WIDTH
    }
    for debruijn_mul in ((1u32 << (SHIFT_WIDTH - 1)) / MULTIPLIER)..=u32::MAX {
        let mut table_fill: u32 = 0;
        for i in 0..BITS_TO_COVER {
            table_fill |= 1u32 << debruijn_index(i, debruijn_mul);
        }
        if table_fill.count_ones() == BITS_TO_COVER {
            let mut table: [u8; 32] = [0xff; 32];
            for i in 0..BITS_TO_COVER {
                table[debruijn_index(i, debruijn_mul) as usize] = i as u8;
            }
            println!("const LOG_DEBRUIJN_CONSTANT: u32 = 0x{:08x};", debruijn_mul);
            println!("#[rustfmt::skip]");
            println!("const LOG_DEBRUIJN_TABLE: [u8; 32] = [");
            for j in 0..table.len() {
                if j % 8 == 0 {
                    print!("   ");
                }
                print!(" 0x{:02x},", table[j]);
                if j % 8 == 7 || j == table.len() - 1 {
                    println!("");
                }
            }
            println!("];");
            process::exit(0);
        }
    }
    process::exit(1);
}
