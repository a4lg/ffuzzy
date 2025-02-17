#! /usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

#   Availability of dual block hashes with body and reconstruction
#   lengths, Avail(n, floor(n / 4)) where n ≧ 0, can be easily proven
#   using mathematical induction with following props:
#       1. Avail(B, 0)                    where 0 ≦ B < 4
#       2. Avail(B, R) -> Avail(B+4, R+1)
#   where some of them coming from more generic props:
#       1. Avail(B, 0)                    where 0 ≦ B ≦ MAX_SEQUENCE_SIZE
#       2. Avail(B, R) -> Avail(B+n, R+1) where 1 ≦ n ≦ 4
#       3. Avail(B, R) -> Avail(B,   R+1) [not used]
#       4. 0 ≦ B ≦ MAX_SEQUENCE_SIZE ⇔ 0 ≦ B < 4
#
#   However, actual correspondence to the program is not obvious from
#   the simpler, bottom-up proof since actual dual block hash availability
#   obvious from the program's behavior will be naturally described
#   as a top-down algorithm.
#
#   This is the reason why this program is here.
#
#   It implements a top-down dual block hash availability checking
#   algorithm with memorization (equivalent to the bottom-up proof).
#
#   From given maximum body and reconstruction lengths, this program
#   takes a sequence consisting of the same character, checks whether
#   the number of reconstruction symbols for that sequence are sufficient,
#   then checks availability of remaining lengths recursively.


# Performs a ceiling division
# for a non-negative dividend and a positive divisor.
def div_ceil(a: int, b: int) -> int:
    assert a >= 0 and b > 0
    # ceil(a / b)
    return (a + b - 1) // b


# Sequence and RLE-based reconstruction configuration
MAX_SEQ_LEN: int = 3  # Maximum sequence length (MAX_SEQUENCE_SIZE)
MAX_RLE_LEN: int = 4  # Maximum RLE length per symbol (minimum is always 1)

# All memorized availabilities.
dual_avail: dict[tuple[int, int], bool] = {}


# Log specific event if debugging is enabled.
def log(evt: str, body: int, recn: int):
    DEBUG = False
    # Digits to print
    D_EVENT = 2
    D_BODY = 2
    D_RECN = 2
    if DEBUG:
        print(f'{evt:<{D_EVENT}} {body:{D_BODY}} {recn:{D_RECN}}')


# Dual block hash available checker (wrapper with memorization)
def is_dual_block_available(body: int, recn: int) -> bool:
    if (body, recn) not in dual_avail:
        # Call availability checker body if not checked yet.
        dual_avail[(body, recn)] = is_dual_block_available_body(body, recn)
    return dual_avail[(body, recn)]


# Dual block hash available checker (body)
def is_dual_block_available_body(body: int, recn: int) -> bool:
    assert body >= 0 and recn >= 0
    log('C', body, recn)
    # If a raw body can be represented without any RLE symbols,
    # dual block hash is available on given lengths.
    if body <= MAX_SEQ_LEN:
        return True
    # Take a sequence of given length.
    for seq_len in range(1, body + 1):
        # Compute number of RLE symbols to consume.
        num_syms = 0
        if seq_len > MAX_SEQ_LEN:
            num_syms = div_ceil(seq_len - MAX_SEQ_LEN, MAX_RLE_LEN)
        # If required RLE symbol count exceeds remaining storage, unavailable.
        if num_syms > recn:
            log('D1', body, recn)
            return False
        # Check remaining lengths (excluding consumed parts) recursively.
        if not is_dual_block_available(body - seq_len, recn - num_syms):
            log('D2', body, recn)
            return False
    # All sequence lengths are checked and found all are available.
    return True


if __name__ == '__main__':
    # Avail(n, floor(n / 4)) for n in 0..=64
    for n in range(0, 64 + 1):
        if not is_dual_block_available(n, n // 4):
            raise AssertionError()
    # Availability: block hash 2 of DualFuzzyHash
    print(f'{is_dual_block_available(32,  8)=}')
    # Availability: block hash 1 of DualFuzzyHash
    # Availability: block hash 1 of LongDualFuzzyHash
    # Availability: block hash 2 of LongDualFuzzyHash
    print(f'{is_dual_block_available(64, 16)=}')
