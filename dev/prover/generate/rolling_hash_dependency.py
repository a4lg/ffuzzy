#! /bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

import sys
import z3

def DeMorganNot(and_clauses):
    # Convert AND clauses and get the complement expression
    # (e.g. for X && Y [and_clauses], return !(X && Y) == (!X || !Y))
    return z3.Or(*[z3.Not(p) for p in and_clauses])

def FindCounterexamples(name, constraints):
    print('Whether {} has a counterexample... '.format(name), file=sys.stderr, end='')
    sys.stderr.flush()
    solver = z3.Solver()
    for constraint in constraints:
        solver.add(constraint)
    result = solver.check()
    if result == z3.sat:
        print('found!\n\nCounterexample:', file=sys.stderr)
        model = solver.model()
        for d in sorted(model.decls(), key=str):
            print('{} = {}'.format(d, model[d]))
        sys.exit(1)
    else:
        print('not found.', file=sys.stderr)



# Rolling hash parameters
BITS_OF_WORD = 32
BITS_OF_BYTE = 8
ROLLING_WINDOW = 7
H3_LSHIFT = 5
assert(BITS_OF_BYTE <= BITS_OF_WORD)
class RollingHash:
    def __init__(self, name):
        self.n_bytes = 0
        self.h1 = z3.BitVec('{}_h1'.format(name), BITS_OF_WORD)
        self.h2 = z3.BitVec('{}_h2'.format(name), BITS_OF_WORD)
        self.h3 = z3.BitVec('{}_h3'.format(name), BITS_OF_WORD)
        self.window = [
            z3.BitVec('{}_wi_{}'.format(name, i), BITS_OF_BYTE) for i in range(ROLLING_WINDOW)
        ]
        self.constraints = [
            self.h1 == 0,
            self.h2 == 0,
            self.h3 == 0,
        ]
        self.constraints += [
            self.window[i] == 0 for i in range(ROLLING_WINDOW)
        ]
    def update(self, ch):
        ch_word = z3.ZeroExt(BITS_OF_WORD - BITS_OF_BYTE, ch)
        fading_byte = self.window[0]
        fading_word = z3.ZeroExt(BITS_OF_WORD - BITS_OF_BYTE, fading_byte)
        self.window[0:1] = []
        self.h2 = self.h2 - self.h1
        self.h2 = self.h2 + ROLLING_WINDOW * ch_word
        self.h1 = self.h1 + ch_word
        self.h1 = self.h1 - fading_word
        self.h3 = self.h3 << H3_LSHIFT
        self.h3 = self.h3 ^ ch_word
        self.window.append(ch)


# Old (fading) bytes (as prefix)
old_1 = [z3.BitVec('o1_{}'.format(i), BITS_OF_BYTE) for i in range(ROLLING_WINDOW)]
old_2 = [z3.BitVec('o2_{}'.format(i), BITS_OF_BYTE) for i in range(ROLLING_WINDOW)]
# New updating bytes
new_b = [z3.BitVec('n__{}'.format(i), BITS_OF_BYTE) for i in range(ROLLING_WINDOW)]

for initial_old in range(0, ROLLING_WINDOW + 1):
    r1 = RollingHash('r1')
    r2 = RollingHash('r2')
    for i in range(initial_old):
        r1.update(old_1[i])
        r2.update(old_2[i])
    for i in range(ROLLING_WINDOW):
        r1.update(new_b[i])
        r2.update(new_b[i])
    # Make sure that the rolling hash values only depend on
    # the last ROLLING_WINDOW bytes.
    FindCounterexamples(
        "Rolling hash dependency (prefix: {})".format(initial_old),
        r1.constraints + r2.constraints + \
        [DeMorganNot([
            r1.h1 == r2.h1,
            r1.h2 == r2.h2,
            r1.h3 == r2.h3,
        ])]
    )
    # Make sure that the window is completely overwritten by new updating bytes.
    assert(r1.window == new_b)
    assert(r2.window == new_b)
