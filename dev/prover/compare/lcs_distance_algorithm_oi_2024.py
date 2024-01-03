#! /bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

import sys
import z3

####
####    NOT IN THIS PROOF:
####
####    Each DP cell (x,y) only depends on (x',y')
####        where x' <= x && y' <= y && (x != x' && y != y'),
####    making the whole algorithm usable to the strings
####    shorter than STRLEN below (on the bit-parallel algorithm,
####    ignoring upper bits will work).
####

# (Maximum) string 1 length and the word size in the bit-parallel algorithm.
STRLEN = 64

# For variable naming
DIGITS = len(str(STRLEN))
DIGIT_FORMAT = '{{:0{}}}'.format(DIGITS)

def Min(a, b):
    return z3.If(a < b, a, b)
def Min3(a, b, c):
    return Min(a, Min(b, c))

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



##
##  DP algorithm to calculate the LCS distance
##  between string 1 and string 2
##

# Row 0: The previously calculated row
dp_row0 = []
# Row 1: The current row (to calculate)
dp_row1 = []
# On the current row (with a character from string 2),
# whether the character matches to the i-th character of the string 1.
dp_char_equal = []

for i in range(-1, STRLEN):
    dp_row0.append(z3.Int('dp_R0_' + DIGIT_FORMAT.format(i)))
    dp_row1.append(z3.Int('dp_R1_' + DIGIT_FORMAT.format(i)))
for i in range(STRLEN):
    dp_char_equal.append(z3.Bool('b_E_' + DIGIT_FORMAT.format(i)))

constraints_dp_row0 = []
constraints_dp_row1_init = []
constraints_dp_row1_calc = []
constraints_dp_row1_post = []
constraints_dp_rows_post = []
# Results of the previous row
for i in range(STRLEN):
    # Row0: adjacent columns have horizontal differences of either +1 or -1.
    # This is a definition for the first row (where the differences are all +1).
    # For other rows, it is to be proven below.
    constraints_dp_row0.append(z3.Or(
        dp_row0[i+1] - dp_row0[i] ==  1,
        dp_row0[i+1] - dp_row0[i] == -1
    ))
# Initialization of the first column of the current row
constraints_dp_row1_init.append(dp_row1[0] == dp_row0[0] + 1)
# Calculation of the current row (remaining columns corresponding string 1)
for i in range(STRLEN):
    constraints_dp_row1_calc.append(dp_row1[i+1] == Min3(
        dp_row0[i+1] + 1,
        dp_row1[i  ] + 1,
        dp_row0[i  ] + z3.If(dp_char_equal[i], 0, 2)
    ))

# Post condition of the current row after the calculation of the current row
for i in range(STRLEN):
    # Horizontal difference is always either 1 or -1
    constraints_dp_row1_post.append(z3.Or(
        dp_row1[i+1] - dp_row1[i] ==  1,
        dp_row1[i+1] - dp_row1[i] == -1
    ))
# Make sure that the post condition is satisfied.
if True:
    FindCounterexamples(
        'DP post condition (horizontal)',
        constraints_dp_row0 + constraints_dp_row1_init + constraints_dp_row1_calc + \
        [DeMorganNot(constraints_dp_row1_post)]
    )

# Post condition between two rows after the calculation of the current row
for i in range(-1, STRLEN):
    # Vertical difference is always either 1 or -1
    constraints_dp_rows_post.append(z3.Or(
        dp_row1[i+1] - dp_row0[i+1] ==  1,
        dp_row1[i+1] - dp_row0[i+1] == -1
    ))
# Make sure that the post condition is satisfied.
if True:
    FindCounterexamples(
        'DP post condition (vertical)',
        constraints_dp_row0 + constraints_dp_row1_init + constraints_dp_row1_calc + \
        [DeMorganNot(constraints_dp_rows_post)]
    )

constraints_dp = \
    constraints_dp_row0 + \
    constraints_dp_row1_init + \
    constraints_dp_row1_calc + \
    constraints_dp_row1_post + \
    constraints_dp_rows_post



##
##  DP algorithm, converted to boolean expressions
##  and encoded as "differences".
##
constraints_b_V = []    # Vertical differences
constraints_b_P = []    # Horizontal differences (on the previous row)
constraints_b_H = []    # Horizontal differences (on the current row)

constraints_b_H_calc = []
constraints_b_V_calc = []

# On the current row (with a character from string 2),
# whether the character matches to the i-th character of the string 1.
b_E = dp_char_equal

# Vertical differences (True if the vertical difference is +1)
b_V = []
for i in range(-1, STRLEN):
    b_V.append(z3.Bool('b_V_' + DIGIT_FORMAT.format(i)))
    constraints_b_V.append(b_V[i+1] == (dp_row1[i+1] - dp_row0[i+1] == 1))

# Horizontal differences (likewise)
b_P = []    # Previous row
b_H = []    # Current row
for i in range(STRLEN):
    b_P.append(z3.Bool('b_P_' + DIGIT_FORMAT.format(i)))
    b_H.append(z3.Bool('b_H_' + DIGIT_FORMAT.format(i)))
    constraints_b_P.append(b_P[i] == (dp_row0[i+1] - dp_row0[i] == 1))
    constraints_b_H.append(b_H[i] == (dp_row1[i+1] - dp_row1[i] == 1))

# Calculation of horizontal differences
# H[ 0, 0] == 1 <-> V[ 0,-1] == 0 || (H[-1, 0] == 1 && E[ 0, 0] == 0)
for i in range(STRLEN):
    constraints_b_H_calc.append(
        b_H[i] == z3.Or(z3.Not(b_V[i+0]), z3.And(b_P[i], z3.Not(b_E[i]))))
# Make sure that this conversion is valid.
if True:
    FindCounterexamples(
        'DP-BOOL calculation (horizontal)',
        constraints_dp + \
        constraints_b_V + constraints_b_P + constraints_b_H + \
        [DeMorganNot(constraints_b_H_calc)]
    )

# Calculation of vertical differences
# V[ 0, 0] == 1 <-> H[-1, 0] == 0 || (V[ 0,-1] == 1 && E[ 0, 0] == 0)
# (except b_V_-1, which is always True because of the row initialization)
for i in range(-1, STRLEN):
    if i == -1:
        constraints_b_V_calc.append(b_V[i+1])
    else:
        # Beware that b_V[i+1] depends on b_V[i+0],
        # making the bit-parallel calculation of V below not simple.
        constraints_b_V_calc.append(
            b_V[i+1] == z3.Or(z3.Not(b_P[i]), z3.And(b_V[i+0], z3.Not(b_E[i]))))
# Make sure that this conversion is valid.
if True:
    FindCounterexamples(
        'DP-BOOL calculation (vertical)',
        constraints_dp + \
        constraints_b_V + constraints_b_P + constraints_b_H + \
        constraints_b_H_calc + \
        [DeMorganNot(constraints_b_V_calc)]
    )

constraints_dp_bool = \
    constraints_b_V + \
    constraints_b_P + \
    constraints_b_H + \
    constraints_b_H_calc + \
    constraints_b_V_calc



##
##  The bit-parallel LCS distance algorithm by Tsukasa OI (2024),
##  inspired by the concept of Myers (1999) but simplified
##  using the "parity" relations.
##

# V (representing vertical differences) omits index -1,
# making all four bit vectors' length STRLEN.
V = z3.BitVec('V', STRLEN)
P = z3.BitVec('P', STRLEN)
H = z3.BitVec('H', STRLEN)
E = z3.BitVec('E', STRLEN)

# Each bits of V, H and E.
Vs = [z3.Extract(i, i, V) for i in range(STRLEN)]
Ps = [z3.Extract(i, i, P) for i in range(STRLEN)]
Hs = [z3.Extract(i, i, H) for i in range(STRLEN)]
Es = [z3.Extract(i, i, E) for i in range(STRLEN)]

# Correspondence between DP-BOOL variables and bit vectors.
constraints_bitpar_dp_bool = []
for i in range(STRLEN):
    constraints_bitpar_dp_bool.append(b_V[i+1] == (Vs[i] == 1))
    constraints_bitpar_dp_bool.append(b_P[i  ] == (Ps[i] == 1))
    constraints_bitpar_dp_bool.append(b_H[i  ] == (Hs[i] == 1))
    constraints_bitpar_dp_bool.append(b_E[i  ] == (Es[i] == 1))

# Calculation of vertical differences
# (horizontal dependency resolved using Myers (1999))
X = ~P | (~E & 1)
Y = ~E >> 1
constraints_bitpar_V_calc = [
    V == (((X & Y) + Y) ^ Y) | X
]
if True:
    FindCounterexamples(
        'Bit-parallel calculation (vertical)',
        constraints_dp + constraints_dp_bool + \
        constraints_bitpar_dp_bool + \
        [DeMorganNot(constraints_bitpar_V_calc)]
    )

# Calculation of horizontal differences
constraints_bitpar_H_calc = [
    H == ~((V << 1) | 1) | (P & ~E)
]
if True:
    FindCounterexamples(
        'Bit-parallel calculation (horizontal)',
        constraints_dp + constraints_dp_bool + \
        constraints_bitpar_dp_bool + \
        constraints_bitpar_V_calc + \
        [DeMorganNot(constraints_bitpar_H_calc)]
    )

constraints_bitpar = \
    constraints_bitpar_dp_bool + \
    constraints_bitpar_V_calc + \
    constraints_bitpar_H_calc



##
##  Further optimization (minor)
##

# (-1)-st bit of V in DP-BOOL domain is True and the original expression
# reflected that.  But this expression can be simplified as follows:
constraints_bitpar_H_opt_calc = [
    H == (~V << 1) | (P & ~E)
]
if True:
    FindCounterexamples(
        'Bit-parallel calculation (horizontal; optimized)',
        constraints_dp + constraints_dp_bool + constraints_bitpar + \
        [DeMorganNot(constraints_bitpar_H_opt_calc)]
    )



##
##  Old bit-parallel LCS distance algorithm based on Hyyrö et al. (2005),
##  heavily modified to calculate pure LCS distance between two strings.
##
##  This customized algorithm was written by Tsukasa OI for ssdeep 2.14.
##

# Note:
# "Vertical" and "horizontal" are swapped between Hyyrö et al. (2005)
# and OI (2024).  So, the original "pv" and "nv" are substituted to
# P (previous horizontal differences) and ~P (the complement of that) here.

# Calculation of horizontal differences and compare
# with the latest simplified algorithm.
ZD = (((E & P) + P) ^ P) | E | ~P
NH = P & ZD
X_ = ~P | ~(P | ZD) | (P & ~E & 1)
Y_ = (P - NH) >> 1
PH = (X_ + Y_) ^ Y_
constraints_bitpar_old_V_calc = [
    V == PH,
    NH == ~PH   # PH and NH are complements
]
if True:
    FindCounterexamples(
        'Old bit-parallel calculation (vertical)',
        constraints_dp + constraints_dp_bool + constraints_bitpar + \
        [DeMorganNot(constraints_bitpar_old_V_calc)]
    )

# Calculation of horizontal differences and compare
# with the latest simplified algorithm.
T = (PH << 1) | 1
NV = T & ZD
PV = (NH << 1) | ~(T | ZD) | (T & (P - NH))
constraints_bitpar_old_H_calc = [
    H == PV,
    NV == ~PV   # PV and NV are complements
]
if True:
    FindCounterexamples(
        'Old bit-parallel calculation (horizontal)',
        constraints_dp + constraints_dp_bool + constraints_bitpar + \
        [DeMorganNot(constraints_bitpar_old_H_calc)]
    )

sys.exit(0)
