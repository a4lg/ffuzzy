#! /bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2024 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

import functools
import sys
import z3

# (Maximum) string 1 length and the word size in the bit-parallel algorithm.
STRLEN = 64

# For variable naming
DIGITS = len(str(STRLEN))
DIGIT_FORMAT = '{{:0{}}}'.format(DIGITS)

def Max(a, b):
    return z3.If(a > b, a, b)

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
##  DP algorithm to calculate the LCS length
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
constraints_dp_rows_init = []
constraints_dp_row1_calc = []
constraints_dp_row1_post = []
constraints_dp_rows_post = []
constraints_dp_llcs_post = []
# Initialization of the first column of the both rows
constraints_dp_rows_init = [
    dp_row1[0] == 0,
    dp_row0[0] == 0,
]
# Results of the previous row
for i in range(STRLEN):
    # Row0: adjacent columns have horizontal differences of either 0 or +1.
    # This is a definition for the first row (where the differences are all 0).
    # For other rows, it is to be proven below.
    constraints_dp_row0.append(z3.Or(
        dp_row0[i+1] - dp_row0[i] == 0,
        dp_row0[i+1] - dp_row0[i] == 1
    ))
# Calculation of the current row (remaining columns corresponding string 1)
for i in range(STRLEN):
    constraints_dp_row1_calc.append(dp_row1[i+1] == z3.If(
        dp_char_equal[i], dp_row0[i] + 1,
        Max(dp_row0[i+1], dp_row1[i])
    ))

# Post condition of the current row after the calculation of the current row
for i in range(STRLEN):
    # Hyyrö, 2017: Observation 1.
    # Horizontal difference is always either 0 or +1
    constraints_dp_row1_post.append(z3.Or(
        dp_row1[i+1] - dp_row1[i] == 0,
        dp_row1[i+1] - dp_row1[i] == 1
    ))
# Make sure that the post condition is satisfied.
if True:
    FindCounterexamples(
        'DP post condition (horizontal)',
        constraints_dp_row0 + constraints_dp_rows_init + constraints_dp_row1_calc + \
        [DeMorganNot(constraints_dp_row1_post)]
    )

# Post condition between two rows after the calculation of the current row
for i in range(-1, STRLEN):
    # Vertical difference is always either 0 or +1
    constraints_dp_rows_post.append(z3.Or(
        dp_row1[i+1] - dp_row0[i+1] == 0,
        dp_row1[i+1] - dp_row0[i+1] == 1
    ))
# Make sure that the post condition is satisfied.
if True:
    FindCounterexamples(
        'DP post condition (vertical)',
        constraints_dp_row0 + constraints_dp_rows_init + constraints_dp_row1_calc + \
        [DeMorganNot(constraints_dp_rows_post)]
    )

# Hyyrö, 2017: Observation 2:
# The difference of the accumlated LLCS equals the number of horizontally
# changed columns.
llcs_after_row1_calc = dp_row1[-1] - dp_row1[0]
num_of_changes = functools.reduce(
    lambda x, y: x + y,
    [(dp_row1[i+1] - dp_row1[i+0]) for i in range(STRLEN)]
)
constraints_dp_llcs_post = [llcs_after_row1_calc == num_of_changes]
if True:
    FindCounterexamples(
        'DP post condition (LLCS accumlation)',
        constraints_dp_row0 + constraints_dp_rows_init + constraints_dp_row1_calc + constraints_dp_rows_post + \
        [DeMorganNot(constraints_dp_llcs_post)]
    )

constraints_dp = \
    constraints_dp_row0 + \
    constraints_dp_rows_init + \
    constraints_dp_row1_calc + \
    constraints_dp_row1_post + \
    constraints_dp_rows_post + \
    constraints_dp_llcs_post


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

# Calculation of vertical differences
# V[ 0, 0] == 1 <-> H[-1, 0] == 0 && (V[ 0,-1] == 1 || E[ 0, 0] == 1)
# (except b_V_-1, which stays False)
for i in range(-1, STRLEN):
    if i == -1:
        constraints_b_V_calc.append(z3.Not(b_V[i+1]))
    else:
        # Beware that b_V[i+1] depends on b_V[i+0],
        # making the bit-parallel calculation of V below not simple.
        constraints_b_V_calc.append(
            b_V[i+1] == z3.And(z3.Not(b_P[i]), z3.Or(b_V[i+0], b_E[i])))
# Make sure that this conversion is valid.
if True:
    FindCounterexamples(
        'DP-BOOL calculation (vertical)',
        constraints_dp + \
        constraints_b_V + constraints_b_P + constraints_b_H + \
        [DeMorganNot(constraints_b_V_calc)]
    )

# Calculation of horizontal differences
# H[ 0, 0] == 1 <-> V[ 0,-1] == 0 && (H[-1, 0] == 1 || E[ 0, 0] == 1)
for i in range(STRLEN):
    constraints_b_H_calc.append(
        b_H[i] == z3.And(z3.Not(b_V[i+0]), z3.Or(b_P[i], b_E[i])))
# Make sure that this conversion is valid.
if True:
    FindCounterexamples(
        'DP-BOOL calculation (horizontal)',
        constraints_dp + \
        constraints_b_V + constraints_b_P + constraints_b_H + \
        constraints_b_V_calc + \
        [DeMorganNot(constraints_b_H_calc)]
    )

constraints_dp_bool = \
    constraints_b_V + \
    constraints_b_P + \
    constraints_b_H + \
    constraints_b_V_calc + \
    constraints_b_H_calc


##
##  The bit-parallel LCS length algorithm by Hyyrö (2004).
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

# Calculation of horizontal differences
Pdash = ~P
Hdash = ~H
T = E & Pdash
constraints_bitpar_H_calc = [
    # Compute complement of H (all bits where horizontal difference is zero)
    Hdash == (Pdash + T) | (Pdash - T)
]
if True:
    FindCounterexamples(
        'Bit-parallel calculation (horizontal)',
        constraints_dp + constraints_dp_bool + \
        constraints_bitpar_dp_bool + \
        [DeMorganNot(constraints_bitpar_H_calc)]
    )

####
####    NOT IN THIS FORMAL PROOF:
####
####    Because LLCS is the *longest* common subsequence,
####    the LCS distance can be thought as number of operations
####    preserving the longest common subsequence between two and
####    add / remove all other characters.  That would minimize the
####    number of operations required to turn A into B.
####    That relation makes:
####        LCS-distance(a,b) = a.len() + b.len() - 2 * LCS-length(a,b)
####
####    Also, if the actual length of the string 1 is shorter than STRLEN,
####    the value of the highest valid DP cell is carried
####    to the highest position preserving the value, making:
####        row1[a.len()-1] == row1[STRLEN-1]
####        (excluding the first implicit "0" column).
####

sys.exit(0)
