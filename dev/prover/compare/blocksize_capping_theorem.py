#! /usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

from z3 import *

set_param(proof=True)
solver = Solver()

# Variables and constraints
a = Int('a')
b = Int('b')
c = Int('c')
solver.add(a > 0)
solver.add(b > 0)
solver.add(c > 0)

# Find counterexamples of the theorem:
# (a <= b * c) <-> ((a + b - 1) / b <= c)
# where a,b,c (integer) > 0
solver.add((a <= b * c) != (((a + b - 1) / b <= c)))

# Expect: unsat (proven that no counterexamples exist)
print(solver.check())
print(solver.proof().sexpr())
