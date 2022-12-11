from rule import Rule
from opcodes import *

"""
Rule:
mask = shlWorkaround(u256(-1), unsigned(A.d())) >> unsigned(B.d())
SHR(B, SHL(A, X)) -> AND(SH[L/R]([B - A / A - B], X), Mask)
Requirements:
A < BitWidth
B < BitWidth
"""

rule = Rule()

n_bits = 64

# Input vars
X = BitVec('X', n_bits)
A = BitVec('A', n_bits)
B = BitVec('B', n_bits)

# Constants
BitWidth = BitVecVal(n_bits, n_bits)

# Requirements
rule.require(ULT(A, BitWidth))
rule.require(ULT(B, BitWidth))

# Non optimized result
nonopt = SHR(B, SHL(A, X))

# Optimized result
Mask = SHR(B, SHL(A, Int2BV(IntVal(-1), n_bits)))
opt = If(
	UGT(A, B),
	AND(SHL(A - B, X), Mask),
		If(
			UGT(B, A),
			AND(SHR(B - A, X), Mask),
			AND(X, Mask)
		)
	)

rule.check(nonopt, opt)
