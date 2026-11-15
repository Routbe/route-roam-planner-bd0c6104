#!/usr/bin/env python3
"""Derives the class-group discriminant D = -p for the Wesolowski VDF (no trusted setup).

p is the first probable prime p = 3 (mod 4), p >= P0, stepping by 4, where P0 is 2048 bits of
SHA-256(DST || i) (i = 0..7) with the top bit and the two low bits set. Anyone can re-run this; the
Rust test `discriminant_is_derived_from_the_public_seed` recomputes it independently.
"""
import hashlib, random

DST = b"ROUT-VDF-WES-CLASSGROUP-2048-v1:D"

def mr(n, rounds=40):
    if n < 2: return False
    for q in (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97):
        if n % q == 0: return n == q
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    rng = random.Random(1)
    for i in range(rounds):
        a = 2 if i == 0 else rng.randrange(3, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True

wide = b"".join(hashlib.sha256(DST + bytes([i])).digest() for i in range(8))
p0 = int.from_bytes(wide, "big") | (1 << 2047) | 3
k = 0
while not mr(p0 + 4 * k): k += 1
p = p0 + 4 * k
assert p % 4 == 3 and p.bit_length() == 2048
print("steps", k)
limbs = [(p >> (64 * i)) & (2**64 - 1) for i in range(32)]
print("pub const P: [u64; 32] = [")
for i in range(0, 32, 4):
    print("    " + ", ".join(f"0x{x:016x}" for x in limbs[i:i+4]) + ",")
print("];")
