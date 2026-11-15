//! Stap 10: Wesolowski verifiable delay function (Wesolowski, "Efficient
//! verifiable delay functions", EUROCRYPT 2019) for the time-stamped ledger.
//!
//! Group: (Z/NZ)* / {±1} for the RSA-2048 challenge modulus N (RSA
//! Laboratories, 1991; its factorisation is unknown, so no party holds a
//! trapdoor). An element is stored as its canonical representative
//! min(a, N - a) in [1, (N-1)/2], 256 bytes big-endian; the quotient removes
//! the order-2 element -1 that would otherwise allow a low-order forgery.
//!
//!   x  = HashToGroup(input, T)                 (SHA-256 expansion, < 2^2047)
//!   y  = x^(2^T)                               T sequential squarings: O(T)
//!   l  = HashToPrime(T, x, y)                  256-bit prime, Fiat-Shamir
//!   pi = x^floor(2^T / l)                      long division on the fly: O(T)
//!   verify: r = 2^T mod l, accept iff pi^l * x^r == y
//!
//! Verification costs two exponentiations with 256-bit exponents and a
//! 64-bit exponentiation modulo l, independent of T apart from that log T
//! step (O(1) group operations in T). Evaluation needs 2T modular squarings
//! (plus T selected multiplications) and cannot be parallelised.
//!
//! Arithmetic: fixed-size little-endian u64 limbs and Montgomery
//! multiplication (CIOS); no allocator, no secrets (every value here is
//! public), stack-only buffers.
use sha2::{Digest, Sha256};
use crate::{Error, Result};

/// One group element, big-endian.
pub const ELEM_LEN: usize = 256;
/// Proof bytes: y || pi.
pub const PROOF_LEN: usize = 2 * ELEM_LEN;
/// Largest challenge input (bytes).
pub const MAX_INPUT: usize = 1024;
/// Largest delay parameter T (squarings).
pub const MAX_T: u64 = 1 << 32;

const DST_X: &[u8] = b"ROUT-VDF-WES-RSA2048-v1:x";
const DST_L: &[u8] = b"ROUT-VDF-WES-RSA2048-v1:l";
const L: usize = 32;
pub(crate) const PL: usize = 4;

/// RSA-2048 challenge modulus, little-endian 64-bit limbs.
pub const N: [u64; L] = [
    0x399d48c6361cc7e5, 0x33a5eb6817f7bc16, 0xcc30f95054c824e7, 0x31f55615172866bc,
    0x721f24a3fc0f1b31, 0xe56b16a4d9d373d8, 0x4c61dc5b3c3b7923, 0xbc729592642920f2,
    0x872c909525bdad32, 0x609f10ac6a95ad65, 0xcb1813addc80cd05, 0xf6135809f85334b5,
    0xeb955f3ea37d5159, 0x3f442709439de66c, 0x02c479af89d64d37, 0xf7e8daefd26c66fc,
    0xbe35f592bdef524a, 0x8eb991c2c4d730bb, 0x781be4d1673164ba, 0xb4f14a04b51f7bfd,
    0xd40ea33c80039f35, 0x46eb09c7cf5e8592, 0x44b4b6ffc93384b6, 0xa31f5b0b7765ff8b,
    0xa04107f0648c2813, 0x721aeeacc2acde32, 0xc72f93d1650011bd, 0x7ff0db8e1ea1189e,
    0xa8726f463550bb5b, 0x73911081c790f5f1, 0x4490201a7aa613cd, 0xc7970ceedcc3b075,];

pub(crate) type Limbs<const K: usize> = [u64; K];

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// a - b and the final borrow (1 when a < b).
pub(crate) fn sub<const K: usize>(a: &Limbs<K>, b: &Limbs<K>) -> (Limbs<K>, u64) {
    let mut out = [0u64; K];
    let mut borrow = 0;
    for i in 0..K {
        let (d, br) = sbb(a[i], b[i], borrow);
        out[i] = d;
        borrow = br;
    }
    (out, borrow)
}

/// 2a and the bit shifted out.
pub(crate) fn shl1<const K: usize>(a: &Limbs<K>) -> (Limbs<K>, u64) {
    let mut out = [0u64; K];
    let mut carry = 0;
    for i in 0..K {
        out[i] = (a[i] << 1) | carry;
        carry = a[i] >> 63;
    }
    (out, carry)
}

/// `yes` when choice == 1, else `no` (branch-free).
pub(crate) fn select<const K: usize>(yes: &Limbs<K>, no: &Limbs<K>, choice: u64) -> Limbs<K> {
    let mask = 0u64.wrapping_sub(choice & 1);
    let mut out = [0u64; K];
    for i in 0..K {
        out[i] = (yes[i] & mask) | (no[i] & !mask);
    }
    out
}

pub(crate) fn is_zero<const K: usize>(a: &Limbs<K>) -> bool {
    a.iter().fold(0u64, |acc, x| acc | x) == 0
}

pub(crate) fn eq<const K: usize>(a: &Limbs<K>, b: &Limbs<K>) -> bool {
    a.iter().zip(b.iter()).fold(0u64, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn from_be<const K: usize>(b: &[u8]) -> Limbs<K> {
    let mut out = [0u64; K];
    for i in 0..K {
        let end = b.len() - 8 * i;
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[end - 8..end]);
        out[i] = u64::from_be_bytes(w);
    }
    out
}

pub(crate) fn to_be<const K: usize>(a: &Limbs<K>, out: &mut [u8]) {
    let n = out.len();
    for i in 0..K {
        out[n - 8 * (i + 1)..n - 8 * i].copy_from_slice(&a[i].to_be_bytes());
    }
}

/// Montgomery arithmetic modulo an odd n (R = 2^(64K)).
pub(crate) struct Monty<const K: usize> {
    pub(crate) n: Limbs<K>,
    n0: u64,
    /// R mod n: the Montgomery form of 1.
    pub(crate) one: Limbs<K>,
    r2: Limbs<K>,
}

impl<const K: usize> Monty<K> {
    pub(crate) fn new(n: &Limbs<K>) -> Self {
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let mut m = Monty { n: *n, n0: inv.wrapping_neg(), one: [0; K], r2: [0; K] };
        let mut acc = [0u64; K];
        acc[0] = 1;
        for _ in 0..64 * K {
            acc = m.double(&acc);
        }
        m.one = acc;
        for _ in 0..64 * K {
            acc = m.double(&acc);
        }
        m.r2 = acc;
        m
    }

    /// 2a mod n for a < n.
    fn double(&self, a: &Limbs<K>) -> Limbs<K> {
        let (s, carry) = shl1(a);
        let (d, borrow) = sub(&s, &self.n);
        select(&d, &s, carry | (borrow ^ 1))
    }

    /// a * b * R^-1 mod n for a, b < n (CIOS).
    pub(crate) fn mul(&self, a: &Limbs<K>, b: &Limbs<K>) -> Limbs<K> {
        let mut t = [0u64; K];
        let mut t_hi: u64 = 0;
        for i in 0..K {
            let mut c = 0u64;
            for j in 0..K {
                let (lo, hi) = mac(t[j], a[j], b[i], c);
                t[j] = lo;
                c = hi;
            }
            let (s, c1) = adc(t_hi, c, 0);
            let m = t[0].wrapping_mul(self.n0);
            let (_, mut c2) = mac(t[0], m, self.n[0], 0);
            for j in 1..K {
                let (lo, hi) = mac(t[j], m, self.n[j], c2);
                t[j - 1] = lo;
                c2 = hi;
            }
            let (s2, c3) = adc(s, c2, 0);
            t[K - 1] = s2;
            t_hi = c1 + c3;
        }
        let (d, borrow) = sub(&t, &self.n);
        select(&d, &t, (t_hi & 1) | (borrow ^ 1))
    }

    pub(crate) fn to_mont(&self, a: &Limbs<K>) -> Limbs<K> {
        self.mul(a, &self.r2)
    }

    pub(crate) fn from_mont(&self, a: &Limbs<K>) -> Limbs<K> {
        let mut one = [0u64; K];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// base^e (Montgomery form in and out), e as little-endian limbs, every bit processed.
    pub(crate) fn pow<const E: usize>(&self, base: &Limbs<K>, e: &Limbs<E>) -> Limbs<K> {
        let mut acc = self.one;
        for i in (0..64 * E).rev() {
            acc = self.mul(&acc, &acc);
            let t = self.mul(&acc, base);
            acc = select(&t, &acc, (e[i / 64] >> (i % 64)) & 1);
        }
        acc
    }
}

/// min(a, N - a) for 0 < a < N.
fn canon(m: &Monty<L>, a: &Limbs<L>) -> Limbs<L> {
    let (neg, _) = sub(&m.n, a);
    let (_, borrow) = sub(&neg, a); // borrow = 1 when N - a < a
    select(&neg, a, borrow)
}

/// A canonical element: 1 <= a <= (N-1)/2.
fn decode_elem(m: &Monty<L>, b: &[u8]) -> Result<Limbs<L>> {
    let a: Limbs<L> = from_be(b);
    let (_, below_n) = sub(&a, &m.n);
    if below_n != 1 || is_zero(&a) || !eq(&canon(m, &a), &a) {
        return Err(Error::Invalid);
    }
    Ok(a)
}

/// x = HashToGroup(input, T): 2048 expanded bits with the top bit cleared (x < 2^2047 < N), canonical.
fn hash_to_group(m: &Monty<L>, input: &[u8], t: u64) -> Result<Limbs<L>> {
    let mut wide = [0u8; ELEM_LEN];
    for (blk, chunk) in wide.chunks_exact_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(DST_X);
        h.update([blk as u8]);
        h.update(t.to_be_bytes());
        h.update((input.len() as u32).to_be_bytes());
        h.update(input);
        chunk.copy_from_slice(&h.finalize());
    }
    wide[0] &= 0x7f;
    let x: Limbs<L> = from_be(&wide);
    let mut one = [0u64; L];
    one[0] = 1;
    if is_zero(&x) || eq(&x, &one) {
        return Err(Error::Invalid);
    }
    Ok(canon(m, &x))
}

pub(crate) const SMALL_PRIMES: [u64; 24] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

pub(crate) fn rem_small(a: &Limbs<PL>, p: u64) -> u64 {
    let mut r: u128 = 0;
    for i in (0..PL).rev() {
        r = ((r << 64) | a[i] as u128) % p as u128;
    }
    r as u64
}

/// Miller-Rabin with the bases 2 and SMALL_PRIMES (25 rounds) after trial division.
pub(crate) fn probable_prime(c: &Limbs<PL>) -> bool {
    if c[0] & 1 == 0 {
        return false;
    }
    if SMALL_PRIMES.iter().any(|&p| rem_small(c, p) == 0) {
        return false;
    }
    let m = Monty::<PL>::new(c);
    let mut one = [0u64; PL];
    one[0] = 1;
    let (d0, _) = sub(c, &one);
    let mut s = 0;
    let mut d = d0;
    while d[0] & 1 == 0 {
        for i in 0..PL {
            d[i] = (d[i] >> 1) | if i + 1 < PL { d[i + 1] << 63 } else { 0 };
        }
        s += 1;
    }
    let (minus_one, _) = sub(&m.n, &m.one);
    for &b in [2u64].iter().chain(SMALL_PRIMES.iter()) {
        let mut base = [0u64; PL];
        base[0] = b;
        let mut x = m.pow(&m.to_mont(&base), &d);
        if eq(&x, &m.one) || eq(&x, &minus_one) {
            continue;
        }
        let mut witness = true;
        for _ in 1..s {
            x = m.mul(&x, &x);
            if eq(&x, &minus_one) {
                witness = false;
                break;
            }
        }
        if witness {
            return false;
        }
    }
    true
}

/// l = HashToPrime(T, x, y): the first SHA-256 candidate (top and low bit set) that is a probable prime.
fn hash_to_prime(t: u64, x: &[u8], y: &[u8]) -> Result<Limbs<PL>> {
    hash_to_prime_dst(DST_L, t, x, y)
}

/// HashToPrime under a caller-chosen domain separation tag.
pub(crate) fn hash_to_prime_dst(dst: &[u8], t: u64, x: &[u8], y: &[u8]) -> Result<Limbs<PL>> {
    for ctr in 0u32..65_536 {
        let mut h = Sha256::new();
        h.update(dst);
        h.update(ctr.to_be_bytes());
        h.update(t.to_be_bytes());
        h.update(x);
        h.update(y);
        let mut c: Limbs<PL> = from_be(&h.finalize());
        c[PL - 1] |= 1 << 63;
        c[0] |= 1;
        if probable_prime(&c) {
            return Ok(c);
        }
    }
    Err(Error::Invalid)
}

fn check_params(input: &[u8], t: u64) -> Result<()> {
    if input.len() > MAX_INPUT || t == 0 || t > MAX_T {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// y || pi for (input, T). O(T) sequential squarings.
pub fn evaluate(input: &[u8], t: u64, out: &mut [u8]) -> Result<()> {
    check_params(input, t)?;
    if out.len() != PROOF_LEN {
        return Err(Error::Invalid);
    }
    let m = Monty::<L>::new(&N);
    let x = hash_to_group(&m, input, t)?;
    let xm = m.to_mont(&x);
    let mut y_m = xm;
    for _ in 0..t {
        y_m = m.mul(&y_m, &y_m);
    }
    let y = canon(&m, &m.from_mont(&y_m));
    let mut xb = [0u8; ELEM_LEN];
    let (yb, pb) = out.split_at_mut(ELEM_LEN);
    to_be(&x, &mut xb);
    to_be(&y, yb);
    let l = hash_to_prime(t, &xb, yb)?;
    // Long division of 2^T by l, most significant quotient bit first: pi = x^floor(2^T / l).
    let mut r = [0u64; PL];
    r[0] = 1;
    let mut pi = m.one;
    for _ in 0..t {
        let (r2, carry) = shl1(&r);
        let (d, borrow) = sub(&r2, &l);
        let bit = carry | (borrow ^ 1);
        r = select(&d, &r2, bit);
        pi = m.mul(&pi, &pi);
        let px = m.mul(&pi, &xm);
        pi = select(&px, &pi, bit);
    }
    to_be(&canon(&m, &m.from_mont(&pi)), pb);
    crate::wipe::words(&mut pi);
    crate::wipe::words(&mut y_m);
    crate::wipe::words(&mut r);
    Ok(())
}

/// Accepts iff proof = y || pi is the canonical Wesolowski proof for (input, T).
pub fn verify(input: &[u8], t: u64, proof: &[u8]) -> Result<()> {
    check_params(input, t)?;
    if proof.len() != PROOF_LEN {
        return Err(Error::Invalid);
    }
    let m = Monty::<L>::new(&N);
    let y = decode_elem(&m, &proof[..ELEM_LEN])?;
    let pi = decode_elem(&m, &proof[ELEM_LEN..])?;
    let x = hash_to_group(&m, input, t)?;
    let mut xb = [0u8; ELEM_LEN];
    to_be(&x, &mut xb);
    let l = hash_to_prime(t, &xb, &proof[..ELEM_LEN])?;
    // r = 2^T mod l, in the Montgomery domain of l.
    let ml = Monty::<PL>::new(&l);
    let mut two = [0u64; PL];
    two[0] = 2;
    let r = ml.from_mont(&ml.pow(&ml.to_mont(&two), &[t]));
    let lhs = m.mul(&m.pow(&m.to_mont(&pi), &l), &m.pow(&m.to_mont(&x), &r));
    if eq(&canon(&m, &m.from_mont(&lhs)), &y) {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn montgomery_round_trip_and_one() {
        let m = Monty::<L>::new(&N);
        let mut a = [0u64; L];
        a[0] = 12345;
        a[7] = 0xdead_beef;
        assert_eq!(m.from_mont(&m.to_mont(&a)), a);
        assert_eq!(m.from_mont(&m.one)[0], 1);
    }

    #[test]
    fn small_prime_test() {
        // 2^255 + 95 is prime; 2^255 + 93 is not (divisible by 3? checked by trial or MR).
        let mut p = [0u64; PL];
        p[PL - 1] = 1 << 63;
        p[0] = 95;
        assert!(probable_prime(&p));
        p[0] = 97; // 2^255 + 97 = 3 * ... is composite
        assert_eq!(rem_small(&p, 3), 0);
        assert!(!probable_prime(&p));
    }
}
