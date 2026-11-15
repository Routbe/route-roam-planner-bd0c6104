//! Stap 10: Wesolowski VDF in the class group of an imaginary quadratic order (no trusted setup).
//!
//! Group: Cl(D) for the fundamental discriminant D = -p, p a 2048-bit prime = 3 (mod 4) derived
//! from a public seed (tools/vdf_discriminant.py; re-derived by a test). Nobody knows the class
//! number, and unlike an RSA modulus there is no factorisation anyone could have kept: no trusted
//! setup. h(D) is odd (genus theory, D prime), so there is no element of order two.
//!
//!   x  = HashToGroup(input, T)    a prime form (a, b, c), a a 256-bit prime with (D/a) = 1
//!   y  = x^(2^T)                  T sequential squarings
//!   l  = HashToPrime(T, x, y)     256-bit prime (Fiat-Shamir), shared with vdf.rs
//!   pi = x^floor(2^T / l)         long division on the fly
//!   verify: pi^l * x^(2^T mod l) == y
//!
//! Elements travel as reduced forms: a (128 bytes) || sign(b) (1 byte) || |b| (128 bytes);
//! decoding refuses anything that is not the unique reduced representative.
//!
//! Arithmetic: fixed-width signed integers ([u64; W] magnitudes on the stack), composition after
//! Shanks/Atkin (the inkfish reference algorithm), Gauss reduction. No allocator and no memory
//! growth; every integer is overwritten with volatile writes when it is dropped, so no squaring
//! intermediate outlives its use. All values are public: these routines are variable-time.
use core::cmp::Ordering;
use sha2::{Digest, Sha256};

use crate::vdf::{self, Limbs, Monty, PL};
use crate::{wipe, Error, Result};

/// Limbs per integer: 4352 bits, enough for the 4097-bit products inside a composition.
const W: usize = 68;
/// One reduced form on the wire.
pub const ELEM_LEN: usize = 257;
pub const PROOF_LEN: usize = 2 * ELEM_LEN;
pub const MAX_INPUT: usize = 1024;
pub const MAX_T: u64 = 1 << 32;
const HALF: usize = 128;

const DST_G: &[u8] = b"ROUT-VDF-WES-CLASSGROUP-2048-v1:x";
const DST_L: &[u8] = b"ROUT-VDF-WES-CLASSGROUP-2048-v1:l";
/// Seed for the discriminant (see tools/vdf_discriminant.py).
pub const DST_D: &[u8] = b"ROUT-VDF-WES-CLASSGROUP-2048-v1:D";

/// p with D = -p, little-endian limbs (tools/vdf_discriminant.py, 1791 steps from the seed).
pub const P: [u64; 32] = [
    0xca30b24291c1552f, 0x4a7f514da5705bcd, 0xd7377fa8c236a94d, 0xad494c28e0f20747,
    0xabe62696d478fe89, 0x0df8fab87f08a189, 0xa67b1e0c8a88b8aa, 0x504ddc08bf1d699a,
    0xa202f5fe12c7d663, 0xa16b30c75130e3ea, 0x719fa7596e278443, 0x42e5d32f70804403,
    0x085c605937ad5739, 0x2b67ec4312d2d2ad, 0x395bd9dcde1d22e2, 0x89ae9266ae982fc5,
    0x5c17d188c1f37184, 0x772d55b853bdd5f0, 0x996bbac9f4bed205, 0x7431bd9a0ca30931,
    0xedaf314c35c60e34, 0x180e553447c7dfae, 0x54e2acb2bfb6ab24, 0x8e7eed15c878e403,
    0x8f3a3684bac8acee, 0x1b56ec25b8b767ff, 0x34939c7a49a953d8, 0xc0532c248b896258,
    0xb1bad62715d4a24c, 0x7ac20c7e8dd28fb4, 0x988f018178c86979, 0xbc2f22a6b691f71a,
];

// ------------------------------------------------------------------ fixed-width integers

type Mag = [u64; W];

fn mlen(a: &Mag) -> usize {
    let mut n = W;
    while n > 0 && a[n - 1] == 0 {
        n -= 1;
    }
    n
}

fn mcmp(a: &Mag, b: &Mag) -> Ordering {
    for i in (0..W).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

fn madd(a: &Mag, b: &Mag) -> Result<Mag> {
    let mut out = [0u64; W];
    let mut c = 0u128;
    for i in 0..W {
        let s = a[i] as u128 + b[i] as u128 + c;
        out[i] = s as u64;
        c = s >> 64;
    }
    if c != 0 {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// a - b for a >= b.
fn msub(a: &Mag, b: &Mag) -> Mag {
    let mut out = [0u64; W];
    let mut br = 0u64;
    for i in 0..W {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(br);
        out[i] = d2;
        br = (b1 | b2) as u64;
    }
    out
}

fn mmul(a: &Mag, b: &Mag) -> Result<Mag> {
    let (la, lb) = (mlen(a), mlen(b));
    if la == 0 || lb == 0 {
        return Ok([0u64; W]);
    }
    if la + lb > W + 1 {
        return Err(Error::TooLarge);
    }
    let mut out = [0u64; W + 1];
    for i in 0..la {
        let mut c = 0u128;
        for j in 0..lb {
            let t = out[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + c;
            out[i + j] = t as u64;
            c = t >> 64;
        }
        if i + lb <= W {
            out[i + lb] = c as u64;
        } else if c != 0 {
            return Err(Error::TooLarge);
        }
    }
    if out[W] != 0 {
        return Err(Error::TooLarge);
    }
    let mut r = [0u64; W];
    r.copy_from_slice(&out[..W]);
    wipe::words(&mut out);
    Ok(r)
}

/// (u / v, u % v), Knuth algorithm D.
fn mdivrem(u: &Mag, v: &Mag) -> Result<(Mag, Mag)> {
    let n = mlen(v);
    if n == 0 {
        return Err(Error::Invalid);
    }
    let mut q = [0u64; W];
    if mcmp(u, v) == Ordering::Less {
        return Ok((q, *u));
    }
    let m = mlen(u);
    if n == 1 {
        let d = v[0] as u128;
        let mut r = 0u128;
        for i in (0..m).rev() {
            let cur = (r << 64) | u[i] as u128;
            q[i] = (cur / d) as u64;
            r = cur % d;
        }
        let mut rem = [0u64; W];
        rem[0] = r as u64;
        return Ok((q, rem));
    }
    let s = v[n - 1].leading_zeros();
    let mut vn = [0u64; W];
    let mut un = [0u64; W + 1];
    for i in (0..n).rev() {
        vn[i] = (v[i] << s) | if s > 0 && i > 0 { v[i - 1] >> (64 - s) } else { 0 };
    }
    un[m] = if s > 0 { u[m - 1] >> (64 - s) } else { 0 };
    for i in (0..m).rev() {
        un[i] = (u[i] << s) | if s > 0 && i > 0 { u[i - 1] >> (64 - s) } else { 0 };
    }
    let b: u128 = 1 << 64;
    for j in (0..=m - n).rev() {
        let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
        let mut qhat = num / vn[n - 1] as u128;
        let mut rhat = num % vn[n - 1] as u128;
        while qhat >= b || qhat * (vn[n - 2] as u128) > ((rhat << 64) | un[j + n - 2] as u128) {
            qhat -= 1;
            rhat += vn[n - 1] as u128;
            if rhat >= b {
                break;
            }
        }
        let mut borrow: i128 = 0;
        let mut carry: u128 = 0;
        for i in 0..n {
            let p = qhat * vn[i] as u128 + carry;
            carry = p >> 64;
            let t = un[i + j] as i128 - (p as u64) as i128 + borrow;
            un[i + j] = t as u64;
            borrow = t >> 64;
        }
        let t = un[j + n] as i128 - carry as i128 + borrow;
        un[j + n] = t as u64;
        q[j] = qhat as u64;
        if t < 0 {
            q[j] = q[j].wrapping_sub(1);
            let mut c = 0u128;
            for i in 0..n {
                let s2 = un[i + j] as u128 + vn[i] as u128 + c;
                un[i + j] = s2 as u64;
                c = s2 >> 64;
            }
            un[j + n] = un[j + n].wrapping_add(c as u64);
        }
    }
    let mut r = [0u64; W];
    for i in 0..n {
        r[i] = (un[i] >> s) | if s > 0 { un[i + 1] << (64 - s) } else { 0 };
    }
    wipe::words(&mut un);
    wipe::words(&mut vn);
    Ok((q, r))
}

/// A signed integer; its magnitude is overwritten (volatile) when dropped.
pub struct Int {
    neg: bool,
    m: Mag,
}

impl Drop for Int {
    fn drop(&mut self) {
        wipe::words(&mut self.m);
        self.neg = false;
    }
}

impl Clone for Int {
    fn clone(&self) -> Self {
        Int { neg: self.neg, m: self.m }
    }
}

impl core::fmt::Debug for Int {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}0x", if self.neg { "-" } else { "" })?;
        let n = mlen(&self.m).max(1);
        for i in (0..n).rev() {
            write!(f, "{:016x}", self.m[i])?;
        }
        Ok(())
    }
}

impl PartialEq for Int {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}

impl Int {
    fn mk(neg: bool, m: Mag) -> Int {
        let z = mlen(&m) == 0;
        Int { neg: neg && !z, m }
    }
    pub fn zero() -> Int {
        Int { neg: false, m: [0; W] }
    }
    pub fn from_i64(v: i64) -> Int {
        let mut m = [0u64; W];
        m[0] = v.unsigned_abs();
        Int::mk(v < 0, m)
    }
    pub fn from_limbs<const K: usize>(l: &[u64; K], neg: bool) -> Int {
        let mut m = [0u64; W];
        m[..K].copy_from_slice(l);
        Int::mk(neg, m)
    }
    fn is_zero(&self) -> bool {
        mlen(&self.m) == 0
    }
    fn is_neg(&self) -> bool {
        self.neg
    }
    fn is_odd(&self) -> bool {
        self.m[0] & 1 == 1
    }
    fn bits(&self) -> usize {
        let n = mlen(&self.m);
        if n == 0 { 0 } else { 64 * n - self.m[n - 1].leading_zeros() as usize }
    }
    fn neg(&self) -> Int {
        Int::mk(!self.neg, self.m)
    }
    fn abs(&self) -> Int {
        Int::mk(false, self.m)
    }
    pub fn cmp(&self, o: &Int) -> Ordering {
        match (self.neg, o.neg) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => mcmp(&self.m, &o.m),
            (true, true) => mcmp(&o.m, &self.m),
        }
    }
    fn add(&self, o: &Int) -> Result<Int> {
        if self.neg == o.neg {
            return Ok(Int::mk(self.neg, madd(&self.m, &o.m)?));
        }
        match mcmp(&self.m, &o.m) {
            Ordering::Less => Ok(Int::mk(o.neg, msub(&o.m, &self.m))),
            _ => Ok(Int::mk(self.neg, msub(&self.m, &o.m))),
        }
    }
    fn sub(&self, o: &Int) -> Result<Int> {
        self.add(&o.neg())
    }
    fn mul(&self, o: &Int) -> Result<Int> {
        Ok(Int::mk(self.neg != o.neg, mmul(&self.m, &o.m)?))
    }
    /// Floor division by d > 0: (q, r) with 0 <= r < d.
    fn divmod(&self, d: &Int) -> Result<(Int, Int)> {
        if d.neg || d.is_zero() {
            return Err(Error::Invalid);
        }
        let (q, r) = mdivrem(&self.m, &d.m)?;
        let (q, r) = (Int::mk(false, q), Int::mk(false, r));
        if !self.neg {
            return Ok((q, r));
        }
        if r.is_zero() {
            return Ok((q.neg(), r));
        }
        Ok((q.add(&Int::from_i64(1))?.neg(), d.sub(&r)?))
    }
    /// Floor division by any non-zero d.
    fn fdiv(&self, d: &Int) -> Result<Int> {
        if d.neg {
            return self.neg().fdiv(&d.neg());
        }
        Ok(self.divmod(d)?.0)
    }
    fn modp(&self, d: &Int) -> Result<Int> {
        Ok(self.divmod(d)?.1)
    }
    /// self / d, refusing a remainder.
    fn exact(&self, d: &Int) -> Result<Int> {
        let ad = d.abs();
        let (q, r) = mdivrem(&self.m, &ad.m)?;
        if mlen(&r) != 0 {
            return Err(Error::Invalid);
        }
        Ok(Int::mk(self.neg != d.neg, q))
    }
    fn half(&self) -> Result<Int> {
        self.exact(&Int::from_i64(2))
    }
    fn to_limbs<const K: usize>(&self) -> Result<[u64; K]> {
        if self.neg || mlen(&self.m) > K {
            return Err(Error::Invalid);
        }
        let mut o = [0u64; K];
        o.copy_from_slice(&self.m[..K]);
        Ok(o)
    }
    fn to_be(&self, out: &mut [u8]) -> Result<()> {
        let n = out.len();
        if self.bits() > 8 * n {
            return Err(Error::Invalid);
        }
        for (i, b) in out.iter_mut().enumerate() {
            let pos = n - 1 - i; // byte index from the least significant end
            *b = (self.m[pos / 8] >> (8 * (pos % 8))) as u8;
        }
        Ok(())
    }
    fn from_be(b: &[u8]) -> Result<Int> {
        if b.len() > 8 * W {
            return Err(Error::Invalid);
        }
        let mut m = [0u64; W];
        for (i, &x) in b.iter().rev().enumerate() {
            m[i / 8] |= (x as u64) << (8 * (i % 8));
        }
        Ok(Int::mk(false, m))
    }
}

/// (g, x) with x*a = g (mod b), g = gcd(a, b), for a, b >= 0.
fn xgcd(a: &Int, b: &Int) -> Result<(Int, Int)> {
    let (mut r0, mut r1) = (a.clone(), b.clone());
    let (mut s0, mut s1) = (Int::from_i64(1), Int::zero());
    while !r1.is_zero() {
        let (q, r) = r0.divmod(&r1)?;
        let s = s0.sub(&q.mul(&s1)?)?;
        r0 = core::mem::replace(&mut r1, r);
        s0 = core::mem::replace(&mut s1, s);
    }
    Ok((r0, s0))
}

fn gcd(a: &Int, b: &Int) -> Result<Int> {
    let (mut x, mut y) = (a.abs(), b.abs());
    while !y.is_zero() {
        let r = x.modp(&y)?;
        x = core::mem::replace(&mut y, r);
    }
    Ok(x)
}

/// Solves a*x = b (mod m): (x0, m / g), or Invalid when g does not divide b.
fn solve_mod(a: &Int, b: &Int, m: &Int) -> Result<(Int, Int)> {
    let (g, d) = xgcd(&a.modp(m)?, m)?;
    let (q, r) = b.divmod(&g)?;
    if !r.is_zero() {
        return Err(Error::Invalid);
    }
    Ok((q.mul(&d)?.modp(m)?, m.exact(&g)?))
}

// ------------------------------------------------------------------ binary quadratic forms

/// The form a x^2 + b xy + c y^2 of discriminant b^2 - 4ac.
#[derive(Clone, Debug, PartialEq)]
pub struct Form {
    pub a: Int,
    pub b: Int,
    pub c: Int,
}

impl Form {
    pub fn discriminant(&self) -> Result<Int> {
        self.b.mul(&self.b)?.sub(&Int::from_i64(4).mul(&self.a)?.mul(&self.c)?)
    }

    /// The identity (1, 1, (1 - D) / 4) for D = 1 (mod 4).
    pub fn identity(d: &Int) -> Result<Form> {
        Ok(Form { a: Int::from_i64(1), b: Int::from_i64(1), c: Int::from_i64(1).sub(d)?.exact(&Int::from_i64(4))? })
    }

    /// The form with leading coefficient a and middle b, c from the discriminant (exact).
    pub fn from_ab(a: Int, b: Int, d: &Int) -> Result<Form> {
        if a.is_neg() || a.is_zero() {
            return Err(Error::Invalid);
        }
        let c = b.mul(&b)?.sub(d)?.exact(&Int::from_i64(4).mul(&a)?)?;
        Ok(Form { a, b, c })
    }

    fn normalize(&mut self) -> Result<()> {
        let two_a = self.a.add(&self.a)?;
        let r = self.a.sub(&self.b)?.fdiv(&two_a)?;
        if r.is_zero() {
            return Ok(());
        }
        // b' = b + 2ra, c' = a r^2 + b r + c
        let c = self.a.mul(&r)?.mul(&r)?.add(&self.b.mul(&r)?)?.add(&self.c)?;
        self.b = self.b.add(&two_a.mul(&r)?)?;
        self.c = c;
        Ok(())
    }

    pub fn is_reduced(&self) -> bool {
        let ab = self.b.abs();
        if self.a.is_neg() || self.a.is_zero() {
            return false;
        }
        match (ab.cmp(&self.a), self.a.cmp(&self.c)) {
            (Ordering::Greater, _) | (_, Ordering::Greater) => false,
            (Ordering::Equal, _) | (_, Ordering::Equal) => !self.b.is_neg(),
            _ => true,
        }
    }

    pub fn reduce(&mut self) -> Result<()> {
        self.normalize()?;
        let mut guard = 0u32;
        while self.a.cmp(&self.c) == Ordering::Greater || (self.a == self.c && self.b.is_neg()) {
            guard += 1;
            if guard > 1 << 16 {
                return Err(Error::Invalid);
            }
            // (a, b, c) -> (c, -b + 2sc, c s^2 - b s + a), s = floor((c + b) / 2c)
            let two_c = self.c.add(&self.c)?;
            let s = self.c.add(&self.b)?.fdiv(&two_c)?;
            let nc = self.c.mul(&s)?.mul(&s)?.sub(&self.b.mul(&s)?)?.add(&self.a)?;
            let nb = two_c.mul(&s)?.sub(&self.b)?;
            self.a = core::mem::replace(&mut self.c, nc);
            self.b = nb;
        }
        Ok(())
    }

    /// Composition (Shanks; the inkfish reference algorithm), reduced.
    pub fn compose(&self, o: &Form) -> Result<Form> {
        let (a1, b1, c1) = (&self.a, &self.b, &self.c);
        let (a2, b2, c2) = (&o.a, &o.b, &o.c);
        let g = b2.add(b1)?.half()?;
        let h = b2.sub(b1)?.half()?;
        let w = gcd(&gcd(a1, a2)?, &g)?;
        let s = a1.exact(&w)?;
        let t = a2.exact(&w)?;
        let u = g.exact(&w)?;
        let st = s.mul(&t)?;
        let tu = t.mul(&u)?;
        let hu = h.mul(&u)?;
        let (k0, cf) = solve_mod(&tu, &hu.add(&s.mul(c1)?)?, &st)?;
        let (n, _) = solve_mod(&t.mul(&cf)?, &h.sub(&t.mul(&k0)?)?, &s)?;
        let k = k0.add(&cf.mul(&n)?)?;
        let l = t.mul(&k)?.sub(&h)?.exact(&s)?;
        let m = tu.mul(&k)?.sub(&hu)?.sub(&c1.mul(&s)?)?.exact(&st)?;
        let _ = c2;
        let mut f = Form {
            a: st,
            b: w.mul(&u)?.sub(&k.mul(&t)?.add(&l.mul(&s)?)?)?,
            c: k.mul(&l)?.sub(&w.mul(&m)?)?,
        };
        f.reduce()?;
        Ok(f)
    }

    pub fn square(&self) -> Result<Form> {
        self.compose(self)
    }

    /// self^e for e as little-endian limbs (public exponent, square-and-multiply).
    pub fn pow<const E: usize>(&self, e: &[u64; E], d: &Int) -> Result<Form> {
        let mut acc = Form::identity(d)?;
        let mut started = false;
        for i in (0..64 * E).rev() {
            if started {
                acc = acc.square()?;
            }
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                acc = if started { acc.compose(self)? } else { self.clone() };
                started = true;
            }
        }
        Ok(acc)
    }

    fn encode(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != ELEM_LEN {
            return Err(Error::Invalid);
        }
        self.a.to_be(&mut out[..HALF])?;
        out[HALF] = self.b.is_neg() as u8;
        self.b.abs().to_be(&mut out[HALF + 1..])
    }

    fn decode(bytes: &[u8], d: &Int) -> Result<Form> {
        if bytes.len() != ELEM_LEN || bytes[HALF] > 1 {
            return Err(Error::Invalid);
        }
        let a = Int::from_be(&bytes[..HALF])?;
        let bm = Int::from_be(&bytes[HALF + 1..])?;
        if bytes[HALF] == 1 && bm.is_zero() {
            return Err(Error::Invalid);
        }
        let b = if bytes[HALF] == 1 { bm.neg() } else { bm };
        if !b.is_odd() {
            return Err(Error::Invalid); // b = D (mod 2)
        }
        let f = Form::from_ab(a, b, d)?;
        if !f.is_reduced() {
            return Err(Error::Invalid);
        }
        Ok(f)
    }
}

// ------------------------------------------------------------------ the VDF

pub fn discriminant() -> Int {
    Int::from_limbs(&P, true)
}

/// x = HashToGroup(input, T): the prime form for the first SHA-256 candidate a (256 bits,
/// a = 3 mod 4, probable prime, D a square mod a), b the odd square root of D mod a.
fn hash_to_group(input: &[u8], t: u64, d: &Int) -> Result<Form> {
    for ctr in 0u32..65_536 {
        let mut h = Sha256::new();
        h.update(DST_G);
        h.update(ctr.to_be_bytes());
        h.update(t.to_be_bytes());
        h.update((input.len() as u32).to_be_bytes());
        h.update(input);
        let mut a: Limbs<PL> = vdf::from_be(&h.finalize());
        a[PL - 1] |= 1 << 63;
        a[0] |= 3;
        if !vdf::probable_prime(&a) {
            continue;
        }
        let ai = Int::from_limbs(&a, false);
        let dm: Limbs<PL> = d.modp(&ai)?.to_limbs()?;
        let mont = Monty::<PL>::new(&a);
        // e = (a + 1) / 4 = (a >> 2) + 1 for a = 3 (mod 4)
        let mut e = [0u64; PL];
        for i in 0..PL {
            e[i] = (a[i] >> 2) | if i + 1 < PL { a[i + 1] << 62 } else { 0 };
        }
        let mut one = [0u64; PL];
        one[0] = 1;
        let (e, _) = {
            let mut s = [0u64; PL];
            let mut c = 1u128;
            for i in 0..PL {
                let v = e[i] as u128 + c;
                s[i] = v as u64;
                c = v >> 64;
            }
            (s, c)
        };
        let dmm = mont.to_mont(&dm);
        let root_m = mont.pow(&dmm, &e);
        if !vdf::eq(&mont.mul(&root_m, &root_m), &dmm) {
            continue; // D is not a square mod a
        }
        let root = Int::from_limbs(&mont.from_mont(&root_m), false);
        let b = if root.is_odd() { root } else { ai.sub(&root)? };
        let mut f = Form::from_ab(ai, b, d)?;
        f.reduce()?;
        return Ok(f);
    }
    Err(Error::Invalid)
}

fn check_params(input: &[u8], t: u64) -> Result<()> {
    if input.len() > MAX_INPUT || t == 0 || t > MAX_T {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Evaluation under an explicit discriminant (tests use small ones).
pub fn evaluate_with(d: &Int, input: &[u8], t: u64, out: &mut [u8]) -> Result<()> {
    check_params(input, t)?;
    if out.len() != PROOF_LEN {
        return Err(Error::Invalid);
    }
    let x = hash_to_group(input, t, d)?;
    let mut y = x.clone();
    for _ in 0..t {
        y = y.square()?;
    }
    let mut xb = [0u8; ELEM_LEN];
    x.encode(&mut xb)?;
    let (yb, pb) = out.split_at_mut(ELEM_LEN);
    y.encode(yb)?;
    let l = vdf::hash_to_prime_dst(DST_L, t, &xb, yb)?;
    let li = Int::from_limbs(&l, false);
    let mut r = Int::from_i64(1);
    let mut pi = Form::identity(d)?;
    for _ in 0..t {
        let r2 = r.add(&r)?;
        pi = pi.square()?;
        if r2.cmp(&li) != Ordering::Less {
            r = r2.sub(&li)?;
            pi = pi.compose(&x)?;
        } else {
            r = r2;
        }
    }
    pi.encode(pb)
}

pub fn verify_with(d: &Int, input: &[u8], t: u64, proof: &[u8]) -> Result<()> {
    check_params(input, t)?;
    if proof.len() != PROOF_LEN {
        return Err(Error::Invalid);
    }
    let y = Form::decode(&proof[..ELEM_LEN], d)?;
    let pi = Form::decode(&proof[ELEM_LEN..], d)?;
    let x = hash_to_group(input, t, d)?;
    let mut xb = [0u8; ELEM_LEN];
    x.encode(&mut xb)?;
    let l = vdf::hash_to_prime_dst(DST_L, t, &xb, &proof[..ELEM_LEN])?;
    let ml = Monty::<PL>::new(&l);
    let mut two = [0u64; PL];
    two[0] = 2;
    let r = ml.from_mont(&ml.pow(&ml.to_mont(&two), &[t]));
    let lhs = pi.pow(&l, d)?.compose(&x.pow(&r, d)?)?;
    if lhs == y {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

/// y || pi for (input, T) in Cl(-p). O(T) sequential squarings.
pub fn evaluate(input: &[u8], t: u64, out: &mut [u8]) -> Result<()> {
    evaluate_with(&discriminant(), input, t, out)
}

/// Accepts iff proof = y || pi is the canonical Wesolowski proof for (input, T).
pub fn verify(input: &[u8], t: u64, proof: &[u8]) -> Result<()> {
    verify_with(&discriminant(), input, t, proof)
}

#[cfg(test)]
mod unit {
    use super::*;

    fn d(v: i64) -> Int {
        Int::from_i64(v)
    }

    /// Every reduced form of discriminant D (brute force; independent of compose).
    fn reduced_forms(dv: i64) -> Vec<(i64, i64)> {
        let mut out = vec![];
        let mut a = 1i64;
        while 3 * a * a <= -dv {
            for b in -a + 1..=a {
                if (b * b - dv) % (4 * a) == 0 {
                    let c = (b * b - dv) / (4 * a);
                    if c >= a && !(b < 0 && (a == c)) {
                        out.push((a, b));
                    }
                }
            }
            a += 1;
        }
        out
    }

    #[test]
    fn bignum_division_matches_u128() {
        let mut x: u128 = 0x1234_5678_9abc_def0_0fed_cba9_8765_4321;
        for _ in 0..2000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let y = (x >> 37) | 1;
            let a = Int::from_limbs(&[x as u64, (x >> 64) as u64], false);
            let b = Int::from_limbs(&[y as u64, (y >> 64) as u64], false);
            let (q, r) = a.divmod(&b).unwrap();
            assert_eq!(q, Int::from_limbs(&[(x / y) as u64, ((x / y) >> 64) as u64], false));
            assert_eq!(r, Int::from_limbs(&[(x % y) as u64, ((x % y) >> 64) as u64], false));
            let (qn, rn) = a.neg().divmod(&b).unwrap();
            assert_eq!(qn.mul(&b).unwrap().add(&rn).unwrap(), a.neg());
            assert!(!rn.is_neg() && rn.cmp(&b) == Ordering::Less);
        }
    }

    #[test]
    fn wide_division_round_trips() {
        // (a * b + r) / b == a for multi-limb a, b.
        let mut a = Int::zero();
        let mut b = Int::zero();
        for i in 0..30 {
            a.m[i] = 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1);
            b.m[i] = 0xc2b2_ae3d_27d4_eb4fu64.wrapping_mul(i as u64 + 7);
        }
        b.m[0] |= 1;
        let r = Int::from_limbs(&[12345u64, 678], false);
        let n = a.mul(&b).unwrap().add(&r).unwrap();
        let (q, rr) = n.divmod(&b).unwrap();
        assert_eq!(q, a);
        assert_eq!(rr, r);
    }

    #[test]
    fn class_number_kills_every_form() {
        for &dv in &[-23i64, -47, -71, -199, -1031, -10007, -100_003] {
            let forms = reduced_forms(dv);
            let h = forms.len() as u64;
            assert!(h % 2 == 1, "prime discriminant has odd class number");
            let dd = d(dv);
            let id = Form::identity(&dd).unwrap();
            for &(a, b) in forms.iter().take(12) {
                let f = Form::from_ab(d(a), d(b), &dd).unwrap();
                assert!(f.is_reduced());
                let p = f.pow(&[h], &dd).unwrap();
                assert_eq!(p, id, "f^h != 1 for D={} f=({},{})", dv, a, b);
                // f^(h+1) == f and the discriminant is preserved by every step
                let q = f.pow(&[h + 1], &dd).unwrap();
                assert_eq!(q, f);
                assert_eq!(f.square().unwrap().discriminant().unwrap(), dd);
            }
        }
    }

    #[test]
    fn composition_is_a_group_law() {
        let dv = -100_003i64;
        let dd = d(dv);
        let forms = reduced_forms(dv);
        let fs: Vec<Form> = forms.iter().take(8).map(|&(a, b)| Form::from_ab(d(a), d(b), &dd).unwrap()).collect();
        for x in &fs {
            for y in &fs {
                let xy = x.compose(y).unwrap();
                assert!(xy.is_reduced());
                assert_eq!(xy, y.compose(x).unwrap());
                for z in fs.iter().take(3) {
                    assert_eq!(xy.compose(z).unwrap(), x.compose(&y.compose(z).unwrap()).unwrap());
                }
            }
        }
    }

    #[test]
    fn vdf_round_trip_small_discriminant_and_tamper() {
        // A 2048-bit run is in tests/vdf.rs; here the logic on a 64-bit discriminant.
        let dd = Int::from_limbs(&[0xffff_ffff_ffff_ffc5u64], true); // -(2^64 - 59), 2^64-59 is prime, = 3 mod 4
        let mut proof = [0u8; PROOF_LEN];
        evaluate_with(&dd, b"ledger", 200, &mut proof).unwrap();
        verify_with(&dd, b"ledger", 200, &proof).unwrap();
        assert!(verify_with(&dd, b"ledger", 201, &proof).is_err());
        assert!(verify_with(&dd, b"ledgeR", 200, &proof).is_err());
    }

    #[test]
    fn ints_are_wiped_on_drop() {
        let mut slot = core::mem::MaybeUninit::<Int>::uninit();
        let p = slot.as_mut_ptr();
        unsafe {
            p.write(Int::from_i64(0x1234_5678));
            core::ptr::drop_in_place(p);
            assert!((*p).m.iter().all(|&w| w == 0));
        }
    }
}
