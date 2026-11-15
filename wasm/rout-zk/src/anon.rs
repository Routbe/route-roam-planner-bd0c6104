//! Anonymous booking (Stap 7f): the guest's presentation of a slot credential
//! and the host's capacity proofs.
//!
//! Presentation. A slot credential (forward_secure::EpochKey::sign_slot_credential)
//! signs [key_id, I2OSP(t, 8), RAW I2OSP(slot, 8), m_1..m_L] plus the guest's
//! blind message [nullifier]. At arrival the guest runs BlindProofGen under
//! CREDENTIAL_HEADER with the verifier's challenge as presentation header and
//!   - discloses key id, epoch, m_1..m_L and the nullifier,
//!   - commits to the slot: C = Y_0·s + Y_1·slot (committed disclosure, the
//!     COM_DIS generators of the blind ciphersuite),
//!   - hides the prover blind.
//! Two 64-bit Bulletproofs over the Pedersen pair (g, h) = (Y_1, Y_0) then show
//!   C − lo·Y_1 = commit(slot − lo, s)   and   hi·Y_1 − C = commit(hi − slot, −s)
//! are in [0, 2^64), i.e. lo <= slot <= hi, without revealing the slot. Both
//! proofs are bound (context) to the challenge, the window and C, so neither
//! can be moved to another presentation. Encoding:
//!   blind proof (8 + bbs_len + 48 + 32) || range(slot − lo) (928) || range(hi − slot) (928)
//!
//! Capacity. A pool of `capacity` seats is opened as C_0 = commit(capacity, r_0)
//! with a range proof. Take i (1-based) of `take` seats publishes
//!   C_take,i = commit(take, r_i)    and    C_rem,i = C_rem,i−1 − C_take,i
//! with one range proof that take − 1 >= 0 (on C_take,i − g) and one that the
//! remainder is >= 0 (on C_rem,i), so the pool can never be overbooked and a
//! take can never add seats. Blindings are derived from 32 octets of host key
//! material: r_0 = H(km, pool, 0, 0), r_i = H(km, pool, 1, i) and the remainder
//! blinding r_0 − Σ r_i, so the host keeps no per-step secret; nobody without
//! km learns a count. Every proof is bound to (pool, step, role).

use crate::blind::{self, Disclosure};
use crate::bulletproofs::{self, BulletproofGens, RangeProof, PROOF_LEN};
use crate::codec::{g1_from_bytes, G1_LEN, SCALAR_LEN};
use crate::core_bbs::{Msg, PROOF_MIN_LEN};
use crate::forward_secure::{self as fs, CREDENTIAL_HEADER, MAX_SLOT_MESSAGES};
use crate::generators::API_ID_BLIND;
use crate::limits::MAX_SIGNER_MESSAGES;
use crate::pedersen::{Commitment, PedersenGens, COMMITMENT_LEN};
use crate::random::ScalarSource;
use crate::xmd::Xmd;
use crate::{wipe, Error, Result};
use bls12_381::{G1Projective, Scalar};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const NULLIFIER_LEN: usize = 32;
pub const WINDOW_PROOFS_LEN: usize = 2 * PROOF_LEN;
/// One committed disclosure: C (48) and its response (32).
pub const COMMIT_TAIL_LEN: usize = G1_LEN + SCALAR_LEN;
pub const MAX_CHALLENGE: usize = 256;
pub const PRESENT_CTX: &[u8] = b"ROUT-ANON-PRESENT-WINDOW-V1";

pub const KM_LEN: usize = 32;
pub const MAX_POOL_ID: usize = 128;
/// Takes per pool (the remainder blinding replays every step once).
pub const MAX_TAKES: u64 = 1 << 16;
pub const CAPACITY_PROOFS_LEN: usize = 2 * PROOF_LEN;
pub const CAPACITY_DST: &[u8] = b"ROUT-ANON-CAPACITY-BLIND-V1_";
pub const CAPACITY_CTX: &[u8] = b"ROUT-ANON-CAPACITY-V1";

/// (g, h) = (Y_1, Y_0): the pair the committed disclosure uses.
fn window_gens() -> Result<PedersenGens> {
    let (y0, y1) = blind::com_dis_generators(API_ID_BLIND)?;
    Ok(PedersenGens { g: y1, h: y0 })
}

fn window_ctx(role: &[u8; 2], lo: u64, hi: u64, c: &[u8], challenge: &[u8]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(PRESENT_CTX);
    d.update(role);
    d.update(lo.to_be_bytes());
    d.update(hi.to_be_bytes());
    d.update(c);
    d.update((challenge.len() as u32).to_be_bytes());
    d.update(challenge);
    d.finalize().into()
}

fn window_inputs(nullifier: &[u8], challenge: &[u8], lo: u64, hi: u64, n_msgs: usize) -> Result<()> {
    if nullifier.len() != NULLIFIER_LEN || challenge.is_empty() || challenge.len() > MAX_CHALLENGE || lo > hi {
        return Err(Error::Invalid);
    }
    if n_msgs > MAX_SLOT_MESSAGES {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Length of the blind-proof part of an encoded presentation.
fn blind_part_len(proof: &[u8]) -> Result<usize> {
    if proof.len() < 8 + WINDOW_PROOFS_LEN {
        return Err(Error::Invalid);
    }
    let bbs = u64::from_be_bytes(proof[..8].try_into().map_err(|_| Error::Invalid)?);
    let max = (proof.len() - 8 - WINDOW_PROOFS_LEN - COMMIT_TAIL_LEN) as u64;
    if bbs < PROOF_MIN_LEN as u64 || bbs > max {
        return Err(Error::Invalid);
    }
    let len = 8 + bbs as usize + COMMIT_TAIL_LEN;
    if len + WINDOW_PROOFS_LEN != proof.len() {
        return Err(Error::Invalid);
    }
    Ok(len)
}

/// Guest presentation at arrival; returns its length in `out`.
#[allow(clippy::too_many_arguments)]
pub fn present<R: ScalarSource>(
    pk: &[u8], kid: &[u8], epoch: u64, sig: &[u8], slot: u64, msgs: &[&[u8]], nullifier: &[u8], prover_blind: &Scalar,
    challenge: &[u8], lo: u64, hi: u64, rng: &mut R, out: &mut [u8],
) -> Result<usize> {
    window_inputs(nullifier, challenge, lo, hi, msgs.len())?;
    let kid = fs::key_id(kid)?;
    if slot < lo || slot > hi {
        // Not this window: no proof is produced at all.
        return Err(Error::Rejected);
    }
    if out.len() < WINDOW_PROOFS_LEN + 8 {
        return Err(Error::TooLarge);
    }
    let e = epoch.to_be_bytes();
    let s = slot.to_be_bytes();
    let mut m = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES];
    let n = fs::slot_bound(kid, &e, &s, msgs, &mut m);
    let mut sd = [Disclosure::Disclose; MAX_SIGNER_MESSAGES];
    sd[2] = Disclosure::Commit;
    let cap = out.len() - WINDOW_PROOFS_LEN;
    let mut rands = [Scalar::zero(); 1];
    let mut v = [Scalar::zero(); 3];
    let res = present_ranges(
        pk, sig, challenge, &m[..n], &sd[..n], nullifier, prover_blind, slot, lo, hi, rng, out, cap, &mut rands, &mut v,
    );
    wipe::scalars(&mut rands);
    wipe::scalars(&mut v);
    if res.is_err() {
        wipe::bytes(out);
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn present_ranges<R: ScalarSource>(
    pk: &[u8], sig: &[u8], challenge: &[u8], m: &[Msg<'_>], sd: &[Disclosure], nullifier: &[u8], prover_blind: &Scalar,
    slot: u64, lo: u64, hi: u64, rng: &mut R, out: &mut [u8], cap: usize, rands: &mut [Scalar; 1], v: &mut [Scalar; 3],
) -> Result<usize> {
    let b = [Msg::Hash(nullifier)];
    let len = blind::blind_proof_gen(
        pk, sig, CREDENTIAL_HEADER, challenge, m, &b, sd, &[Disclosure::Disclose], prover_blind, rng, &mut out[..cap], Some(&mut rands[..]),
    )?;
    let bbs = u64::from_be_bytes(out[..8].try_into().map_err(|_| Error::Invalid)?) as usize;
    if len != 8 + bbs + COMMIT_TAIL_LEN {
        return Err(Error::Invalid);
    }
    let c_bytes = &out[8 + bbs..8 + bbs + G1_LEN];
    let c = G1Projective::from(g1_from_bytes(c_bytes)?);
    let gens = window_gens()?;
    let bg = BulletproofGens::canonical();
    let ctx_lo = window_ctx(b"lo", lo, hi, c_bytes, challenge);
    let ctx_hi = window_ctx(b"hi", lo, hi, c_bytes, challenge);
    v[0] = Scalar::from(slot - lo);
    v[1] = Scalar::from(hi - slot);
    v[2] = -rands[0];
    let (c_lo, p_lo) = bulletproofs::prove(&gens, &bg, &v[0], &rands[0], &ctx_lo, rng)?;
    let (c_hi, p_hi) = bulletproofs::prove(&gens, &bg, &v[1], &v[2], &ctx_hi, rng)?;
    // The range commitments must be exactly the ones the verifier derives from C.
    let want_lo = Commitment(c - gens.g * Scalar::from(lo));
    let want_hi = Commitment(gens.g * Scalar::from(hi) - c);
    if !(c_lo.ct_eq(&want_lo) && c_hi.ct_eq(&want_hi)) {
        return Err(Error::Invalid);
    }
    out[len..len + PROOF_LEN].copy_from_slice(&p_lo.to_bytes());
    out[len + PROOF_LEN..len + WINDOW_PROOFS_LEN].copy_from_slice(&p_hi.to_bytes());
    Ok(len + WINDOW_PROOFS_LEN)
}

/// Verifier side: Ok only if `proof` shows a valid slot credential of this
/// chain and epoch, with these public messages and this nullifier, for the
/// given challenge, whose hidden slot lies in [lo, hi].
#[allow(clippy::too_many_arguments)]
pub fn verify_presentation(
    pk: &[u8], kid: &[u8], epoch: u64, proof: &[u8], msgs: &[&[u8]], nullifier: &[u8], challenge: &[u8], lo: u64, hi: u64,
) -> Result<()> {
    window_inputs(nullifier, challenge, lo, hi, msgs.len())?;
    let kid = fs::key_id(kid)?;
    let blind_len = blind_part_len(proof)?;
    let e = epoch.to_be_bytes();
    let mut dm = [Msg::Hash(&[]); MAX_SIGNER_MESSAGES + 1];
    let mut dd = [Disclosure::Disclose; MAX_SIGNER_MESSAGES + 1];
    dm[0] = Msg::Hash(kid);
    dm[1] = Msg::Hash(&e);
    for (i, x) in msgs.iter().enumerate() {
        dm[2 + i] = Msg::Hash(x);
    }
    dm[2 + msgs.len()] = Msg::Hash(nullifier);
    let issuer_known = fs::SLOT_BOUND_MESSAGES + msgs.len();
    dd[2] = Disclosure::Commit;
    blind::blind_proof_verify(pk, &proof[..blind_len], CREDENTIAL_HEADER, challenge, issuer_known, &dm[..3 + msgs.len()], &dd[..issuer_known + 1])?;
    let bbs = blind_len - 8 - COMMIT_TAIL_LEN;
    let c_bytes = &proof[8 + bbs..8 + bbs + G1_LEN];
    let c = G1Projective::from(g1_from_bytes(c_bytes)?);
    let gens = window_gens()?;
    let bg = BulletproofGens::canonical();
    let p_lo = RangeProof::from_bytes(&proof[blind_len..blind_len + PROOF_LEN])?;
    let p_hi = RangeProof::from_bytes(&proof[blind_len + PROOF_LEN..])?;
    let c_lo = Commitment(c - gens.g * Scalar::from(lo));
    let c_hi = Commitment(gens.g * Scalar::from(hi) - c);
    bulletproofs::verify(&gens, &bg, &c_lo, &p_lo, &window_ctx(b"lo", lo, hi, c_bytes, challenge))?;
    bulletproofs::verify(&gens, &bg, &c_hi, &p_hi, &window_ctx(b"hi", lo, hi, c_bytes, challenge))
}

// ---- capacity -------------------------------------------------------------

fn pool_inputs(km: Option<&[u8]>, pool: &[u8]) -> Result<()> {
    if pool.is_empty() || pool.len() > MAX_POOL_ID {
        return Err(Error::Invalid);
    }
    if let Some(km) = km {
        if km.len() != KM_LEN || bool::from(km.ct_eq(&[0u8; KM_LEN][..])) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

fn pool_blind(km: &[u8], pool: &[u8], role: u8, step: u64) -> Result<Scalar> {
    let mut x = Xmd::new();
    x.update(km).update(&(pool.len() as u32).to_be_bytes()).update(pool).update(&[role]).update(&step.to_be_bytes());
    x.to_scalar(CAPACITY_DST)
}

/// r_0 − Σ_{i=1..done} r_i: the blinding of the remainder after `done` takes.
fn remainder_blind(km: &[u8], pool: &[u8], done: u64) -> Result<Scalar> {
    let mut r = pool_blind(km, pool, 0, 0)?;
    for i in 1..=done {
        let mut t = match pool_blind(km, pool, 1, i) {
            Ok(t) => t,
            Err(e) => {
                wipe::scalar(&mut r);
                return Err(e);
            }
        };
        r -= t;
        wipe::scalar(&mut t);
    }
    Ok(r)
}

fn capacity_ctx(pool: &[u8], step: u64, role: &[u8; 4]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(CAPACITY_CTX);
    d.update((pool.len() as u32).to_be_bytes());
    d.update(pool);
    d.update(step.to_be_bytes());
    d.update(role);
    d.finalize().into()
}

/// Opens a pool: C_0 (48) and its range proof (928).
pub fn capacity_open<R: ScalarSource>(km: &[u8], pool: &[u8], capacity: u64, rng: &mut R) -> Result<([u8; COMMITMENT_LEN], [u8; PROOF_LEN])> {
    pool_inputs(Some(km), pool)?;
    let mut r = pool_blind(km, pool, 0, 0)?;
    let mut v = Scalar::from(capacity);
    let res = bulletproofs::prove(&PedersenGens::canonical(), &BulletproofGens::canonical(), &v, &r, &capacity_ctx(pool, 0, b"open"), rng);
    wipe::scalar(&mut r);
    wipe::scalar(&mut v);
    let (c, p) = res?;
    Ok((c.to_bytes(), p.to_bytes()))
}

pub fn capacity_verify_open(c: &[u8], pool: &[u8], proof: &[u8]) -> Result<()> {
    pool_inputs(None, pool)?;
    let c = Commitment::from_bytes(c)?;
    let p = RangeProof::from_bytes(proof)?;
    bulletproofs::verify(&PedersenGens::canonical(), &BulletproofGens::canonical(), &c, &p, &capacity_ctx(pool, 0, b"open"))
}

/// A take.
pub struct Take {
    pub take_commitment: [u8; COMMITMENT_LEN],
    pub remaining_commitment: [u8; COMMITMENT_LEN],
    pub proofs: [u8; CAPACITY_PROOFS_LEN],
}

/// Take number `step` (1-based) of `take` seats from `before` remaining ones.
/// More than remain, or zero, is REJECTED: no proof exists for it.
pub fn capacity_take<R: ScalarSource>(km: &[u8], pool: &[u8], step: u64, before: u64, take: u64, rng: &mut R) -> Result<Take> {
    pool_inputs(Some(km), pool)?;
    if step == 0 || step > MAX_TAKES {
        return Err(Error::Invalid);
    }
    if take == 0 || take > before {
        return Err(Error::Rejected);
    }
    let pg = PedersenGens::canonical();
    let bg = BulletproofGens::canonical();
    let mut s = [Scalar::zero(); 5];
    let res = (|| {
        s[0] = remainder_blind(km, pool, step - 1)?; // r_rem,i−1
        s[1] = pool_blind(km, pool, 1, step)?; // r_i
        s[2] = s[0] - s[1]; // r_rem,i
        s[3] = Scalar::from(take - 1);
        s[4] = Scalar::from(before - take);
        let (c_take_minus_g, p_take) = bulletproofs::prove(&pg, &bg, &s[3], &s[1], &capacity_ctx(pool, step, b"take"), rng)?;
        let (c_rem, p_rem) = bulletproofs::prove(&pg, &bg, &s[4], &s[2], &capacity_ctx(pool, step, b"rest"), rng)?;
        let c_take = Commitment(c_take_minus_g.0 + pg.g);
        // Sanity: the remainder is exactly the previous one minus this take.
        let c_before = pg.commit_u64(before, &s[0]);
        if !c_rem.ct_eq(&c_before.sub(&c_take)) {
            return Err(Error::Invalid);
        }
        let mut proofs = [0u8; CAPACITY_PROOFS_LEN];
        proofs[..PROOF_LEN].copy_from_slice(&p_take.to_bytes());
        proofs[PROOF_LEN..].copy_from_slice(&p_rem.to_bytes());
        Ok(Take { take_commitment: c_take.to_bytes(), remaining_commitment: c_rem.to_bytes(), proofs })
    })();
    wipe::scalars(&mut s);
    res
}

/// Ok only if C_rem,i = C_rem,i−1 − C_take,i, take >= 1 and the remainder >= 0.
pub fn capacity_verify_take(before: &[u8], take: &[u8], after: &[u8], pool: &[u8], step: u64, proofs: &[u8]) -> Result<()> {
    pool_inputs(None, pool)?;
    if step == 0 || step > MAX_TAKES || proofs.len() != CAPACITY_PROOFS_LEN {
        return Err(Error::Invalid);
    }
    let pg = PedersenGens::canonical();
    let bg = BulletproofGens::canonical();
    let c_before = Commitment::from_bytes(before)?;
    let c_take = Commitment::from_bytes(take)?;
    let c_after = Commitment::from_bytes(after)?;
    let p_take = RangeProof::from_bytes(&proofs[..PROOF_LEN])?;
    let p_rem = RangeProof::from_bytes(&proofs[PROOF_LEN..])?;
    if !c_after.ct_eq(&c_before.sub(&c_take)) {
        return Err(Error::Rejected);
    }
    bulletproofs::verify(&pg, &bg, &Commitment(c_take.0 - pg.g), &p_take, &capacity_ctx(pool, step, b"take"))?;
    bulletproofs::verify(&pg, &bg, &c_after, &p_rem, &capacity_ctx(pool, step, b"rest"))
}
