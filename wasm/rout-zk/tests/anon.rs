//! Stap 7f: slot credentials, anonymous window presentations and capacity pools.

use bls12_381::Scalar;
use rout_zk::anon::{self, CAPACITY_PROOFS_LEN, WINDOW_PROOFS_LEN};
use rout_zk::blind;
use rout_zk::codec::scalar_from_be;
use rout_zk::core_bbs::Msg;
use rout_zk::forward_secure::{self as fs, EpochKey};
use rout_zk::random::Seeded;
use rout_zk::Error;

const KID: &[u8] = b"hk_7f00000000000000000000000000000000000000000000000000000000000001";
const NF: [u8; 32] = [0x42; 32];
const SLOT: u64 = 29_000_000; // unix minutes
const KM: [u8; 32] = [0x17; 32];

fn rng(tag: &'static [u8]) -> Seeded<'static> {
    Seeded { seed: tag, dst: b"ROUT-ZK-TEST-ANON-7F" }
}

struct Issued {
    key: EpochKey,
    pk: [u8; 96],
    sig: [u8; 80],
    blind: Scalar,
}

fn issue(slot: u64, msgs: &[&[u8]]) -> Issued {
    let mut key = EpochKey::from_seed(&[0x33; 32]).unwrap();
    key.advance(KID, 3).unwrap();
    let pk = key.public_key(KID).unwrap();
    let mut cwp = [0u8; 512];
    let (len, pb) = blind::commit(&[Msg::Hash(&NF)], &mut rng(b"commit"), &mut cwp).unwrap();
    let sig = key.sign_slot_credential(KID, &cwp[..len], slot, msgs).unwrap();
    fs::verify_slot_credential(&pk, KID, 3, &sig, slot, msgs, &[&NF], &pb).unwrap();
    Issued { key, pk, sig, blind: pb }
}

fn present(i: &Issued, msgs: &[&[u8]], ch: &[u8], lo: u64, hi: u64) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; 8192];
    let n = anon::present(&i.pk, KID, 3, &i.sig, SLOT, msgs, &NF, &i.blind, ch, lo, hi, &mut rng(b"present"), &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[test]
fn slot_credential_is_bound_to_slot_epoch_and_nullifier() {
    let i = issue(SLOT, &[b"service:1"]);
    let m: &[&[u8]] = &[b"service:1"];
    assert_eq!(fs::verify_slot_credential(&i.pk, KID, 3, &i.sig, SLOT + 1, m, &[&NF], &i.blind), Err(Error::Rejected));
    assert_eq!(fs::verify_slot_credential(&i.pk, KID, 2, &i.sig, SLOT, m, &[&NF], &i.blind), Err(Error::Rejected));
    assert_eq!(fs::verify_slot_credential(&i.pk, KID, 3, &i.sig, SLOT, m, &[&[0x43; 32]], &i.blind), Err(Error::Rejected));
    assert!(i.key.epoch() == 3);
}

#[test]
fn presentation_proves_the_window_without_the_slot() {
    let m: &[&[u8]] = &[b"service:1"];
    let i = issue(SLOT, m);
    let ch = b"arrival-challenge-0001";
    let p = present(&i, m, ch, SLOT - 15, SLOT + 15).unwrap();
    // Fixed shape: blind proof with one committed disclosure + two range proofs.
    assert!(p.len() > WINDOW_PROOFS_LEN);
    anon::verify_presentation(&i.pk, KID, 3, &p, m, &NF, ch, SLOT - 15, SLOT + 15).unwrap();
    // The slot never appears in the presentation.
    assert!(!p.windows(8).any(|w| w == SLOT.to_be_bytes()));
    // Exact edges are inside the window.
    assert!(present(&i, m, ch, SLOT, SLOT).is_ok());
    // Outside the window no proof is produced.
    assert_eq!(present(&i, m, ch, SLOT + 1, SLOT + 30).unwrap_err(), Error::Rejected);
    assert_eq!(present(&i, m, ch, SLOT - 30, SLOT - 1).unwrap_err(), Error::Rejected);
}

#[test]
fn presentation_rejects_every_substitution() {
    let m: &[&[u8]] = &[b"service:1"];
    let i = issue(SLOT, m);
    let ch = b"arrival-challenge-0002";
    let (lo, hi) = (SLOT - 10, SLOT + 10);
    let p = present(&i, m, ch, lo, hi).unwrap();
    let v = |pk: &[u8], e: u64, p: &[u8], m: &[&[u8]], nf: &[u8], ch: &[u8], lo: u64, hi: u64| {
        anon::verify_presentation(pk, KID, e, p, m, nf, ch, lo, hi)
    };
    assert!(v(&i.pk, 3, &p, m, &NF, ch, lo, hi).is_ok());
    // Another challenge (replay), window, nullifier, message, epoch or key.
    assert!(v(&i.pk, 3, &p, m, &NF, b"arrival-challenge-0003", lo, hi).is_err());
    assert!(v(&i.pk, 3, &p, m, &NF, ch, lo + 1, hi).is_err());
    assert!(v(&i.pk, 3, &p, m, &NF, ch, lo, hi + 1).is_err());
    assert!(v(&i.pk, 3, &p, m, &[0x43; 32], ch, lo, hi).is_err());
    assert!(v(&i.pk, 3, &p, &[b"service:2"], &NF, ch, lo, hi).is_err());
    assert!(v(&i.pk, 4, &p, m, &NF, ch, lo, hi).is_err());
    let other = EpochKey::from_seed(&[0x34; 32]).unwrap().public_key(KID).unwrap();
    assert!(v(&other, 3, &p, m, &NF, ch, lo, hi).is_err());
    // Flipping any byte of any part fails.
    for at in [0usize, 9, 300, p.len() - WINDOW_PROOFS_LEN - 40, p.len() - WINDOW_PROOFS_LEN + 5, p.len() - 1] {
        let mut t = p.clone();
        t[at] ^= 1;
        assert!(v(&i.pk, 3, &t, m, &NF, ch, lo, hi).is_err(), "byte {at}");
    }
    // Swapping the two range proofs fails.
    let mut s = p.clone();
    let base = p.len() - WINDOW_PROOFS_LEN;
    s[base..base + 928].copy_from_slice(&p[base + 928..]);
    s[base + 928..].copy_from_slice(&p[base..base + 928]);
    assert!(v(&i.pk, 3, &s, m, &NF, ch, lo, hi).is_err());
    // Truncated or extended encodings are malformed.
    assert_eq!(v(&i.pk, 3, &p[..p.len() - 1], m, &NF, ch, lo, hi), Err(Error::Invalid));
    let mut e = p.clone();
    e.push(0);
    assert_eq!(v(&i.pk, 3, &e, m, &NF, ch, lo, hi), Err(Error::Invalid));
}

#[test]
fn two_presentations_of_one_credential_share_no_bytes_but_the_disclosed() {
    let m: &[&[u8]] = &[b"service:1"];
    let i = issue(SLOT, m);
    let mut out = vec![0u8; 8192];
    let a = anon::present(&i.pk, KID, 3, &i.sig, SLOT, m, &NF, &i.blind, b"c1", SLOT - 5, SLOT + 5, &mut rng(b"a"), &mut out).unwrap();
    let pa = out[..a].to_vec();
    let b = anon::present(&i.pk, KID, 3, &i.sig, SLOT, m, &NF, &i.blind, b"c1", SLOT - 5, SLOT + 5, &mut rng(b"b"), &mut out).unwrap();
    let pb = out[..b].to_vec();
    assert_eq!(a, b);
    // Fresh randomness: the slot commitment C differs between presentations.
    let bbs = u64::from_be_bytes(pa[..8].try_into().unwrap()) as usize;
    assert_ne!(&pa[8 + bbs..8 + bbs + 48], &pb[8 + bbs..8 + bbs + 48]);
}

#[test]
fn capacity_pool_never_overbooks() {
    let pool = b"cp_0000000000000000000000000000000000000000000000000000000000000001";
    let (c0, p0) = anon::capacity_open(&KM, pool, 5, &mut rng(b"open")).unwrap();
    anon::capacity_verify_open(&c0, pool, &p0).unwrap();
    assert!(anon::capacity_verify_open(&c0, b"cp_other", &p0).is_err());

    let mut before_c = c0;
    let mut before = 5u64;
    for (step, take) in [(1u64, 2u64), (2, 1), (3, 2)] {
        let t = anon::capacity_take(&KM, pool, step, before, take, &mut rng(b"take")).unwrap();
        anon::capacity_verify_take(&before_c, &t.take_commitment, &t.remaining_commitment, pool, step, &t.proofs).unwrap();
        // Bound to its step and pool, and to the previous remainder.
        assert!(anon::capacity_verify_take(&before_c, &t.take_commitment, &t.remaining_commitment, pool, step + 1, &t.proofs).is_err());
        assert!(anon::capacity_verify_take(&c0, &t.take_commitment, &t.remaining_commitment, b"cp_x", step, &t.proofs).is_err());
        if step > 1 {
            assert!(anon::capacity_verify_take(&c0, &t.take_commitment, &t.remaining_commitment, pool, step, &t.proofs).is_err());
        }
        before_c = t.remaining_commitment;
        before -= take;
    }
    assert_eq!(before, 0);
    // The pool is empty: no take of any size has a proof.
    assert_eq!(anon::capacity_take(&KM, pool, 4, 0, 1, &mut rng(b"t")).err(), Some(Error::Rejected));
    assert_eq!(anon::capacity_take(&KM, pool, 4, 3, 0, &mut rng(b"t")).err(), Some(Error::Rejected));
    assert_eq!(anon::capacity_take(&KM, pool, 4, 3, 4, &mut rng(b"t")).err(), Some(Error::Rejected));
}

#[test]
fn a_lying_host_cannot_prove_a_take_beyond_the_remainder() {
    // Claiming 10 remain when only 1 does: the commitment chain no longer
    // matches, so the verifier (who holds the published C_rem) refuses.
    let pool = b"cp_lie";
    let (c0, _) = anon::capacity_open(&KM, pool, 1, &mut rng(b"open")).unwrap();
    let t = anon::capacity_take(&KM, pool, 1, 10, 5, &mut rng(b"take")).unwrap();
    assert!(anon::capacity_verify_take(&c0, &t.take_commitment, &t.remaining_commitment, pool, 1, &t.proofs).is_err());
    // Tampered proofs or commitments fail too.
    let ok = anon::capacity_take(&KM, pool, 1, 1, 1, &mut rng(b"take")).unwrap();
    anon::capacity_verify_take(&c0, &ok.take_commitment, &ok.remaining_commitment, pool, 1, &ok.proofs).unwrap();
    let mut bad = ok.proofs;
    bad[CAPACITY_PROOFS_LEN - 1] ^= 1;
    assert!(anon::capacity_verify_take(&c0, &ok.take_commitment, &ok.remaining_commitment, pool, 1, &bad).is_err());
    // Another host key material produces different, unlinkable commitments.
    let (c0b, _) = anon::capacity_open(&[0x18; 32], pool, 1, &mut rng(b"open")).unwrap();
    assert_ne!(c0, c0b);
    // All-zero key material is refused (a failed derivation).
    assert_eq!(anon::capacity_open(&[0u8; 32], pool, 1, &mut rng(b"open")).err(), Some(Error::Invalid));
    let _ = scalar_from_be(&[0u8; 32]);
}
