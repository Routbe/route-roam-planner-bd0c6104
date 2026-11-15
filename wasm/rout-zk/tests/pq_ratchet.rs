//! Stap 8: hybrid post-quantum double ratchet (ML-KEM-1024 + X25519, RVE2).

use rout_zk::pq_ratchet::{self as pq, off, ENCRYPT_RANDOM_LEN, ENVELOPE_OVERHEAD, HEADER_LEN, RESPONDER_RANDOM_LEN, STATE_LEN};
use rout_zk::Error;
use sha2::{Digest, Sha256};

const CTX: &[u8] = b"rout.pqr.v1|member-a|member-b|conversation-1";

/// Deterministic test randomness: SHA-256(tag || counter) blocks.
struct Rng {
    tag: &'static [u8],
    n: u64,
}

impl Rng {
    fn new(tag: &'static [u8]) -> Self {
        Rng { tag, n: 0 }
    }
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(self.tag);
            h.update(self.n.to_be_bytes());
            self.n += 1;
            let d = h.finalize();
            chunk.copy_from_slice(&d[..chunk.len()]);
        }
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}

struct Party {
    state: Vec<u8>,
    rng: Rng,
}

impl Party {
    fn send(&mut self, msg: &[u8]) -> Vec<u8> {
        let r: [u8; ENCRYPT_RANDOM_LEN] = self.rng.bytes();
        let mut out = vec![0u8; ENVELOPE_OVERHEAD + msg.len()];
        let n = pq::encrypt(&mut self.state, &r, msg, &mut out).unwrap();
        assert_eq!(n, out.len());
        out
    }
    fn recv(&mut self, env: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; pq::MAX_PLAINTEXT];
        let n = pq::decrypt(&mut self.state, env, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

fn pair() -> (Party, Party) {
    let mut bob = Party { state: vec![0u8; STATE_LEN], rng: Rng::new(b"bob") };
    let mut bundle = vec![0u8; pq::BUNDLE_LEN];
    let r: [u8; RESPONDER_RANDOM_LEN] = bob.rng.bytes();
    pq::responder_init(&r, CTX, &mut bob.state, &mut bundle).unwrap();
    let mut alice = Party { state: vec![0u8; STATE_LEN], rng: Rng::new(b"alice") };
    pq::initiator_init(CTX, &bundle, &mut alice.state).unwrap();
    (alice, bob)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn layout_constants() {
    assert_eq!(pq::BUNDLE_LEN, 1606);
    assert_eq!(HEADER_LEN, 3186);
    assert_eq!(ENVELOPE_OVERHEAD, 3234);
    assert_eq!(STATE_LEN, 9888);
}

#[test]
fn handshake_and_hybrid_exchange_round_trip() {
    let (mut alice, mut bob) = pair();
    let e1 = alice.send(b"hello bob");
    assert_eq!(&e1[..6], b"RVE2\x01\x01");
    assert_eq!(bob.recv(&e1).unwrap(), b"hello bob");
    // Bob answers on a fresh KEM + DH step, Alice answers again: three chains.
    let e2 = bob.send(b"hello alice");
    assert_ne!(&e2[6..38], &e1[6..38]);
    assert_eq!(alice.recv(&e2).unwrap(), b"hello alice");
    let e3 = alice.send(b"status: online");
    assert_ne!(&e3[6..38], &e1[6..38]);
    assert_eq!(bob.recv(&e3).unwrap(), b"status: online");
    // Both sides agree on the root key after every step.
    assert_eq!(&alice.state[off::RK..off::RK + 32], &bob.state[off::RK..off::RK + 32]);
    // Empty and maximum-size payloads.
    let e4 = bob.send(b"");
    assert_eq!(alice.recv(&e4).unwrap(), b"");
    let big = vec![0x5au8; pq::MAX_PLAINTEXT];
    let e5 = alice.send(&big);
    assert_eq!(bob.recv(&e5).unwrap(), big);
}

#[test]
fn both_shares_bind_the_root_key() {
    // A responder whose ML-KEM seed or X25519 secret differs from the bundle it
    // published cannot open the first message: each share alone changes RK.
    // (The ML-KEM seed is d || z; d determines the key pair, z only the implicit-rejection value.)
    for at in [off::OWN_KEM_SEED, off::OWN_X_SK + 1] {
        let (mut alice, mut bob) = pair();
        bob.state[at] ^= 1;
        let before = bob.state.clone();
        let e1 = alice.send(b"bound");
        assert_eq!(bob.recv(&e1), Err(Error::Rejected));
        assert_eq!(bob.state, before);
    }
    // Another context (other identities or conversation) does not open either.
    let (mut alice, _) = pair();
    let mut other = Party { state: vec![0u8; STATE_LEN], rng: Rng::new(b"bob") };
    let mut bundle = vec![0u8; pq::BUNDLE_LEN];
    let r: [u8; RESPONDER_RANDOM_LEN] = other.rng.bytes();
    pq::responder_init(&r, b"rout.pqr.v1|member-a|member-c|conversation-1", &mut other.state, &mut bundle).unwrap();
    assert_eq!(other.recv(&alice.send(b"x")), Err(Error::Rejected));
}

#[test]
fn responder_cannot_send_first_and_bad_inputs_are_refused() {
    let (_, mut bob) = pair();
    let r: [u8; ENCRYPT_RANDOM_LEN] = bob.rng.bytes();
    let mut out = vec![0u8; ENVELOPE_OVERHEAD + 1];
    assert_eq!(pq::encrypt(&mut bob.state, &r, b"x", &mut out), Err(Error::Invalid));
    let mut s = vec![0u8; STATE_LEN];
    let mut bundle = vec![0u8; pq::BUNDLE_LEN];
    assert_eq!(pq::responder_init(&[0u8; RESPONDER_RANDOM_LEN], CTX, &mut s, &mut bundle), Err(Error::Invalid));
    let r2: [u8; RESPONDER_RANDOM_LEN] = Rng::new(b"z").bytes();
    assert_eq!(pq::responder_init(&r2, b"", &mut s, &mut bundle), Err(Error::Invalid));
    pq::responder_init(&r2, CTX, &mut s, &mut bundle).unwrap();
    let mut bad = bundle.clone();
    bad[5] = 1;
    assert_eq!(pq::initiator_init(CTX, &bad, &mut s), Err(Error::Invalid));
    // An ML-KEM key with a coefficient >= q fails the FIPS 203 input check.
    let mut bad = bundle.clone();
    bad[38] = 0xff;
    bad[39] |= 0x0f;
    assert_eq!(pq::initiator_init(CTX, &bad, &mut s), Err(Error::Invalid));
    let mut bad = bundle.clone();
    bad[6..38].fill(0);
    assert_eq!(pq::initiator_init(CTX, &bad, &mut s), Err(Error::Invalid));
}

#[test]
fn forward_secrecy_old_chain_and_message_keys_are_gone() {
    let (mut alice, mut bob) = pair();
    let e1 = alice.send(b"one");
    bob.recv(&e1).unwrap();
    let ck_before = alice.state[off::CKS..off::CKS + 32].to_vec();
    let e2 = alice.send(b"two");
    // The chain key was replaced in place; its old value is nowhere in the state.
    assert_ne!(&alice.state[off::CKS..off::CKS + 32], &ck_before[..]);
    assert!(!contains(&alice.state, &ck_before));
    let ckr_before = bob.state[off::CKR..off::CKR + 32].to_vec();
    assert_eq!(bob.recv(&e2).unwrap(), b"two");
    assert!(!contains(&bob.state, &ckr_before));
    // A full copy of Bob's state taken now opens neither old message: the keys are spent.
    let mut stolen = Party { state: bob.state.clone(), rng: Rng::new(b"thief") };
    assert_eq!(stolen.recv(&e1), Err(Error::Rejected));
    assert_eq!(stolen.recv(&e2), Err(Error::Rejected));
    // After a receive step Bob's own X25519 and ML-KEM secrets are wiped.
    let e3 = bob.send(b"three");
    alice.recv(&e3).unwrap();
    assert!(alice.state[off::OWN_X_SK..off::OWN_X_SK + 32].iter().all(|b| *b == 0));
    assert!(alice.state[off::OWN_KEM_SEED..off::OWN_KEM_SEED + 64].iter().all(|b| *b == 0));
    assert_eq!(alice.state[off::CKS..off::CKS + 32], [0u8; 32]);
}

#[test]
fn post_compromise_a_stolen_state_loses_track_after_one_round_trip() {
    let (mut alice, mut bob) = pair();
    bob.recv(&alice.send(b"a1")).unwrap();
    alice.recv(&bob.send(b"b1")).unwrap();
    // The attacker copies Alice's whole state, then Alice sends with fresh
    // randomness and Bob replies: the copy cannot follow the new root.
    let mut stolen = Party { state: alice.state.clone(), rng: Rng::new(b"thief") };
    let a2 = alice.send(b"a2");
    bob.recv(&a2).unwrap();
    let b2 = bob.send(b"b2");
    assert_eq!(alice.recv(&b2).unwrap(), b"b2");
    assert_eq!(stolen.recv(&b2), Err(Error::Rejected));
}

#[test]
fn out_of_order_delivery_within_and_across_chains_without_leftovers() {
    let (mut alice, mut bob) = pair();
    let a: Vec<Vec<u8>> = (0..5).map(|i| alice.send(format!("a{i}").as_bytes())).collect();
    for &i in &[4usize, 1, 3, 0, 2] {
        assert_eq!(bob.recv(&a[i]).unwrap(), format!("a{i}").as_bytes());
    }
    assert_eq!(pq::skipped_count(&bob.state), 0);
    // Across a ratchet: a5, a6 sent; Bob only gets a6 and replies; Alice's next
    // chain arrives before the late a5.
    let a5 = alice.send(b"a5");
    let a6 = alice.send(b"a6");
    assert_eq!(bob.recv(&a6).unwrap(), b"a6");
    assert_eq!(pq::skipped_count(&bob.state), 1);
    alice.recv(&bob.send(b"b0")).unwrap();
    let a7 = alice.send(b"a7");
    assert_eq!(bob.recv(&a7).unwrap(), b"a7");
    assert_eq!(bob.recv(&a5).unwrap(), b"a5");
    assert_eq!(pq::skipped_count(&bob.state), 0);
    // Every slot is wiped once used: the skipped table is all zeros again.
    let table = &bob.state[off::SKIPPED..];
    assert!(table.iter().all(|b| *b == 0));
    // A replay of any delivered message finds no key.
    for e in a.iter().chain([&a5, &a6, &a7]) {
        let before = bob.state.clone();
        assert_eq!(bob.recv(e), Err(Error::Rejected));
        assert_eq!(bob.state, before);
    }
}

#[test]
fn a_gap_wider_than_max_skip_is_refused_and_the_table_stays_bounded() {
    let (mut alice, mut bob) = pair();
    bob.recv(&alice.send(b"first")).unwrap();
    let mut last = Vec::new();
    for i in 0..(pq::MAX_SKIP + 2) {
        last = alice.send(format!("m{i}").as_bytes());
    }
    let before = bob.state.clone();
    assert_eq!(bob.recv(&last), Err(Error::TooLarge));
    assert_eq!(bob.state, before);
    // Repeated maximal gaps never hold more than SKIPPED_SLOTS keys.
    let (mut alice, mut bob) = pair();
    bob.recv(&alice.send(b"first")).unwrap();
    for _ in 0..3 {
        let mut env = Vec::new();
        for _ in 0..=pq::MAX_SKIP {
            env = alice.send(b"burst");
        }
        bob.recv(&env).unwrap();
        assert!(pq::skipped_count(&bob.state) <= pq::SKIPPED_SLOTS);
    }
    assert_eq!(pq::skipped_count(&bob.state), pq::SKIPPED_SLOTS);
}

#[test]
fn tampered_envelopes_and_bit_flips_are_rejected_without_state_change() {
    let (mut alice, mut bob) = pair();
    bob.recv(&alice.send(b"warm-up")).unwrap();
    let mut b = Party { state: bob.state.clone(), rng: Rng::new(b"unused") };
    let env = alice.send(b"the real message");
    let n = env.len();
    // One flipped bit in every region: magic, version, kind, ratchet key,
    // ML-KEM key, ML-KEM ciphertext, PN, N, length, ciphertext, GCM tag, HMAC tag.
    let spots = [0usize, 4, 5, 6, 37, 38, 1605, 1606, 3173, HEADER_LEN - 12, HEADER_LEN - 8, HEADER_LEN - 4, HEADER_LEN, HEADER_LEN + 5, n - 48, n - 33, n - 32, n - 1];
    for &at in &spots {
        for bit in [0u8, 7] {
            let mut t = env.clone();
            t[at] ^= 1 << bit;
            let before = b.state.clone();
            let r = b.recv(&t);
            assert!(matches!(r, Err(Error::Rejected) | Err(Error::Invalid) | Err(Error::TooLarge)), "byte {at} bit {bit}: {r:?}");
            assert_eq!(b.state, before, "state changed for byte {at}");
        }
    }
    // Truncated and extended envelopes.
    assert_eq!(b.recv(&env[..n - 1]), Err(Error::Invalid));
    let mut longer = env.clone();
    longer.push(0);
    assert_eq!(b.recv(&longer), Err(Error::Invalid));
    // The untouched envelope still opens afterwards.
    assert_eq!(b.recv(&env).unwrap(), b"the real message");
    // A tampered first message of a new chain (new ratchet header) is refused too
    // and leaves room for the genuine one.
    let reply = b.send(b"reply");
    let mut t = reply.clone();
    t[2000] ^= 0x10; // inside the ML-KEM ciphertext: implicit rejection, then MAC failure
    let before = alice.state.clone();
    assert_eq!(alice.recv(&t), Err(Error::Rejected));
    assert_eq!(alice.state, before);
    assert_eq!(alice.recv(&reply).unwrap(), b"reply");
}

#[test]
fn state_and_envelope_shape_checks() {
    let (mut alice, mut bob) = pair();
    let env = alice.send(b"x");
    let mut garbage = vec![0u8; STATE_LEN];
    let mut out = vec![0u8; 16];
    assert_eq!(pq::decrypt(&mut garbage, &env, &mut out), Err(Error::Invalid));
    let mut short = vec![0u8; STATE_LEN - 1];
    assert_eq!(pq::decrypt(&mut short, &env, &mut out), Err(Error::Invalid));
    let mut tiny = [0u8; 0];
    assert_eq!(pq::decrypt(&mut bob.state, &env, &mut tiny), Err(Error::Invalid));
    let r: [u8; ENCRYPT_RANDOM_LEN] = alice.rng.bytes();
    let mut small = vec![0u8; ENVELOPE_OVERHEAD];
    assert_eq!(pq::encrypt(&mut alice.state, &r, b"xy", &mut small), Err(Error::Invalid));
    let big = vec![0u8; pq::MAX_PLAINTEXT + 1];
    let mut out = vec![0u8; ENVELOPE_OVERHEAD + big.len()];
    assert_eq!(pq::encrypt(&mut alice.state, &r, &big, &mut out), Err(Error::Invalid));
}
