//! Stap 8: hybrid post-quantum double ratchet (ML-KEM-1024 + X25519) with
//! RVE2 envelopes, for end-to-end protected messages and status updates
//! between two identities.
//!
//! Primitives: ML-KEM-1024 (FIPS 203, RustCrypto `ml-kem`, decapsulation
//! with implicit rejection and constant-time compare), X25519 (RFC 7748,
//! `x25519-dalek`), HMAC-SHA256 / HKDF-SHA256 (RFC 2104 / 5869, this crate),
//! AES-256-GCM (SP 800-38D, RustCrypto `aes-gcm`, bitsliced software AES).
//!
//! Context. Both sides bind the same caller context (the two identities and
//! the conversation): ctx = SHA-256("ROUT-PQR-CTX-V1" || I2OSP(len, 4) || context).
//! RK_0 = HKDF-Extract(salt = "ROUT-PQR-ROOT0-V1", IKM = ctx). The context is
//! not a secret; secrecy comes from the KEM and DH shares. Authenticating the
//! responder's bundle (and with it the peer identity) is the caller's job.
//!
//! Handshake. The responder publishes an RVE2 bundle (its first X25519 and
//! ML-KEM-1024 public keys). The initiator's first message is the first
//! asymmetric ratchet step against that bundle, so handshake and ratchet are
//! one mechanism.
//!
//! Asymmetric (KEM + DH) ratchet step, by the side that starts a sending chain:
//!   fresh X25519 key x', fresh ML-KEM-1024 key (dk', ek') from a 64-byte seed,
//!   (ct, ss_kem) = ML-KEM.Encaps(ek_peer)          (32 bytes of fresh randomness)
//!   ss_x         = X25519(x', X_peer)               (all-zero result refused)
//!   PRK          = HKDF-Extract(salt = RK, IKM = ss_kem || ss_x)
//!   RK' || CK    = HKDF-Expand(PRK, "rout.v1.ratchet.root" || ctx || X(x') ||
//!                              X_peer || SHA-256(ct), 64)
//! The receiver recomputes ss_kem = ML-KEM.Decaps(dk_own, ct) and
//! ss_x = X25519(x_own, X(x')). Breaking the root update needs both ML-KEM
//! and X25519 broken; binding both public keys and the ciphertext follows
//! the X-Wing combiner. After a receive step the receiver erases its own
//! X25519 and ML-KEM secrets (they were used once) and starts a new sending
//! chain with fresh keys on its next message.
//!
//! Symmetric chain (per message), with volatile wipe of the old chain key:
//!   K_msg  = HMAC-SHA256(K_chain, "rout.v1.ratchet.msg")
//!   K_chain' = HMAC-SHA256(K_chain, "rout.v1.ratchet.chain")
//!   enc || mac || iv = HKDF-Expand(K_msg, "rout.v1.ratchet.keys", 32 + 32 + 12)
//! Every K_msg encrypts exactly one message, so the derived IV never repeats
//! under one key.
//!
//! RVE2 message envelope (big-endian lengths):
//!   "RVE2" | 0x01 | 0x01 | X25519 ratchet key (32) | ML-KEM-1024 key (1568) |
//!   ML-KEM-1024 ciphertext (1568) | PN (4) | N (4) | len (4) |
//!   AES-256-GCM ciphertext (len) | GCM tag (16) | HMAC-SHA256 tag (32)
//! GCM AAD = header || ctx; HMAC(mac, ctx || everything before the HMAC tag).
//! The receiver checks the HMAC tag (constant time) and then GCM; both keys
//! come from the same K_msg, the HMAC is defense in depth over the full
//! envelope. RVE2 bundle: "RVE2" | 0x01 | 0x02 | X25519 key | ML-KEM-1024 key.
//!
//! Out-of-order delivery. Up to MAX_SKIP message keys per gap are derived
//! ahead and kept in a fixed table of SKIPPED_SLOTS entries (oldest evicted
//! and wiped when full); a used entry is wiped at once, so a replay finds no
//! key and is rejected.
//!
//! Atomicity. Encrypt and decrypt work on a copy of the state and write it
//! back only on success: a forged, replayed or bit-flipped envelope leaves
//! the state byte-for-byte unchanged.
//!
//! Memory. Fixed-size state (STATE_LEN) and stack buffers only, no allocator.
//! Secrets created here are wiped with volatile writes before return; copies
//! made inside the dependencies are covered by the host zero-filling the
//! whole linear memory after every call.

use crate::pseudonym::hmac_sha256;
use crate::{wipe, Error, Result};
use aes_gcm::{aead::AeadInOut, Aes256Gcm, KeyInit};
use ml_kem::{kem::Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem1024};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const X_LEN: usize = 32;
pub const EK_LEN: usize = 1568;
pub const CT_LEN: usize = 1568;
pub const KEM_SEED_LEN: usize = 64;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAC_LEN: usize = 32;
pub const MAX_PLAINTEXT: usize = 16 * 1024;
pub const MAX_CONTEXT: usize = 512;
/// Largest gap (skipped messages) one envelope may open in one chain.
pub const MAX_SKIP: u32 = 64;
/// Skipped message keys kept at once.
pub const SKIPPED_SLOTS: usize = 64;

pub const MAGIC: &[u8; 4] = b"RVE2";
pub const VERSION: u8 = 1;
pub const KIND_MESSAGE: u8 = 1;
pub const KIND_BUNDLE: u8 = 2;
pub const BUNDLE_LEN: usize = 6 + X_LEN + EK_LEN;
pub const HEADER_LEN: usize = 6 + X_LEN + EK_LEN + CT_LEN + 12;
pub const ENVELOPE_OVERHEAD: usize = HEADER_LEN + TAG_LEN + MAC_LEN;
/// Randomness: responder = X25519 secret + ML-KEM seed; sending step = + encapsulation randomness.
pub const RESPONDER_RANDOM_LEN: usize = X_LEN + KEM_SEED_LEN;
pub const ENCRYPT_RANDOM_LEN: usize = X_LEN + KEM_SEED_LEN + 32;

pub const CTX_DST: &[u8] = b"ROUT-PQR-CTX-V1";
pub const ROOT0_SALT: &[u8] = b"ROUT-PQR-ROOT0-V1";
pub const ROOT_INFO: &[u8] = b"rout.v1.ratchet.root";
pub const MSG_INFO: &[u8] = b"rout.v1.ratchet.msg";
pub const CHAIN_INFO: &[u8] = b"rout.v1.ratchet.chain";
pub const KEYS_INFO: &[u8] = b"rout.v1.ratchet.keys";

/// Byte offsets of the fixed state layout (public so tests can inspect it).
pub mod off {
    pub const VERSION: usize = 0;
    pub const FLAGS: usize = 1;
    pub const NS: usize = 4;
    pub const NR: usize = 8;
    pub const PN: usize = 12;
    pub const AGE: usize = 16;
    pub const RK: usize = 32;
    pub const CKS: usize = 64;
    pub const CKR: usize = 96;
    pub const CTX: usize = 128;
    pub const OWN_X_SK: usize = 160;
    pub const OWN_X_PK: usize = 192;
    pub const OWN_KEM_SEED: usize = 224;
    pub const OWN_EK: usize = 288;
    pub const REMOTE_X: usize = OWN_EK + super::EK_LEN;
    pub const REMOTE_EK: usize = REMOTE_X + super::X_LEN;
    pub const SEND_CT: usize = REMOTE_EK + super::EK_LEN;
    pub const SKIPPED: usize = SEND_CT + super::CT_LEN;
}
/// Skipped-key slot: used (1) | pad (3) | N (4) | age (4) | ratchet key (32) | K_msg (32).
pub const SLOT_LEN: usize = 76;
pub const STATE_LEN: usize = off::SKIPPED + SKIPPED_SLOTS * SLOT_LEN;

pub mod flag {
    pub const HAS_REMOTE: u8 = 1;
    pub const HAS_OWN: u8 = 2;
    pub const NEED_SEND: u8 = 4;
    pub const HAS_SEND: u8 = 8;
    pub const HAS_RECV: u8 = 16;
    pub const ALL: u8 = 31;
}

fn rd32(s: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]])
}

fn wr32(s: &mut [u8], at: usize, v: u32) {
    s[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Volatile wipe, then write.
fn put(s: &mut [u8], at: usize, v: &[u8]) {
    wipe::bytes(&mut s[at..at + v.len()]);
    s[at..at + v.len()].copy_from_slice(v);
}

fn clear(s: &mut [u8], at: usize, len: usize) {
    wipe::bytes(&mut s[at..at + len]);
}

fn is_zero(b: &[u8]) -> bool {
    let mut acc = 0u8;
    for x in b {
        acc |= *x;
    }
    bool::from(acc.ct_eq(&0u8))
}

fn context_hash(context: &[u8]) -> Result<[u8; 32]> {
    if context.is_empty() || context.len() > MAX_CONTEXT {
        return Err(Error::Invalid);
    }
    let mut h = Sha256::new();
    h.update(CTX_DST);
    h.update((context.len() as u32).to_be_bytes());
    h.update(context);
    Ok(h.finalize().into())
}

fn check_state(state: &[u8]) -> Result<()> {
    if state.len() != STATE_LEN || state[off::VERSION] != VERSION || state[off::FLAGS] & !flag::ALL != 0 {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey<MlKem1024>> {
    let arr = bytes.try_into().map_err(|_| Error::Invalid)?;
    EncapsulationKey::<MlKem1024>::new(arr).map_err(|_| Error::Invalid)
}

/// RK' || CK from the hybrid shares (see module docs).
fn kdf_root(rk: &[u8], ss_kem: &[u8], ss_x: &[u8], ctx: &[u8], x_send: &[u8], x_recv: &[u8], ct: &[u8]) -> ([u8; 32], [u8; 32]) {
    let ct_hash: [u8; 32] = Sha256::digest(ct).into();
    let mut prk = hmac_sha256(rk, &[ss_kem, ss_x]);
    let t1 = hmac_sha256(&prk, &[ROOT_INFO, ctx, x_send, x_recv, &ct_hash, &[1u8]]);
    let t2 = hmac_sha256(&prk, &[&t1, ROOT_INFO, ctx, x_send, x_recv, &ct_hash, &[2u8]]);
    wipe::bytes(&mut prk);
    (t1, t2)
}

/// K_msg from the chain key; the chain key is replaced in place (old value volatile-wiped first).
fn chain_step(ck: &mut [u8]) -> [u8; 32] {
    let mk = hmac_sha256(ck, &[MSG_INFO]);
    let mut next = hmac_sha256(ck, &[CHAIN_INFO]);
    wipe::bytes(ck);
    ck.copy_from_slice(&next);
    wipe::bytes(&mut next);
    mk
}

struct MessageKeys {
    enc: [u8; KEY_LEN],
    mac: [u8; KEY_LEN],
    iv: [u8; IV_LEN],
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        wipe::bytes(&mut self.enc);
        wipe::bytes(&mut self.mac);
        wipe::bytes(&mut self.iv);
    }
}

/// HKDF-Expand(K_msg, KEYS_INFO, 76); K_msg is wiped.
fn message_keys(mk: &mut [u8; 32]) -> MessageKeys {
    let enc = hmac_sha256(mk, &[KEYS_INFO, &[1u8]]);
    let mac = hmac_sha256(mk, &[&enc, KEYS_INFO, &[2u8]]);
    let mut t3 = hmac_sha256(mk, &[&mac, KEYS_INFO, &[3u8]]);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&t3[..IV_LEN]);
    wipe::bytes(&mut t3);
    wipe::bytes(mk);
    MessageKeys { enc, mac, iv }
}

/// Installs a fresh own X25519 + ML-KEM-1024 key pair from caller randomness.
fn install_own(s: &mut [u8], x_sk: &[u8], kem_seed: &[u8]) -> Result<()> {
    if x_sk.len() != X_LEN || kem_seed.len() != KEM_SEED_LEN || is_zero(x_sk) || is_zero(kem_seed) {
        return Err(Error::Invalid);
    }
    let mut sk = [0u8; X_LEN];
    sk.copy_from_slice(x_sk);
    let pk = x25519(sk, X25519_BASEPOINT_BYTES);
    wipe::bytes(&mut sk);
    let mut seed = [0u8; KEM_SEED_LEN];
    seed.copy_from_slice(kem_seed);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed.into());
    wipe::bytes(&mut seed);
    let ek = dk.encapsulation_key().to_bytes();
    drop(dk);
    put(s, off::OWN_X_SK, x_sk);
    put(s, off::OWN_X_PK, &pk);
    put(s, off::OWN_KEM_SEED, kem_seed);
    put(s, off::OWN_EK, &ek);
    Ok(())
}

fn clear_own(s: &mut [u8]) {
    clear(s, off::OWN_X_SK, X_LEN);
    clear(s, off::OWN_X_PK, X_LEN);
    clear(s, off::OWN_KEM_SEED, KEM_SEED_LEN);
    clear(s, off::OWN_EK, EK_LEN);
}

fn fresh_state(s: &mut [u8], context: &[u8]) -> Result<()> {
    let ctx = context_hash(context)?;
    wipe::bytes(s);
    s[off::VERSION] = VERSION;
    put(s, off::CTX, &ctx);
    let rk0 = hmac_sha256(ROOT0_SALT, &[&ctx]);
    put(s, off::RK, &rk0);
    Ok(())
}

/// Responder: a fresh state holding its first own key pair, and the RVE2 bundle to publish.
pub fn responder_init(random: &[u8], context: &[u8], state: &mut [u8], bundle: &mut [u8]) -> Result<()> {
    if random.len() != RESPONDER_RANDOM_LEN || state.len() != STATE_LEN || bundle.len() != BUNDLE_LEN {
        return Err(Error::Invalid);
    }
    let r = (|| {
        fresh_state(state, context)?;
        install_own(state, &random[..X_LEN], &random[X_LEN..])?;
        state[off::FLAGS] = flag::HAS_OWN;
        bundle[..4].copy_from_slice(MAGIC);
        bundle[4] = VERSION;
        bundle[5] = KIND_BUNDLE;
        bundle[6..6 + X_LEN].copy_from_slice(&state[off::OWN_X_PK..off::OWN_X_PK + X_LEN]);
        bundle[6 + X_LEN..].copy_from_slice(&state[off::OWN_EK..off::OWN_EK + EK_LEN]);
        Ok(())
    })();
    if r.is_err() {
        wipe::bytes(state);
    }
    r
}

/// Initiator: a fresh state aimed at the responder's (caller-authenticated) bundle.
pub fn initiator_init(context: &[u8], bundle: &[u8], state: &mut [u8]) -> Result<()> {
    if bundle.len() != BUNDLE_LEN || state.len() != STATE_LEN || &bundle[..4] != MAGIC || bundle[4] != VERSION || bundle[5] != KIND_BUNDLE {
        return Err(Error::Invalid);
    }
    let x = &bundle[6..6 + X_LEN];
    let ek = &bundle[6 + X_LEN..];
    if is_zero(x) {
        return Err(Error::Invalid);
    }
    encapsulation_key(ek)?;
    fresh_state(state, context)?;
    put(state, off::REMOTE_X, x);
    put(state, off::REMOTE_EK, ek);
    state[off::FLAGS] = flag::HAS_REMOTE | flag::NEED_SEND;
    Ok(())
}

/// Starts a new sending chain: fresh own keys, encapsulation to the peer.
fn send_ratchet(s: &mut [u8], random: &[u8]) -> Result<()> {
    let m = &random[X_LEN + KEM_SEED_LEN..];
    if is_zero(m) {
        return Err(Error::Invalid);
    }
    let ek = encapsulation_key(&s[off::REMOTE_EK..off::REMOTE_EK + EK_LEN])?;
    let mut mm = [0u8; 32];
    mm.copy_from_slice(m);
    let (ct, mut ss_kem) = ek.encapsulate_deterministic(&mm.into());
    wipe::bytes(&mut mm);
    let r = (|| {
        install_own(s, &random[..X_LEN], &random[X_LEN..X_LEN + KEM_SEED_LEN])?;
        let mut sk = [0u8; X_LEN];
        sk.copy_from_slice(&s[off::OWN_X_SK..off::OWN_X_SK + X_LEN]);
        let mut remote = [0u8; X_LEN];
        remote.copy_from_slice(&s[off::REMOTE_X..off::REMOTE_X + X_LEN]);
        let mut ss_x = x25519(sk, remote);
        wipe::bytes(&mut sk);
        if is_zero(&ss_x) {
            return Err(Error::Rejected);
        }
        let mut own_pk = [0u8; X_LEN];
        own_pk.copy_from_slice(&s[off::OWN_X_PK..off::OWN_X_PK + X_LEN]);
        let mut ctx = [0u8; 32];
        ctx.copy_from_slice(&s[off::CTX..off::CTX + 32]);
        let (mut rk, mut ck) = kdf_root(&s[off::RK..off::RK + 32], ss_kem.as_slice(), &ss_x, &ctx, &own_pk, &remote, ct.as_slice());
        wipe::bytes(&mut ss_x);
        put(s, off::RK, &rk);
        put(s, off::CKS, &ck);
        wipe::bytes(&mut rk);
        wipe::bytes(&mut ck);
        put(s, off::SEND_CT, ct.as_slice());
        let ns = rd32(s, off::NS);
        wr32(s, off::PN, ns);
        wr32(s, off::NS, 0);
        s[off::FLAGS] = (s[off::FLAGS] | flag::HAS_SEND | flag::HAS_OWN) & !flag::NEED_SEND;
        Ok(())
    })();
    wipe::bytes(ss_kem.as_mut_slice());
    r
}

/// Encrypts one message into `out` (RVE2); returns the envelope length. The
/// state is replaced only on success. `random` (ENCRYPT_RANDOM_LEN) is used
/// when this message starts a new sending chain.
pub fn encrypt(state: &mut [u8], random: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
    check_state(state)?;
    if random.len() != ENCRYPT_RANDOM_LEN || plaintext.len() > MAX_PLAINTEXT || out.len() < ENVELOPE_OVERHEAD + plaintext.len() {
        return Err(Error::Invalid);
    }
    let mut work = [0u8; STATE_LEN];
    work.copy_from_slice(state);
    let r = encrypt_work(&mut work, random, plaintext, out);
    if r.is_ok() {
        state.copy_from_slice(&work);
    } else {
        wipe::bytes(out);
    }
    wipe::bytes(&mut work);
    r
}

fn encrypt_work(s: &mut [u8], random: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
    let f = s[off::FLAGS];
    if f & flag::HAS_REMOTE == 0 {
        return Err(Error::Invalid);
    }
    if f & flag::NEED_SEND != 0 {
        send_ratchet(s, random)?;
    } else if f & flag::HAS_SEND == 0 {
        return Err(Error::Invalid);
    }
    let ns = rd32(s, off::NS);
    if ns == u32::MAX {
        return Err(Error::TooLarge);
    }
    let mut mk = chain_step(&mut s[off::CKS..off::CKS + 32]);
    let keys = message_keys(&mut mk);
    let n = plaintext.len();
    out[..4].copy_from_slice(MAGIC);
    out[4] = VERSION;
    out[5] = KIND_MESSAGE;
    out[6..6 + X_LEN].copy_from_slice(&s[off::OWN_X_PK..off::OWN_X_PK + X_LEN]);
    out[6 + X_LEN..6 + X_LEN + EK_LEN].copy_from_slice(&s[off::OWN_EK..off::OWN_EK + EK_LEN]);
    out[6 + X_LEN + EK_LEN..6 + X_LEN + EK_LEN + CT_LEN].copy_from_slice(&s[off::SEND_CT..off::SEND_CT + CT_LEN]);
    let t = HEADER_LEN - 12;
    out[t..t + 4].copy_from_slice(&rd32(s, off::PN).to_be_bytes());
    out[t + 4..t + 8].copy_from_slice(&ns.to_be_bytes());
    out[t + 8..t + 12].copy_from_slice(&(n as u32).to_be_bytes());
    let mut aad = [0u8; HEADER_LEN + 32];
    aad[..HEADER_LEN].copy_from_slice(&out[..HEADER_LEN]);
    aad[HEADER_LEN..].copy_from_slice(&s[off::CTX..off::CTX + 32]);
    out[HEADER_LEN..HEADER_LEN + n].copy_from_slice(plaintext);
    let cipher = Aes256Gcm::new_from_slice(&keys.enc).map_err(|_| Error::Invalid)?;
    let tag = cipher
        .encrypt_inout_detached(&keys.iv.into(), &aad, (&mut out[HEADER_LEN..HEADER_LEN + n]).into())
        .map_err(|_| Error::Invalid)?;
    out[HEADER_LEN + n..HEADER_LEN + n + TAG_LEN].copy_from_slice(tag.as_slice());
    let mac_at = HEADER_LEN + n + TAG_LEN;
    let mac = hmac_sha256(&keys.mac, &[&s[off::CTX..off::CTX + 32], &out[..mac_at]]);
    out[mac_at..mac_at + MAC_LEN].copy_from_slice(&mac);
    wr32(s, off::NS, ns + 1);
    Ok(mac_at + MAC_LEN)
}

/// Opens one RVE2 envelope into `out`; returns the plaintext length. The
/// state is replaced only on success; any forged, replayed or altered
/// envelope is `Rejected` (or `Invalid` / `TooLarge` when malformed or the
/// gap is too wide) and leaves the state unchanged.
pub fn decrypt(state: &mut [u8], envelope: &[u8], out: &mut [u8]) -> Result<usize> {
    check_state(state)?;
    if envelope.len() < ENVELOPE_OVERHEAD || &envelope[..4] != MAGIC || envelope[4] != VERSION || envelope[5] != KIND_MESSAGE {
        return Err(Error::Invalid);
    }
    let n = be32(envelope, HEADER_LEN - 4) as usize;
    if n > MAX_PLAINTEXT || envelope.len() != ENVELOPE_OVERHEAD + n || out.len() < n {
        return Err(Error::Invalid);
    }
    let mut work = [0u8; STATE_LEN];
    work.copy_from_slice(state);
    let r = decrypt_work(&mut work, envelope, n, out);
    if r.is_ok() {
        state.copy_from_slice(&work);
    } else {
        wipe::bytes(&mut out[..n]);
    }
    wipe::bytes(&mut work);
    r
}

fn decrypt_work(s: &mut [u8], env: &[u8], n: usize, out: &mut [u8]) -> Result<usize> {
    let hx = &env[6..6 + X_LEN];
    let hek = &env[6 + X_LEN..6 + X_LEN + EK_LEN];
    let hct = &env[6 + X_LEN + EK_LEN..6 + X_LEN + EK_LEN + CT_LEN];
    let pn = be32(env, HEADER_LEN - 12);
    let msg_n = be32(env, HEADER_LEN - 8);
    if let Some(slot) = find_skipped(s, hx, msg_n) {
        let at = off::SKIPPED + slot * SLOT_LEN;
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&s[at + 44..at + 76]);
        clear(s, at, SLOT_LEN);
        return open(s, &mut mk, env, n, out);
    }
    let f = s[off::FLAGS];
    if f & flag::HAS_RECV == 0 || !bool::from(hx.ct_eq(&s[off::REMOTE_X..off::REMOTE_X + X_LEN])) {
        if f & flag::HAS_OWN == 0 {
            return Err(Error::Rejected);
        }
        if f & flag::HAS_RECV != 0 {
            skip_until(s, pn)?;
        }
        recv_ratchet(s, hx, hek, hct)?;
    }
    let nr = rd32(s, off::NR);
    if msg_n < nr {
        return Err(Error::Rejected);
    }
    if msg_n == u32::MAX {
        return Err(Error::TooLarge);
    }
    skip_until(s, msg_n)?;
    let mut mk = chain_step(&mut s[off::CKR..off::CKR + 32]);
    wr32(s, off::NR, msg_n + 1);
    open(s, &mut mk, env, n, out)
}

/// Derives and stores the keys of the current receiving chain up to (excluding) `until`.
fn skip_until(s: &mut [u8], until: u32) -> Result<()> {
    let nr = rd32(s, off::NR);
    if until < nr {
        return Err(Error::Rejected);
    }
    if until - nr > MAX_SKIP {
        return Err(Error::TooLarge);
    }
    let mut x = [0u8; X_LEN];
    x.copy_from_slice(&s[off::REMOTE_X..off::REMOTE_X + X_LEN]);
    for i in nr..until {
        let mut mk = chain_step(&mut s[off::CKR..off::CKR + 32]);
        store_skipped(s, &x, i, &mk);
        wipe::bytes(&mut mk);
    }
    wr32(s, off::NR, until);
    Ok(())
}

fn recv_ratchet(s: &mut [u8], hx: &[u8], hek: &[u8], hct: &[u8]) -> Result<()> {
    encapsulation_key(hek).map_err(|_| Error::Rejected)?;
    let mut seed = [0u8; KEM_SEED_LEN];
    seed.copy_from_slice(&s[off::OWN_KEM_SEED..off::OWN_KEM_SEED + KEM_SEED_LEN]);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed.into());
    wipe::bytes(&mut seed);
    let ct = hct.try_into().map_err(|_| Error::Invalid)?;
    let mut ss_kem = dk.decapsulate(ct);
    drop(dk);
    let mut sk = [0u8; X_LEN];
    sk.copy_from_slice(&s[off::OWN_X_SK..off::OWN_X_SK + X_LEN]);
    let mut peer = [0u8; X_LEN];
    peer.copy_from_slice(hx);
    let mut ss_x = x25519(sk, peer);
    wipe::bytes(&mut sk);
    let r = (|| {
        if is_zero(&ss_x) {
            return Err(Error::Rejected);
        }
        let mut own_pk = [0u8; X_LEN];
        own_pk.copy_from_slice(&s[off::OWN_X_PK..off::OWN_X_PK + X_LEN]);
        let mut ctx = [0u8; 32];
        ctx.copy_from_slice(&s[off::CTX..off::CTX + 32]);
        let (mut rk, mut ck) = kdf_root(&s[off::RK..off::RK + 32], ss_kem.as_slice(), &ss_x, &ctx, hx, &own_pk, hct);
        put(s, off::RK, &rk);
        put(s, off::CKR, &ck);
        wipe::bytes(&mut rk);
        wipe::bytes(&mut ck);
        put(s, off::REMOTE_X, hx);
        put(s, off::REMOTE_EK, hek);
        wr32(s, off::NR, 0);
        // Own secrets were used once; the next message starts a new sending chain.
        clear_own(s);
        clear(s, off::CKS, 32);
        clear(s, off::SEND_CT, CT_LEN);
        s[off::FLAGS] = (s[off::FLAGS] | flag::HAS_RECV | flag::HAS_REMOTE | flag::NEED_SEND) & !(flag::HAS_OWN | flag::HAS_SEND);
        Ok(())
    })();
    wipe::bytes(&mut ss_x);
    wipe::bytes(ss_kem.as_mut_slice());
    r
}

fn open(s: &[u8], mk: &mut [u8; 32], env: &[u8], n: usize, out: &mut [u8]) -> Result<usize> {
    let keys = message_keys(mk);
    let mac_at = HEADER_LEN + n + TAG_LEN;
    let mut expect = hmac_sha256(&keys.mac, &[&s[off::CTX..off::CTX + 32], &env[..mac_at]]);
    let ok = bool::from(expect.ct_eq(&env[mac_at..mac_at + MAC_LEN]));
    wipe::bytes(&mut expect);
    if !ok {
        return Err(Error::Rejected);
    }
    let mut aad = [0u8; HEADER_LEN + 32];
    aad[..HEADER_LEN].copy_from_slice(&env[..HEADER_LEN]);
    aad[HEADER_LEN..].copy_from_slice(&s[off::CTX..off::CTX + 32]);
    out[..n].copy_from_slice(&env[HEADER_LEN..HEADER_LEN + n]);
    let cipher = Aes256Gcm::new_from_slice(&keys.enc).map_err(|_| Error::Invalid)?;
    let tag = env[HEADER_LEN + n..mac_at].try_into().map_err(|_| Error::Invalid)?;
    cipher
        .decrypt_inout_detached(&keys.iv.into(), &aad, (&mut out[..n]).into(), tag)
        .map_err(|_| Error::Rejected)?;
    Ok(n)
}

fn find_skipped(s: &[u8], x: &[u8], n: u32) -> Option<usize> {
    let mut found = None;
    for i in 0..SKIPPED_SLOTS {
        let at = off::SKIPPED + i * SLOT_LEN;
        if s[at] == 1 && rd32(s, at + 4) == n && bool::from(s[at + 12..at + 44].ct_eq(x)) {
            found = Some(i);
        }
    }
    found
}

fn store_skipped(s: &mut [u8], x: &[u8], n: u32, mk: &[u8; 32]) {
    let mut slot = None;
    let mut oldest = (u32::MAX, 0usize);
    for i in 0..SKIPPED_SLOTS {
        let at = off::SKIPPED + i * SLOT_LEN;
        if s[at] == 0 {
            if slot.is_none() {
                slot = Some(i);
            }
        } else {
            let age = rd32(s, at + 8);
            if age < oldest.0 {
                oldest = (age, i);
            }
        }
    }
    let i = slot.unwrap_or(oldest.1);
    let at = off::SKIPPED + i * SLOT_LEN;
    clear(s, at, SLOT_LEN);
    let age = rd32(s, off::AGE);
    wr32(s, off::AGE, age.wrapping_add(1));
    s[at] = 1;
    wr32(s, at + 4, n);
    wr32(s, at + 8, age);
    s[at + 12..at + 44].copy_from_slice(x);
    s[at + 44..at + 76].copy_from_slice(mk);
}

/// Skipped message keys currently held.
pub fn skipped_count(state: &[u8]) -> usize {
    (0..SKIPPED_SLOTS).filter(|i| state[off::SKIPPED + i * SLOT_LEN] == 1).count()
}
