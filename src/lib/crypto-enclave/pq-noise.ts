/**
 * Stap 10: hybrid post-quantum Noise tunnel, IKpsk2 with every Diffie-Hellman paired with ML-KEM-1024.
 *
 * Protocol name: ROUT_PQNoise_IKpsk2_25519+MLKEM1024_AESGCM_SHA256 (not a registered Noise name: the KEM
 * tokens follow the HFS extension (e1/ekem1) and PQNoise's static-KEM tokens (skem), combined so that
 * each X25519 step has an ML-KEM counterpart, as in RVE2's hybrid combiner).
 *
 *   <- s, skem                                   (responder's static X25519 and ML-KEM-1024 keys, known)
 *   -> e, e1, es, skem(rs), s, ss, skem_i        (e1: ephemeral ML-KEM key; skem(rs): encaps to responder)
 *   <- e, ee, se, ekem1, skem(is), psk           (encaps to e1 and to the initiator's static ML-KEM key)
 *
 * Security goals: confidentiality and mutual authentication hold if X25519 OR ML-KEM-1024 holds
 * (the chaining key absorbs both secrets of every pair); the pre-shared key binds the tunnel to a
 * prior enrolment ("mTLS"-like: both sides prove a static key, neither trusts a CA). Transport uses
 * AES-256-GCM with a strictly increasing 64-bit counter; a replayed, reordered or altered record is
 * rejected and the receiving channel is then closed. This is a design reviewed in code and tests, not
 * a formally verified protocol (no Tamarin/ProVerif model yet).
 *
 * Every secret this module owns (ephemeral keys, shared secrets, chaining key, cipher keys) is
 * zero-filled once used; callers own and wipe their static secret keys and the psk.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { wipe } from "@/lib/crypto/wipe";

export const PQ_NOISE_PROTOCOL = "ROUT_PQNoise_IKpsk2_25519+MLKEM1024_AESGCM_SHA256";
export const X25519_LEN = 32;
export const KEM_PK_LEN = 1568;
export const KEM_SK_LEN = 3168;
export const KEM_CT_LEN = 1568;
export const PSK_LEN = 32;
const TAG = 16;
const MAX_NONCE = 2n ** 64n - 2n; // 2^64 - 1 is reserved, as in Noise.
export const MAX_RECORD = 65_535 - TAG;

export class PqNoiseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PqNoiseError";
  }
}

export interface StaticKeys {
  dhSecret: Uint8Array;
  dhPublic: Uint8Array;
  kemSecret: Uint8Array;
  kemPublic: Uint8Array;
}

export interface PeerStatic {
  dhPublic: Uint8Array;
  kemPublic: Uint8Array;
}

type Random = (n: number) => Uint8Array;

export function generateStaticKeys(random: Random = randomBytes): StaticKeys {
  const dhSecret = random(32);
  const seed = random(64);
  try {
    const kem = ml_kem1024.keygen(seed);
    return { dhSecret, dhPublic: x25519.getPublicKey(dhSecret), kemSecret: kem.secretKey, kemPublic: kem.publicKey };
  } finally {
    wipe(seed);
  }
}

export function wipeStaticKeys(k: StaticKeys): void {
  wipe(k.dhSecret, k.kemSecret);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function nonce12(n: bigint): Uint8Array {
  const out = new Uint8Array(12);
  new DataView(out.buffer).setBigUint64(4, n, false);
  return out;
}

/** HKDF as in Noise section 4.3 (HMAC-SHA-256), returning 2 or 3 outputs. */
function hkdf(ck: Uint8Array, ikm: Uint8Array, n: 2 | 3): Uint8Array[] {
  const temp = hmac(sha256, ck, ikm);
  const o1 = hmac(sha256, temp, Uint8Array.of(1));
  const o2 = hmac(sha256, temp, concat(o1, Uint8Array.of(2)));
  const out = [o1, o2];
  if (n === 3) out.push(hmac(sha256, temp, concat(o2, Uint8Array.of(3))));
  wipe(temp);
  return out;
}

class CipherState {
  private k: Uint8Array | null = null;
  private n = 0n;
  private closed = false;

  constructor(k?: Uint8Array) {
    if (k) this.k = k;
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  setKey(k: Uint8Array): void {
    if (this.k) wipe(this.k);
    this.k = k;
    this.n = 0n;
  }

  get counter(): bigint {
    return this.n;
  }

  encrypt(ad: Uint8Array, pt: Uint8Array): Uint8Array {
    if (this.closed) throw new PqNoiseError("channel closed");
    if (!this.k) return pt.slice();
    if (this.n > MAX_NONCE) throw new PqNoiseError("nonce exhausted");
    const ct = gcm(this.k, nonce12(this.n), ad).encrypt(pt);
    this.n += 1n;
    return ct;
  }

  decrypt(ad: Uint8Array, ct: Uint8Array): Uint8Array {
    if (this.closed) throw new PqNoiseError("channel closed");
    if (!this.k) return ct.slice();
    if (this.n > MAX_NONCE) throw new PqNoiseError("nonce exhausted");
    try {
      const pt = gcm(this.k, nonce12(this.n), ad).decrypt(ct);
      this.n += 1n;
      return pt;
    } catch {
      // One failed record ends the channel: no oracle for later guesses.
      this.close();
      throw new PqNoiseError("record rejected");
    }
  }

  close(): void {
    this.closed = true;
    if (this.k) wipe(this.k);
    this.k = null;
  }
}

class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  cs = new CipherState();

  constructor() {
    const name = new TextEncoder().encode(PQ_NOISE_PROTOCOL);
    this.h = name.length <= 32 ? concat(name, new Uint8Array(32 - name.length)) : sha256(name);
    this.ck = this.h.slice();
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256(concat(this.h, data));
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, k] = hkdf(this.ck, ikm, 2);
    wipe(this.ck);
    this.ck = ck;
    this.cs.setKey(k);
  }

  mixKeyAndHash(ikm: Uint8Array): void {
    const [ck, th, k] = hkdf(this.ck, ikm, 3);
    wipe(this.ck);
    this.ck = ck;
    this.mixHash(th);
    wipe(th);
    this.cs.setKey(k);
  }

  encryptAndHash(pt: Uint8Array): Uint8Array {
    const ct = this.cs.encrypt(this.h, pt);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ct: Uint8Array): Uint8Array {
    const pt = this.cs.decrypt(this.h, ct);
    this.mixHash(ct);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0), 2);
    this.destroy();
    return [new CipherState(k1), new CipherState(k2)];
  }

  destroy(): void {
    wipe(this.ck);
    this.cs.close();
  }
}

function dh(secret: Uint8Array, pub: Uint8Array): Uint8Array {
  const out = x25519.getSharedSecret(secret, pub);
  // An all-zero result means a low-order point: refuse (contributory behaviour).
  if (out.every((b) => b === 0)) {
    wipe(out);
    throw new PqNoiseError("invalid public key");
  }
  return out;
}

function mixSecret(ss: SymmetricState, secret: Uint8Array): void {
  try {
    ss.mixKey(secret);
  } finally {
    wipe(secret);
  }
}

function checkLen(b: Uint8Array, n: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length !== n) throw new PqNoiseError(`bad ${what}`);
}

/** An established tunnel: one sending and one receiving cipher. */
export class PqNoiseTransport {
  constructor(
    private readonly tx: CipherState,
    private readonly rx: CipherState,
    /** Handshake hash: a channel binding both sides can compare or sign. */
    readonly handshakeHash: Uint8Array,
  ) {}

  /** Seals one record (AD binds the direction-independent record counter). */
  send(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length > MAX_RECORD) throw new PqNoiseError("record too large");
    return this.tx.encrypt(new Uint8Array(0), plaintext);
  }

  /** Opens the next record; a replayed, reordered or altered record closes this direction. */
  receive(record: Uint8Array): Uint8Array {
    if (record.length < TAG || record.length > MAX_RECORD + TAG) {
      this.rx.close();
      throw new PqNoiseError("record rejected");
    }
    return this.rx.decrypt(new Uint8Array(0), record);
  }

  get sent(): bigint {
    return this.tx.counter;
  }

  get received(): bigint {
    return this.rx.counter;
  }

  close(): void {
    this.tx.close();
    this.rx.close();
    wipe(this.handshakeHash);
  }
}

function startState(prologue: Uint8Array, responder: PeerStatic): SymmetricState {
  checkLen(responder.dhPublic, X25519_LEN, "responder key");
  checkLen(responder.kemPublic, KEM_PK_LEN, "responder KEM key");
  const ss = new SymmetricState();
  ss.mixHash(prologue);
  ss.mixHash(responder.dhPublic);
  ss.mixHash(responder.kemPublic);
  return ss;
}

/** Initiator side. Call writeMessage1, send it, then readMessage2 with the reply. */
export class PqNoiseInitiator {
  private ss: SymmetricState | null;
  private e: Uint8Array | null = null;
  private e1: Uint8Array | null = null;

  constructor(
    private readonly s: StaticKeys,
    private readonly rs: PeerStatic,
    private readonly psk: Uint8Array,
    prologue: Uint8Array = new Uint8Array(0),
    private readonly random: Random = randomBytes,
  ) {
    checkLen(psk, PSK_LEN, "psk");
    this.ss = startState(prologue, rs);
  }

  writeMessage1(payload: Uint8Array = new Uint8Array(0)): Uint8Array {
    const ss = this.need();
    if (this.e) throw new PqNoiseError("message 1 already written");
    this.e = this.random(32);
    const ePub = x25519.getPublicKey(this.e);
    ss.mixHash(ePub);
    ss.mixKey(ePub); // psk handshakes also mix e into the key
    const seed = this.random(64);
    let e1Pub: Uint8Array;
    try {
      const kem = ml_kem1024.keygen(seed);
      this.e1 = kem.secretKey;
      e1Pub = kem.publicKey;
    } finally {
      wipe(seed);
    }
    const e1Ct = ss.encryptAndHash(e1Pub);
    mixSecret(ss, dh(this.e, this.rs.dhPublic)); // es
    const m = this.random(32);
    const enc = ml_kem1024.encapsulate(this.rs.kemPublic, m);
    wipe(m);
    const skemCt = ss.encryptAndHash(enc.cipherText);
    mixSecret(ss, enc.sharedSecret); // skem(rs)
    const sCt = ss.encryptAndHash(this.s.dhPublic);
    mixSecret(ss, dh(this.s.dhSecret, this.rs.dhPublic)); // ss
    const skemICt = ss.encryptAndHash(this.s.kemPublic);
    const body = ss.encryptAndHash(payload);
    return concat(ePub, e1Ct, skemCt, sCt, skemICt, body);
  }

  readMessage2(msg: Uint8Array): { transport: PqNoiseTransport; payload: Uint8Array } {
    const ss = this.need();
    if (!this.e || !this.e1) throw new PqNoiseError("message 1 not written");
    const min = X25519_LEN + 2 * (KEM_CT_LEN + TAG) + TAG;
    try {
      if (msg.length < min) throw new PqNoiseError("message 2 too short");
      let o = 0;
      const take = (n: number) => msg.subarray(o, (o += n));
      const re = take(X25519_LEN);
      ss.mixHash(re);
      ss.mixKey(re);
      mixSecret(ss, dh(this.e, re)); // ee
      mixSecret(ss, dh(this.s.dhSecret, re)); // se
      const ct2 = ss.decryptAndHash(take(KEM_CT_LEN + TAG));
      mixSecret(ss, ml_kem1024.decapsulate(ct2, this.e1)); // ekem1
      const ct3 = ss.decryptAndHash(take(KEM_CT_LEN + TAG));
      mixSecret(ss, ml_kem1024.decapsulate(ct3, this.s.kemSecret)); // skem(is)
      ss.mixKeyAndHash(this.psk); // psk2
      const payload = ss.decryptAndHash(msg.subarray(o));
      const h = ss.h.slice();
      const [c1, c2] = ss.split();
      this.ss = null;
      return { transport: new PqNoiseTransport(c1, c2, h), payload };
    } catch (err) {
      this.abort();
      throw err instanceof PqNoiseError ? err : new PqNoiseError("handshake rejected");
    } finally {
      wipe(this.e, this.e1);
      this.e = this.e1 = null;
    }
  }

  abort(): void {
    this.ss?.destroy();
    this.ss = null;
    wipe(this.e, this.e1);
    this.e = this.e1 = null;
  }

  private need(): SymmetricState {
    if (!this.ss) throw new PqNoiseError("handshake finished");
    return this.ss;
  }
}

/** Responder side: readMessage1 (learns and checks the initiator), then writeMessage2. */
export class PqNoiseResponder {
  private ss: SymmetricState | null;
  private re: Uint8Array | null = null;
  private re1: Uint8Array | null = null;
  private rs: PeerStatic | null = null;

  constructor(
    private readonly s: StaticKeys,
    /** Decides whether an initiator's static keys are enrolled; must return that peer's psk or null. */
    private readonly pskFor: (peer: PeerStatic) => Uint8Array | null,
    prologue: Uint8Array = new Uint8Array(0),
    private readonly random: Random = randomBytes,
  ) {
    this.ss = startState(prologue, { dhPublic: s.dhPublic, kemPublic: s.kemPublic });
  }

  readMessage1(msg: Uint8Array): { initiator: PeerStatic; payload: Uint8Array } {
    const ss = this.need();
    const min = X25519_LEN + (KEM_PK_LEN + TAG) + (KEM_CT_LEN + TAG) + (X25519_LEN + TAG) + (KEM_PK_LEN + TAG) + TAG;
    try {
      if (msg.length < min) throw new PqNoiseError("message 1 too short");
      let o = 0;
      const take = (n: number) => msg.subarray(o, (o += n));
      const re = take(X25519_LEN).slice();
      ss.mixHash(re);
      ss.mixKey(re);
      this.re = re;
      this.re1 = ss.decryptAndHash(take(KEM_PK_LEN + TAG));
      mixSecret(ss, dh(this.s.dhSecret, re)); // es
      const ct1 = ss.decryptAndHash(take(KEM_CT_LEN + TAG));
      mixSecret(ss, ml_kem1024.decapsulate(ct1, this.s.kemSecret)); // skem(rs)
      const is = ss.decryptAndHash(take(X25519_LEN + TAG));
      mixSecret(ss, dh(this.s.dhSecret, is)); // ss
      const iskem = ss.decryptAndHash(take(KEM_PK_LEN + TAG));
      const payload = ss.decryptAndHash(msg.subarray(o));
      this.rs = { dhPublic: is, kemPublic: iskem };
      return { initiator: this.rs, payload };
    } catch (err) {
      this.abort();
      throw err instanceof PqNoiseError ? err : new PqNoiseError("handshake rejected");
    }
  }

  writeMessage2(payload: Uint8Array = new Uint8Array(0)): { message: Uint8Array; transport: PqNoiseTransport } {
    const ss = this.need();
    if (!this.re || !this.re1 || !this.rs) throw new PqNoiseError("message 1 not read");
    const psk = this.pskFor(this.rs);
    const e = this.random(32);
    try {
      if (!psk || psk.length !== PSK_LEN) throw new PqNoiseError("initiator not enrolled");
      const ePub = x25519.getPublicKey(e);
      ss.mixHash(ePub);
      ss.mixKey(ePub);
      mixSecret(ss, dh(e, this.re)); // ee
      mixSecret(ss, dh(e, this.rs.dhPublic)); // se
      const m2 = this.random(32);
      const enc2 = ml_kem1024.encapsulate(this.re1, m2);
      wipe(m2);
      const c2 = ss.encryptAndHash(enc2.cipherText);
      mixSecret(ss, enc2.sharedSecret); // ekem1
      const m3 = this.random(32);
      const enc3 = ml_kem1024.encapsulate(this.rs.kemPublic, m3);
      wipe(m3);
      const c3 = ss.encryptAndHash(enc3.cipherText);
      mixSecret(ss, enc3.sharedSecret); // skem(is)
      ss.mixKeyAndHash(psk);
      const body = ss.encryptAndHash(payload);
      const h = ss.h.slice();
      const [c1, cB] = ss.split();
      this.ss = null;
      // Responder sends with the second key and receives with the first.
      return { message: concat(ePub, c2, c3, body), transport: new PqNoiseTransport(cB, c1, h) };
    } catch (err) {
      this.abort();
      throw err instanceof PqNoiseError ? err : new PqNoiseError("handshake rejected");
    } finally {
      wipe(e, this.re, this.re1);
      this.re = this.re1 = null;
    }
  }

  abort(): void {
    this.ss?.destroy();
    this.ss = null;
    wipe(this.re, this.re1);
    this.re = this.re1 = null;
  }

  private need(): SymmetricState {
    if (!this.ss) throw new PqNoiseError("handshake finished");
    return this.ss;
  }
}

export const __test = { equal };
