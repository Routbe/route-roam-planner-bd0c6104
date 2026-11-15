/**
 * Stap 8: hybrid post-quantum double ratchet (ML-KEM-1024 + X25519) with
 * RVE2 envelopes, for end-to-end protected messages and status updates
 * between two identities. Thin, typed adapters over wasm/rout-zk
 * (pq_ratchet.rs): key exchange, every ratchet step, HKDF/HMAC and
 * AES-256-GCM run in the pinned engine. Reachable only through the crypto
 * worker ops "pq_ratchet.init_session", "pq_ratchet.ratchet_encrypt",
 * "pq_ratchet.ratchet_decrypt" and "pq_ratchet.close_session".
 *
 *   responder  init_session(role "responder") -> RVE2 bundle (its first
 *              X25519 + ML-KEM-1024 public keys) to hand to the initiator
 *   initiator  init_session(role "initiator", peerBundle); the bundle must be
 *              authenticated by the caller (it carries no identity proof)
 *   context    both sides pass the same context naming the two identities
 *              and the conversation; it is bound into every key and envelope
 *
 * Session state (PQR_STATE_BYTES) lives only in this worker (PqSessionStore):
 * after every operation the held buffer is zero-filled and overwritten in
 * place, a failed decrypt leaves it untouched (the engine commits only on
 * success), and close_session, secure.wipe and worker termination erase it.
 * With an unlocked session vault (pq-session-vault.ts) every new state is
 * first written encrypted to IndexedDB and only then replaces the held
 * buffer, so a reload restores the session; never sent to the server.
 */
import { wipe } from "@/lib/crypto/wipe";
import { withZkFrame, zkCheck, ZkEngineError } from "./zk-engine";

export const PQR_STATE_BYTES = 9888;
export const PQR_BUNDLE_BYTES = 1606;
export const PQR_HEADER_BYTES = 3186;
export const PQR_ENVELOPE_OVERHEAD = 3234;
export const PQR_MAX_PLAINTEXT = 16_384;
export const PQR_MAX_CONTEXT_BYTES = 512;
/** Sessions one worker holds at once. */
export const PQR_MAX_SESSIONS = 64;

const enc = new TextEncoder();
const invalid = (): never => {
  throw new ZkEngineError("zk_invalid_input");
};

function contextBytes(context: string): Uint8Array {
  if (typeof context !== "string") invalid();
  const b = enc.encode(context);
  if (b.length === 0 || b.length > PQR_MAX_CONTEXT_BYTES) invalid();
  return b;
}

function stateLenMatches(len: number) {
  if (len !== PQR_STATE_BYTES) throw new ZkEngineError("zk_engine_integrity");
}

/** Responder side: a fresh state and the RVE2 bundle to publish. */
export async function pqrResponderInit(context: string): Promise<{ state: Uint8Array; bundle: Uint8Array }> {
  const ctx = contextBytes(context);
  return withZkFrame((f) => {
    stateLenMatches(f.ex.rout_zk_pqr_state_len());
    const c = f.put(ctx);
    const st = f.reserve(PQR_STATE_BYTES);
    const b = f.reserve(PQR_BUNDLE_BYTES);
    zkCheck(f.ex.rout_zk_pqr_responder_init(c, ctx.length, st, b));
    return { state: f.take(st, PQR_STATE_BYTES), bundle: f.take(b, PQR_BUNDLE_BYTES) };
  });
}

/** Initiator side: a fresh state aimed at the (caller-authenticated) bundle. */
export async function pqrInitiatorInit(context: string, bundle: Uint8Array): Promise<Uint8Array> {
  const ctx = contextBytes(context);
  if (!(bundle instanceof Uint8Array) || bundle.length !== PQR_BUNDLE_BYTES) invalid();
  return withZkFrame((f) => {
    stateLenMatches(f.ex.rout_zk_pqr_state_len());
    const c = f.put(ctx);
    const b = f.put(bundle);
    const st = f.reserve(PQR_STATE_BYTES);
    zkCheck(f.ex.rout_zk_pqr_initiator_init(c, ctx.length, b, bundle.length, st));
    return f.take(st, PQR_STATE_BYTES);
  });
}

/** One message: the next state (fresh buffer) and the RVE2 envelope. `state` is not modified. */
export async function pqrEncrypt(state: Uint8Array, plaintext: Uint8Array): Promise<{ next: Uint8Array; envelope: Uint8Array }> {
  if (state.length !== PQR_STATE_BYTES || !(plaintext instanceof Uint8Array) || plaintext.length > PQR_MAX_PLAINTEXT) invalid();
  return withZkFrame((f) => {
    stateLenMatches(f.ex.rout_zk_pqr_state_len());
    const st = f.put(state);
    const p = f.put(plaintext);
    const cap = PQR_ENVELOPE_OVERHEAD + plaintext.length;
    const out = f.reserve(cap);
    const n = zkCheck(f.ex.rout_zk_pqr_encrypt(st, p, plaintext.length, out, cap));
    return { next: f.take(st, PQR_STATE_BYTES), envelope: f.take(out, n) };
  });
}

/**
 * Opens one envelope: the next state (fresh buffer) and the plaintext. A
 * forged, replayed or altered envelope throws zk_rejected (or
 * zk_invalid_input when malformed) and `state` stays the valid one.
 */
export async function pqrDecrypt(state: Uint8Array, envelope: Uint8Array): Promise<{ next: Uint8Array; plaintext: Uint8Array }> {
  if (state.length !== PQR_STATE_BYTES || !(envelope instanceof Uint8Array)) invalid();
  if (envelope.length < PQR_ENVELOPE_OVERHEAD || envelope.length > PQR_ENVELOPE_OVERHEAD + PQR_MAX_PLAINTEXT) invalid();
  return withZkFrame((f) => {
    stateLenMatches(f.ex.rout_zk_pqr_state_len());
    const st = f.put(state);
    const e = f.put(envelope);
    const cap = envelope.length - PQR_ENVELOPE_OVERHEAD;
    const out = f.reserve(Math.max(cap, 1));
    const n = zkCheck(f.ex.rout_zk_pqr_decrypt(st, e, envelope.length, out, cap));
    return { next: f.take(st, PQR_STATE_BYTES), plaintext: f.take(out, n) };
  });
}

/** True for a well-formed RVE2 ratchet message (shape only, nothing verified). */
export function isRve2Message(b: Uint8Array): boolean {
  return (
    b instanceof Uint8Array && b.length >= PQR_ENVELOPE_OVERHEAD && b.length <= PQR_ENVELOPE_OVERHEAD + PQR_MAX_PLAINTEXT &&
    b[0] === 0x52 && b[1] === 0x56 && b[2] === 0x45 && b[3] === 0x32 && b[4] === 1 && b[5] === 1
  );
}

const SESSION_ID = /^pqs_[0-9a-f]{32}$/;
export const isPqSessionId = (v: unknown): v is string => typeof v === "string" && SESSION_ID.test(v);

/**
 * Ratchet sessions of this worker, per member. The store owns every held
 * buffer; `replace` overwrites it in place and wipes the incoming copy, and
 * a session runs one operation at a time.
 */
export class PqSessionStore {
  private slots = new Map<string, Uint8Array>();
  private busy = new Set<string>();
  /** Set by the worker: writes a new state before it replaces the held one. */
  persist: ((owner: string, id: string, state: Uint8Array) => Promise<void>) | null = null;

  private key(owner: string, id: string) {
    return `${owner}\u0000${id}`;
  }

  get size(): number {
    return this.slots.size;
  }

  /** Takes ownership of `state`; returns the new session id. */
  create(owner: string, state: Uint8Array): string {
    if (state.length !== PQR_STATE_BYTES || this.slots.size >= PQR_MAX_SESSIONS) {
      wipe(state);
      invalid();
    }
    const id = `pqs_${Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("")}`;
    this.slots.set(this.key(owner, id), state);
    return id;
  }

  /** Re-inserts a state restored from the session vault under its own id (takes ownership). */
  restore(owner: string, id: string, state: Uint8Array): boolean {
    const k = this.key(owner, id);
    if (!isPqSessionId(id) || state.length !== PQR_STATE_BYTES || this.slots.has(k) || this.slots.size >= PQR_MAX_SESSIONS) {
      wipe(state);
      return false;
    }
    this.slots.set(k, state);
    return true;
  }

  has(owner: string, id: string): boolean {
    return this.slots.has(this.key(owner, id));
  }

  /** Runs `fn` with the held state; a returned `next` replaces it in place (and is wiped). */
  async run<T>(owner: string, id: string, fn: (state: Uint8Array) => Promise<{ next: Uint8Array; out: T }>): Promise<T> {
    const k = this.key(owner, id);
    const held = this.slots.get(k);
    if (!held || this.busy.has(k)) invalid();
    this.busy.add(k);
    try {
      const { next, out } = await fn(held!);
      try {
        if (next.length !== PQR_STATE_BYTES || this.slots.get(k) !== held) invalid();
        // Persist first: a failed write keeps the old state and fails the step.
        if (this.persist) await this.persist(owner, id, next);
        held!.fill(0);
        held!.set(next);
      } finally {
        wipe(next);
      }
      return out;
    } finally {
      this.busy.delete(k);
    }
  }

  /** The held buffer (tests only inspect it; callers never get it). */
  peek(owner: string, id: string): Uint8Array | undefined {
    return this.slots.get(this.key(owner, id));
  }

  close(owner: string, id: string): boolean {
    const k = this.key(owner, id);
    const held = this.slots.get(k);
    if (!held) return false;
    wipe(held);
    this.slots.delete(k);
    return true;
  }

  wipeAll(): number {
    let n = 0;
    for (const s of this.slots.values()) {
      wipe(s);
      n++;
    }
    this.slots.clear();
    this.busy.clear();
    return n;
  }
}

export const pqSessions = new PqSessionStore();
