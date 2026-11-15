/**
 * Anonymous booking (Stap 7f): typed adapters over wasm/rout-zk anon.rs and
 * the guest's worker-held booking state. Runs only in the crypto worker.
 *
 * Flow (host H, guest G; the database only ever sees public material):
 *   1. G  "anon_guest.begin"      worker draws a nullifier, a booking nonce and
 *                                 a per-booking seed, derives the per-booking
 *                                 pseudonym, and commits blind to [nullifier];
 *                                 out: commitment_with_proof + pseudonym
 *   2. H  "host_key.sign_slot_credential"  Blind BBS over [key id, epoch, RAW
 *                                 slot, messages..] + the guest commitment
 *   3. G  "anon_guest.accept"     verifies the chain from the anchor and the
 *                                 slot credential under exactly that epoch key
 *   4. H  challenge (random, fresh per arrival)
 *   5. G  "anon_guest.present"    BlindProofGen: discloses key id, epoch,
 *                                 messages and the nullifier, commits to the
 *                                 slot and range-proves lo <= slot <= hi
 *   6. H  "anon_host.verify_presentation", SMT non-membership + insert of the
 *                                 nullifier, "capacity.take" for a pooled slot,
 *                                 then vault_enclave.anon_booking_record
 * The host learns the per-booking pseudonym, the nullifier (random, used once)
 * and that a valid credential of this chain and epoch covers the window: never
 * the guest's identity, other bookings or the exact slot of the presentation.
 *
 * Capacity: the pool blindings come from 32 octets of host key material that
 * the worker derives from the member's RVE1 device seed (capacityKeyMaterial),
 * so the host keeps no per-step secret and nobody without that seed learns a
 * count.
 */
import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { wipe } from "@/lib/crypto/wipe";
import { checkCommitment, hostKeyIdBytes, HOST_PUBLIC_KEY_BYTES, HOST_SIGNATURE_BYTES, HOST_STATE_BYTES, MAX_CREDENTIAL_MESSAGE_BYTES, packHashedMessages, PROVER_BLIND_BYTES } from "./forward-secure";
import { derivePseudonym, PSEUDONYM_BYTES } from "./pseudonyms";
import { withZkFrame, zkCheck, ZkEngineError } from "./zk-engine";

export const NULLIFIER_BYTES = 32;
export const BOOKING_NONCE_BYTES = 32;
export const GUEST_SEED_BYTES = 32;
/** 32 BBS messages minus key id, epoch and slot. */
export const MAX_SLOT_MESSAGES = 29;
export const MAX_CHALLENGE_BYTES = 256;
export const RANGE_PROOF_BYTES = 928;
export const CAPACITY_COMMITMENT_BYTES = 48;
export const CAPACITY_OPEN_PROOF_BYTES = RANGE_PROOF_BYTES;
export const CAPACITY_TAKE_PROOF_BYTES = 2 * RANGE_PROOF_BYTES;
/** Presentation: 8 + (272 + 32·U) + 80 + 1856 octets, U <= 49 undisclosed messages. */
export const PRESENTATION_MIN_BYTES = 8 + 272 + 80 + 2 * RANGE_PROOF_BYTES;
export const PRESENTATION_MAX_BYTES = 8 + 1840 + 80 + 2 * RANGE_PROOF_BYTES;
export const MAX_POOL_ID_BYTES = 128;
export const MAX_POOL_TAKES = 65_536;
export const CAPACITY_KM_BYTES = 32;
export const CAPACITY_SALT = "rout.v1.anon.capacity";
/** u64 values the engine accepts; slots and window edges are unix minutes in practice. */
const U64_MAX = (1n << 64n) - 1n;

const enc = new TextEncoder();

function need(bytes: unknown, len: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== len) throw new ZkEngineError("zk_invalid_input");
  return bytes;
}

function u64(v: unknown): bigint {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "bigint" && v >= 0n && v <= U64_MAX) return v;
  throw new ZkEngineError("zk_invalid_input");
}

function epochOf(v: unknown): bigint {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new ZkEngineError("zk_invalid_input");
  return BigInt(v);
}

function challengeOf(v: unknown): Uint8Array {
  if (!(v instanceof Uint8Array) || v.byteLength === 0 || v.byteLength > MAX_CHALLENGE_BYTES) throw new ZkEngineError("zk_invalid_input");
  return v;
}

/** Pool id as UTF-8, 1..128 octets (the database id "cp_<64 hex>"). */
export function poolIdBytes(poolId: unknown): Uint8Array {
  if (typeof poolId !== "string") throw new ZkEngineError("zk_invalid_input");
  const b = enc.encode(poolId);
  if (b.byteLength === 0 || b.byteLength > MAX_POOL_ID_BYTES) throw new ZkEngineError("zk_invalid_input");
  return b;
}

/** Pool blinding key material from the member's RVE1 device seed (HKDF-SHA256). */
export function capacityKeyMaterial(deviceSeed: Uint8Array): Uint8Array {
  need(deviceSeed, 32);
  const prk = extract(sha256, deviceSeed, enc.encode(CAPACITY_SALT));
  try {
    return expand(sha256, prk, enc.encode("pool-blinding"), CAPACITY_KM_BYTES);
  } finally {
    wipe(prk);
  }
}

/** 0 = valid; -1 (malformed) and -2 (does not verify) = not valid; anything else throws. */
function verdict(rc: number): boolean {
  if (rc === -1 || rc === -2) return false;
  zkCheck(rc);
  return true;
}

// ---- Engine calls: credential and presentation ------------------------------

/** Blind BBS Commit over [nullifier]: commitment_with_proof (112) and the prover blind (32). */
export async function guestCommit(nullifier: Uint8Array): Promise<{ commitmentWithProof: Uint8Array; proverBlind: Uint8Array }> {
  need(nullifier, NULLIFIER_BYTES);
  const packed = packHashedMessages([nullifier], 1);
  try {
    return await withZkFrame((f) => {
      const out = f.reserve(256);
      const pb = f.reserve(PROVER_BLIND_BYTES);
      const n = zkCheck(f.ex.rout_zk_commit(f.put(packed), packed.byteLength, out, 256, pb));
      return { commitmentWithProof: f.take(out, n), proverBlind: f.take(pb, PROVER_BLIND_BYTES) };
    });
  } finally {
    wipe(packed);
  }
}

/** Host: slot credential of the current epoch over [key id, epoch, RAW slot, messages..] and the guest commitment. */
export async function hostKeySignSlot(state: Uint8Array, epoch: number, keyId: string, slot: number | bigint, messages: Uint8Array[], commitment: Uint8Array): Promise<Uint8Array> {
  need(state, HOST_STATE_BYTES);
  const e = epochOf(epoch);
  const s = u64(slot);
  const kid = hostKeyIdBytes(keyId);
  const cwp = checkCommitment(commitment);
  if (cwp.byteLength === 0) throw new ZkEngineError("zk_invalid_input");
  const packed = packHashedMessages(messages, MAX_SLOT_MESSAGES);
  try {
    return await withZkFrame((f) => {
      const sig = f.reserve(HOST_SIGNATURE_BYTES);
      zkCheck(f.ex.rout_zk_hostkey_sign_slot(f.put(state), e, f.put(kid), kid.byteLength, f.put(cwp), cwp.byteLength, s, f.put(packed), packed.byteLength, sig));
      return f.take(sig, HOST_SIGNATURE_BYTES);
    });
  } finally {
    wipe(packed);
  }
}

export async function verifySlotCredential(publicKey: Uint8Array, keyId: string, epoch: number, signature: Uint8Array, slot: number | bigint, messages: Uint8Array[], nullifier: Uint8Array, proverBlind: Uint8Array): Promise<boolean> {
  need(publicKey, HOST_PUBLIC_KEY_BYTES);
  need(signature, HOST_SIGNATURE_BYTES);
  need(nullifier, NULLIFIER_BYTES);
  need(proverBlind, PROVER_BLIND_BYTES);
  const kid = hostKeyIdBytes(keyId);
  const e = epochOf(epoch);
  const s = u64(slot);
  const packed = packHashedMessages(messages, MAX_SLOT_MESSAGES);
  const committed = packHashedMessages([nullifier], 1);
  try {
    return await withZkFrame((f) =>
      verdict(f.ex.rout_zk_hostkey_verify_slot_credential(
        f.put(publicKey), f.put(kid), kid.byteLength, e, f.put(signature), s, f.put(packed), packed.byteLength,
        f.put(committed), committed.byteLength, f.put(proverBlind),
      )),
    );
  } finally {
    wipe(packed, committed);
  }
}

export type PresentInput = {
  publicKey: Uint8Array; keyId: string; epoch: number; signature: Uint8Array; slot: number | bigint; messages: Uint8Array[];
  nullifier: Uint8Array; proverBlind: Uint8Array; challenge: Uint8Array; windowStart: number | bigint; windowEnd: number | bigint;
};

/** Guest: the presentation. A slot outside [windowStart, windowEnd] is refused (zk_rejected), no proof exists for it. */
export async function anonPresent(p: PresentInput): Promise<Uint8Array> {
  need(p.publicKey, HOST_PUBLIC_KEY_BYTES);
  need(p.signature, HOST_SIGNATURE_BYTES);
  need(p.nullifier, NULLIFIER_BYTES);
  need(p.proverBlind, PROVER_BLIND_BYTES);
  const kid = hostKeyIdBytes(p.keyId);
  const ch = challengeOf(p.challenge);
  const [e, s, lo, hi] = [epochOf(p.epoch), u64(p.slot), u64(p.windowStart), u64(p.windowEnd)];
  if (lo > hi) throw new ZkEngineError("zk_invalid_input");
  const packed = packHashedMessages(p.messages, MAX_SLOT_MESSAGES);
  try {
    return await withZkFrame((f) => {
      const out = f.reserve(PRESENTATION_MAX_BYTES);
      const n = zkCheck(f.ex.rout_zk_anon_present(
        f.put(p.publicKey), f.put(kid), kid.byteLength, e, f.put(p.signature), s, f.put(packed), packed.byteLength,
        f.put(p.nullifier), f.put(p.proverBlind), f.put(ch), ch.byteLength, lo, hi, out, PRESENTATION_MAX_BYTES,
      ));
      return f.take(out, n);
    });
  } finally {
    wipe(packed);
  }
}

export type PresentationCheck = {
  publicKey: Uint8Array; keyId: string; epoch: number; presentation: Uint8Array; messages: Uint8Array[]; nullifier: Uint8Array;
  challenge: Uint8Array; windowStart: number | bigint; windowEnd: number | bigint;
};

export async function anonVerifyPresentation(c: PresentationCheck): Promise<boolean> {
  need(c.publicKey, HOST_PUBLIC_KEY_BYTES);
  need(c.nullifier, NULLIFIER_BYTES);
  if (!(c.presentation instanceof Uint8Array) || c.presentation.byteLength < PRESENTATION_MIN_BYTES || c.presentation.byteLength > PRESENTATION_MAX_BYTES) return false;
  const kid = hostKeyIdBytes(c.keyId);
  const ch = challengeOf(c.challenge);
  const [e, lo, hi] = [epochOf(c.epoch), u64(c.windowStart), u64(c.windowEnd)];
  if (lo > hi) return false;
  const packed = packHashedMessages(c.messages, MAX_SLOT_MESSAGES);
  try {
    return await withZkFrame((f) =>
      verdict(f.ex.rout_zk_anon_verify_presentation(
        f.put(c.publicKey), f.put(kid), kid.byteLength, e, f.put(c.presentation), c.presentation.byteLength,
        f.put(packed), packed.byteLength, f.put(c.nullifier), f.put(ch), ch.byteLength, lo, hi,
      )),
    );
  } finally {
    wipe(packed);
  }
}

// ---- Engine calls: chain anchor -------------------------------------------------

export const ANCHOR_HEADER = "ROUT-HOST-ANCHOR-V1";
export const ANCHOR_SALT = "rout.v1.anon.anchor";
const ANCHOR_KEY_INFO = "anchor-signing-key";

/** Anchor signing key material from the member's RVE1 device seed (HKDF-SHA256). */
export function anchorKeyMaterial(deviceSeed: Uint8Array): Uint8Array {
  need(deviceSeed, 32);
  const prk = extract(sha256, deviceSeed, enc.encode(ANCHOR_SALT));
  try {
    return expand(sha256, prk, enc.encode(ANCHOR_KEY_INFO), 32);
  } finally {
    wipe(prk);
  }
}

/**
 * BBS signature (header ROUT-HOST-ANCHOR-V1) over [key id, PK_0, tree id] by a
 * key derived from the device seed: binds the chain's anchor to its nullifier
 * tree and to the device that signs its roots. The secret key exists only in
 * the engine memory of this one call.
 */
export async function signHostAnchor(km: Uint8Array, keyId: string, anchorPublicKey: Uint8Array, treeId: string): Promise<{ signerPublicKey: Uint8Array; signature: Uint8Array }> {
  need(km, 32);
  need(anchorPublicKey, HOST_PUBLIC_KEY_BYTES);
  const msgs = packHashedMessages([hostKeyIdBytes(keyId), anchorPublicKey, poolIdBytes(treeId)], 3);
  const info = enc.encode(ANCHOR_KEY_INFO);
  const header = enc.encode(ANCHOR_HEADER);
  try {
    return await withZkFrame((f) => {
      const sk = f.reserve(32);
      const pk = f.reserve(HOST_PUBLIC_KEY_BYTES);
      zkCheck(f.ex.rout_zk_keygen(f.put(km), km.byteLength, f.put(info), info.byteLength, sk, pk));
      const sig = f.reserve(HOST_SIGNATURE_BYTES);
      zkCheck(f.ex.rout_zk_sign(sk, pk, f.put(header), header.byteLength, f.put(msgs), msgs.byteLength, sig));
      return { signerPublicKey: f.take(pk, HOST_PUBLIC_KEY_BYTES), signature: f.take(sig, HOST_SIGNATURE_BYTES) };
    });
  } finally {
    wipe(msgs);
  }
}

export async function verifyHostAnchor(signerPublicKey: Uint8Array, signature: Uint8Array, keyId: string, anchorPublicKey: Uint8Array, treeId: string): Promise<boolean> {
  need(signerPublicKey, HOST_PUBLIC_KEY_BYTES);
  need(signature, HOST_SIGNATURE_BYTES);
  need(anchorPublicKey, HOST_PUBLIC_KEY_BYTES);
  const msgs = packHashedMessages([hostKeyIdBytes(keyId), anchorPublicKey, poolIdBytes(treeId)], 3);
  const header = enc.encode(ANCHOR_HEADER);
  return withZkFrame((f) => verdict(f.ex.rout_zk_verify(f.put(signerPublicKey), f.put(signature), f.put(header), header.byteLength, f.put(msgs), msgs.byteLength)));
}

// ---- Engine calls: capacity ---------------------------------------------------

/** Opens a pool of `capacity` seats: C_0 (48) and its range proof (928). `km` is wiped by the engine copy only; the caller wipes its own. */
export async function capacityOpen(km: Uint8Array, poolId: string, capacity: number | bigint): Promise<{ commitment: Uint8Array; proof: Uint8Array }> {
  need(km, CAPACITY_KM_BYTES);
  const pool = poolIdBytes(poolId);
  const cap = u64(capacity);
  return withZkFrame((f) => {
    const c = f.reserve(CAPACITY_COMMITMENT_BYTES);
    const pr = f.reserve(CAPACITY_OPEN_PROOF_BYTES);
    zkCheck(f.ex.rout_zk_capacity_open(f.put(km), f.put(pool), pool.byteLength, cap, c, pr));
    return { commitment: f.take(c, CAPACITY_COMMITMENT_BYTES), proof: f.take(pr, CAPACITY_OPEN_PROOF_BYTES) };
  });
}

export async function capacityVerifyOpen(commitment: Uint8Array, poolId: string, proof: Uint8Array): Promise<boolean> {
  need(commitment, CAPACITY_COMMITMENT_BYTES);
  need(proof, CAPACITY_OPEN_PROOF_BYTES);
  const pool = poolIdBytes(poolId);
  return withZkFrame((f) => verdict(f.ex.rout_zk_capacity_verify_open(f.put(commitment), f.put(pool), pool.byteLength, f.put(proof))));
}

/** Take number `step` (1-based) of `take` seats from `remainingBefore`; more than remain (or zero) is zk_rejected. */
export async function capacityTake(km: Uint8Array, poolId: string, step: number, remainingBefore: number | bigint, take: number | bigint): Promise<{ takeCommitment: Uint8Array; remainingCommitment: Uint8Array; proof: Uint8Array }> {
  need(km, CAPACITY_KM_BYTES);
  const pool = poolIdBytes(poolId);
  if (!Number.isSafeInteger(step) || step < 1 || step > MAX_POOL_TAKES) throw new ZkEngineError("zk_invalid_input");
  const [before, t] = [u64(remainingBefore), u64(take)];
  return withZkFrame((f) => {
    const tc = f.reserve(CAPACITY_COMMITMENT_BYTES);
    const rc = f.reserve(CAPACITY_COMMITMENT_BYTES);
    const pr = f.reserve(CAPACITY_TAKE_PROOF_BYTES);
    zkCheck(f.ex.rout_zk_capacity_take(f.put(km), f.put(pool), pool.byteLength, BigInt(step), before, t, tc, rc, pr));
    return { takeCommitment: f.take(tc, CAPACITY_COMMITMENT_BYTES), remainingCommitment: f.take(rc, CAPACITY_COMMITMENT_BYTES), proof: f.take(pr, CAPACITY_TAKE_PROOF_BYTES) };
  });
}

export async function capacityVerifyTake(before: Uint8Array, take: Uint8Array, after: Uint8Array, poolId: string, step: number, proof: Uint8Array): Promise<boolean> {
  need(before, CAPACITY_COMMITMENT_BYTES);
  need(take, CAPACITY_COMMITMENT_BYTES);
  need(after, CAPACITY_COMMITMENT_BYTES);
  need(proof, CAPACITY_TAKE_PROOF_BYTES);
  const pool = poolIdBytes(poolId);
  if (!Number.isSafeInteger(step) || step < 1 || step > MAX_POOL_TAKES) return false;
  return withZkFrame((f) =>
    verdict(f.ex.rout_zk_capacity_verify_take(f.put(before), f.put(take), f.put(after), f.put(pool), pool.byteLength, BigInt(step), f.put(proof))),
  );
}

// ---- Guest state (worker only) --------------------------------------------------

export type GuestCredential = { keyId: string; epoch: number; slot: bigint; messages: Uint8Array[]; signature: Uint8Array; publicKey: Uint8Array };
export type GuestSlotData = {
  hostId: string;
  keyId: string;
  nullifier: Uint8Array;
  bookingNonce: Uint8Array;
  seed: Uint8Array;
  proverBlind: Uint8Array;
  pseudonym: Uint8Array;
  credential: GuestCredential | null;
  expiresAt: number;
};
type GuestSlot = GuestSlotData;

/** One booking a guest is making, from commitment to presentation. 30 days, then wiped. */
export const GUEST_SLOT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_GUEST_SLOTS = 64;

/**
 * Guest secrets per handle, only in this worker: the nullifier, booking nonce,
 * per-booking seed and prover blind never leave it. discard() and wipeAll()
 * zero-fill them. Across reloads a booking exists only as an AES-256-GCM
 * record of the guest vault (guest-vault.ts, Stap 7g); with the vault open
 * the pseudonym seed is the guest's SK_guest (from the passkey PRF), else a
 * fresh random seed per booking.
 */
export class GuestBookingStore {
  private slots = new Map<string, GuestSlot>();

  private sweep(now: number) {
    for (const [h, s] of this.slots) if (s.expiresAt <= now) this.discard(h);
  }

  /** `guestSeed` (SK_guest of an open guest vault) is copied, never kept; the caller wipes its own. */
  async begin(handle: string, hostId: string, keyId: string, now = Date.now(), guestSeed?: Uint8Array): Promise<{ commitmentWithProof: Uint8Array; pseudonym: Uint8Array }> {
    hostKeyIdBytes(keyId);
    if (typeof hostId !== "string" || hostId.length === 0 || enc.encode(hostId).byteLength > 256) throw new ZkEngineError("zk_invalid_input");
    if (guestSeed !== undefined && (!(guestSeed instanceof Uint8Array) || guestSeed.byteLength !== GUEST_SEED_BYTES)) throw new ZkEngineError("zk_invalid_input");
    this.sweep(now);
    if (this.slots.size >= MAX_GUEST_SLOTS || this.slots.has(handle)) throw new ZkEngineError("zk_invalid_input");
    const nullifier = crypto.getRandomValues(new Uint8Array(NULLIFIER_BYTES));
    const bookingNonce = crypto.getRandomValues(new Uint8Array(BOOKING_NONCE_BYTES));
    const seed = guestSeed ? guestSeed.slice() : crypto.getRandomValues(new Uint8Array(GUEST_SEED_BYTES));
    let proverBlind: Uint8Array | null = null;
    try {
      const pseudonym = derivePseudonym(seed, hostId, bookingNonce);
      const c = await guestCommit(nullifier);
      proverBlind = c.proverBlind;
      this.slots.set(handle, { hostId, keyId, nullifier, bookingNonce, seed, proverBlind, pseudonym, credential: null, expiresAt: now + GUEST_SLOT_TTL_MS });
      return { commitmentWithProof: c.commitmentWithProof, pseudonym: pseudonym.slice() };
    } catch (e) {
      wipe(nullifier, bookingNonce, seed);
      if (proverBlind) wipe(proverBlind);
      throw e;
    }
  }

  get(handle: string, now = Date.now()): GuestSlot | undefined {
    this.sweep(now);
    return this.slots.get(handle);
  }

  /** Keeps a verified credential; copies everything it keeps. */
  accept(handle: string, c: GuestCredential): void {
    const s = this.slots.get(handle);
    if (!s || s.credential || c.keyId !== s.keyId) throw new ZkEngineError("zk_invalid_input");
    for (const m of c.messages) if (m.byteLength > MAX_CREDENTIAL_MESSAGE_BYTES) throw new ZkEngineError("zk_invalid_input");
    s.credential = { keyId: c.keyId, epoch: c.epoch, slot: c.slot, messages: c.messages.map((m) => m.slice()), signature: c.signature.slice(), publicKey: c.publicKey.slice() };
  }

  /** Deep copy of one slot for the guest vault (the caller wipes it), or null. */
  exportSlot(handle: string): GuestSlotData | null {
    const s = this.slots.get(handle);
    if (!s) return null;
    const c = s.credential;
    return {
      hostId: s.hostId, keyId: s.keyId, nullifier: s.nullifier.slice(), bookingNonce: s.bookingNonce.slice(), seed: s.seed.slice(),
      proverBlind: s.proverBlind.slice(), pseudonym: s.pseudonym.slice(), expiresAt: s.expiresAt,
      credential: c ? { keyId: c.keyId, epoch: c.epoch, slot: c.slot, messages: c.messages.map((m) => m.slice()), signature: c.signature.slice(), publicKey: c.publicKey.slice() } : null,
    };
  }

  /** Installs a slot read back from the guest vault; takes ownership (wiped when refused). */
  restore(handle: string, data: GuestSlotData, now = Date.now()): boolean {
    this.sweep(now);
    const sized = [data.nullifier, data.bookingNonce, data.seed, data.proverBlind, data.pseudonym].every((b) => b instanceof Uint8Array && b.byteLength === 32);
    if (!sized || data.expiresAt <= now || this.slots.has(handle) || this.slots.size >= MAX_GUEST_SLOTS) {
      wipe(data.nullifier, data.bookingNonce, data.seed, data.proverBlind, data.pseudonym);
      if (data.credential) wipe(data.credential.signature, ...data.credential.messages);
      return false;
    }
    this.slots.set(handle, data);
    return true;
  }

  discard(handle: string): boolean {
    const s = this.slots.get(handle);
    if (!s) return false;
    wipe(s.nullifier, s.bookingNonce, s.seed, s.proverBlind, s.pseudonym);
    if (s.credential) wipe(s.credential.signature, ...s.credential.messages);
    this.slots.delete(handle);
    return true;
  }

  wipeAll(): number {
    let n = 0;
    for (const h of [...this.slots.keys()]) if (this.discard(h)) n++;
    return n;
  }
}

/** Guest bookings of this worker (wiped by secure.wipe). */
export const guestBookings = new GuestBookingStore();
export { PSEUDONYM_BYTES };
