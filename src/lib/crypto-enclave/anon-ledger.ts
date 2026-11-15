/**
 * Client-side check of the anonymous booking ledger (db/0273
 * anon_ledger_events, Stap 7f). The database writes one hash chain per
 * nullifier tree; this module recomputes every hash with the same encoding as
 * vault_enclave.anon_ledger_hash and checks order and structure, so a host
 * never has to trust the server for integrity:
 *
 *   event_hash = SHA-256("rout.anon.ledger.v1" || lp(tree) || I2OSP(seq, 8) ||
 *                lp(kind) || I2OSP(root_epoch, 8) || smt_root || lp(pool) ||
 *                I2OSP(pool_step or -1, 8) || lp(take) || lp(remaining) ||
 *                lp(proof) || lp(nullifier) || lp(pseudonym) || prev_hash)
 *   lp(x)      = I2OSP(len(x), 4) || x, and 0xffffffff for an absent field
 *
 * Only public material passes through here (commitments, proofs, roots,
 * nullifiers, per-booking pseudonyms). The capacity proofs themselves need
 * the engine: verifyAnonLedger returns every pool step with its previous
 * remainder so the caller can run "capacity.verify_open" / "capacity.verify_take"
 * in the crypto worker.
 */
import { sha256 } from "@noble/hashes/sha2.js";

export const LEDGER_DOMAIN = "rout.anon.ledger.v1";
export const LEDGER_HASH_BYTES = 32;
export const CAPACITY_COMMITMENT_BYTES = 48;
export const CAPACITY_OPEN_PROOF_BYTES = 928;
export const CAPACITY_TAKE_PROOF_BYTES = 1856;
export const LEDGER_KINDS = ["genesis", "pool_open", "booking", "invalidate", "retire"] as const;
export type LedgerKind = (typeof LEDGER_KINDS)[number];

export type AnonLedgerEvent = {
  seq: number;
  kind: LedgerKind;
  rootEpoch: number;
  smtRoot: Uint8Array;
  poolId: string | null;
  poolStep: number | null;
  takeCommitment: Uint8Array | null;
  remainingCommitment: Uint8Array | null;
  proof: Uint8Array | null;
  nullifier: Uint8Array | null;
  pseudonym: Uint8Array | null;
  prevHash: Uint8Array;
  eventHash: Uint8Array;
};

export type CapacityStep =
  | { kind: "open"; poolId: string; commitment: Uint8Array; proof: Uint8Array }
  | { kind: "take"; poolId: string; step: number; before: Uint8Array; take: Uint8Array; after: Uint8Array; proof: Uint8Array };

export type LedgerVerdict =
  | { ok: true; headSeq: number; headHash: Uint8Array; capacity: CapacityStep[]; bookings: number }
  | { ok: false; at: number; error: string };

const enc = new TextEncoder();
const ZERO = new Uint8Array(LEDGER_HASH_BYTES);

function i64(v: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt(v), false);
  return out;
}

function lp(b: Uint8Array | null): Uint8Array {
  if (b === null) return Uint8Array.of(0xff, 0xff, 0xff, 0xff);
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setInt32(0, b.length, false);
  out.set(b, 4);
  return out;
}

const same = (a: Uint8Array | null, b: Uint8Array | null) =>
  a !== null && b !== null && a.length === b.length && a.every((x, i) => x === b[i]);

/** event_hash of one event (the same rule as vault_enclave.anon_ledger_hash). */
export function anonLedgerHash(treeId: string, e: Omit<AnonLedgerEvent, "eventHash">): Uint8Array {
  const parts = [
    enc.encode(LEDGER_DOMAIN), lp(enc.encode(treeId)), i64(e.seq), lp(enc.encode(e.kind)), i64(e.rootEpoch), e.smtRoot,
    lp(e.poolId === null ? null : enc.encode(e.poolId)), i64(e.poolStep ?? -1), lp(e.takeCommitment), lp(e.remainingCommitment),
    lp(e.proof), lp(e.nullifier), lp(e.pseudonym), e.prevHash,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    buf.set(p, at);
    at += p.length;
  }
  return sha256(buf);
}

const hexBytes = (v: unknown): Uint8Array | null => {
  if (v === null || v === undefined) return null;
  if (typeof v !== "string" || v.length % 2 !== 0 || !/^[0-9a-f]*$/.test(v)) throw new Error("ledger_malformed");
  const out = new Uint8Array(v.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(v.slice(2 * i, 2 * i + 2), 16);
  return out;
};
const int = (v: unknown, nullable = false): number | null => {
  if (nullable && (v === null || v === undefined)) return null;
  if (typeof v !== "number" || !Number.isSafeInteger(v)) throw new Error("ledger_malformed");
  return v;
};

/** Parses the `events` array of vault_enclave.anon_ledger (hex fields). */
export function ledgerEventsFromJson(rows: unknown): AnonLedgerEvent[] {
  if (!Array.isArray(rows)) throw new Error("ledger_malformed");
  return rows.map((r) => {
    const o = r as Record<string, unknown>;
    if (!LEDGER_KINDS.includes(o.kind as LedgerKind)) throw new Error("ledger_malformed");
    if (o.poolId !== null && o.poolId !== undefined && typeof o.poolId !== "string") throw new Error("ledger_malformed");
    return {
      seq: int(o.seq)!, kind: o.kind as LedgerKind, rootEpoch: int(o.rootEpoch)!, smtRoot: hexBytes(o.smtRoot)!,
      poolId: (o.poolId as string | null | undefined) ?? null, poolStep: int(o.poolStep, true),
      takeCommitment: hexBytes(o.takeCommitment), remainingCommitment: hexBytes(o.remainingCommitment), proof: hexBytes(o.proof),
      nullifier: hexBytes(o.nullifier), pseudonym: hexBytes(o.pseudonym), prevHash: hexBytes(o.prevHash)!, eventHash: hexBytes(o.eventHash)!,
    };
  });
}

function shapeError(e: AnonLedgerEvent): string | null {
  const len = (b: Uint8Array | null, n: number) => b !== null && b.length === n;
  if (!len(e.smtRoot, 32) || !len(e.prevHash, 32) || !len(e.eventHash, 32)) return "length";
  const none = (...xs: unknown[]) => xs.every((x) => x === null);
  switch (e.kind) {
    case "genesis":
      return e.seq === 0 && e.rootEpoch === 0 && same(e.prevHash, ZERO) && none(e.poolId, e.poolStep, e.takeCommitment, e.remainingCommitment, e.proof, e.nullifier, e.pseudonym) ? null : "genesis";
    case "pool_open":
      return e.poolId !== null && e.poolStep === 0 && e.takeCommitment === null && len(e.remainingCommitment, 48) && len(e.proof, CAPACITY_OPEN_PROOF_BYTES) && none(e.nullifier, e.pseudonym) ? null : "pool_open";
    case "booking": {
      if (!len(e.nullifier, 32) || !len(e.pseudonym, 32)) return "booking";
      if (e.poolId === null) return none(e.poolStep, e.takeCommitment, e.remainingCommitment, e.proof) ? null : "booking";
      return (e.poolStep ?? 0) >= 1 && len(e.takeCommitment, 48) && len(e.remainingCommitment, 48) && len(e.proof, CAPACITY_TAKE_PROOF_BYTES) ? null : "booking";
    }
    case "invalidate":
      return len(e.pseudonym, 32) && none(e.poolId, e.poolStep, e.takeCommitment, e.remainingCommitment, e.proof, e.nullifier) ? null : "invalidate";
    case "retire":
      return none(e.poolId, e.poolStep, e.takeCommitment, e.remainingCommitment, e.proof, e.nullifier, e.pseudonym) ? null : "retire";
  }
}

/**
 * Checks a ledger from genesis (or continuing after `from`, a head this
 * client already verified): contiguous sequence, prev_hash links, every hash
 * recomputed, one root step per booking, unique nullifiers, and per pool an
 * opening followed by contiguous steps whose `before` is the last remainder.
 */
export function verifyAnonLedger(treeId: string, events: AnonLedgerEvent[], from?: { seq: number; hash: Uint8Array; rootEpoch: number }): LedgerVerdict {
  let seq = from ? from.seq : -1;
  let prev = from ? from.hash : ZERO;
  let rootEpoch = from ? from.rootEpoch : 0;
  const nullifiers = new Set<string>();
  const pools = new Map<string, { step: number; remaining: Uint8Array }>();
  const capacity: CapacityStep[] = [];
  let bookings = 0;
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  for (const e of events) {
    const fail = (error: string): LedgerVerdict => ({ ok: false, at: e.seq, error });
    if (e.seq !== seq + 1) return fail("sequence");
    const shape = shapeError(e);
    if (shape) return fail(`shape:${shape}`);
    if (e.kind !== "genesis" && !same(e.prevHash, prev)) return fail("prev_hash");
    if (!same(anonLedgerHash(treeId, e), e.eventHash)) return fail("hash");
    if (e.kind === "booking") {
      if (e.rootEpoch !== rootEpoch + 1) return fail("root_epoch");
      const k = hex(e.nullifier!);
      if (nullifiers.has(k)) return fail("double_spend");
      nullifiers.add(k);
      bookings++;
    } else if (e.rootEpoch !== rootEpoch) {
      return fail("root_epoch");
    }
    if (e.kind === "pool_open") {
      if (pools.has(e.poolId!)) return fail("pool_reopened");
      pools.set(e.poolId!, { step: 0, remaining: e.remainingCommitment! });
      capacity.push({ kind: "open", poolId: e.poolId!, commitment: e.remainingCommitment!, proof: e.proof! });
    } else if (e.kind === "booking" && e.poolId !== null) {
      const p = pools.get(e.poolId);
      if (!p) return fail("pool_unknown");
      if (e.poolStep !== p.step + 1) return fail("pool_step");
      capacity.push({ kind: "take", poolId: e.poolId, step: e.poolStep, before: p.remaining, take: e.takeCommitment!, after: e.remainingCommitment!, proof: e.proof! });
      p.step = e.poolStep;
      p.remaining = e.remainingCommitment!;
    }
    seq = e.seq;
    prev = e.eventHash;
    rootEpoch = e.rootEpoch;
  }
  return { ok: true, headSeq: seq, headHash: prev, capacity, bookings };
}
