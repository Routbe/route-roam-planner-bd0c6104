/**
 * Stap 8 prekey bundle: how one member's hybrid PQ ratchet (pq-ratchet.ts)
 * becomes reachable for others. Shared by the crypto worker (creates the
 * bundle, verifies every bundle before a handshake) and the server (checks
 * the passkey assertion before publishing /@username/prekey-bundle.json).
 * Public material only; no secret ever passes through this module.
 *
 * Bundle (1646 bytes):
 *   "RVE2" | version 1 | kind 3 | PK_kem (ML-KEM-1024, 1568) | PK_x25519 (32)
 *          | epoch (u64 BE, UTC day since 1970) | nonce (32)
 * Statement signed by the member's passkey (WebAuthn challenge = SHA-256):
 *   "ROUT-PQR-PREKEY-V1" || lp(rpId) || lp("@" handle) || bundle
 *   lp(x) = I2OSP(len(x), 4) || x
 * Ratchet context of every session started from it (both sides compute it):
 *   "rout.pqr.prekey.v1|" rpId "|@" handle "|" epoch "|" hex(nonce)
 *
 * verifyPrekeyDocument is what the worker runs before any handshake: document
 * shape, handle and RP id, bundle encoding and freshness, ROUT's MDS3
 * statement about the passkey (attested and status safe) and the passkey
 * assertion itself (clientDataJSON, RP id hash, UP+UV, signature). The MDS3
 * verdict is ROUT's statement made when the passkey was registered (0271);
 * the attestation chain itself is not published.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, verifyPasskeyAssertion, type EndorsementCheck } from "@/lib/anon-booking/zkp-anchor";
import { EPOCH_ORIGIN, EPOCH_SECONDS, utcEpochAt } from "@/lib/anon-booking/epoch-clock";

export const PREKEY_TYPE = "rout.pqr-prekey";
export const PREKEY_VERSION = 1;
export const PREKEY_KIND = 3;
export const PREKEY_STATEMENT_HEADER = "ROUT-PQR-PREKEY-V1";
export const PREKEY_KEM_BYTES = 1568;
export const PREKEY_X25519_BYTES = 32;
export const PREKEY_NONCE_BYTES = 32;
export const PREKEY_BUNDLE_BYTES = 6 + PREKEY_KEM_BYTES + PREKEY_X25519_BYTES + 8 + PREKEY_NONCE_BYTES;
/** Engine bundle of pq_ratchet.rs: "RVE2" | 1 | 2 | X25519 | ML-KEM key. */
export const ENGINE_BUNDLE_BYTES = 6 + PREKEY_X25519_BYTES + PREKEY_KEM_BYTES;
/** A bundle older than this many UTC days is refused (the member republishes). */
export const PREKEY_MAX_AGE_EPOCHS = 30;
/** Clock skew tolerated for a bundle dated in the future. */
export const PREKEY_FUTURE_EPOCHS = 1;

const enc = new TextEncoder();
const HANDLE_RE = /^[a-z0-9._-]{2,40}$/;
const RP_ID_RE = /^[a-z0-9.-]{1,253}$/;
const CREDENTIAL_ID_RE = /^[A-Za-z0-9_-]{16,1366}$/;
const PREKEY_ID_RE = /^pqk_[0-9a-f]{32}$/;

export type PrekeyBundle = { kem: Uint8Array; x25519: Uint8Array; epoch: number; nonce: Uint8Array };

export class PrekeyError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "PrekeyError";
  }
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + b.byteLength);
  new DataView(out.buffer).setUint32(0, b.byteLength, false);
  out.set(b, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
}

const isZero = (b: Uint8Array) => b.every((x) => x === 0);

/** "@Name" / "name" → "name", or null. */
export function prekeyHandle(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const h = raw.trim().replace(/^@/, "").toLowerCase();
  return HANDLE_RE.test(h) ? h : null;
}

function checkRpId(rpId: unknown): string {
  if (typeof rpId !== "string" || !RP_ID_RE.test(rpId)) throw new PrekeyError("prekey_rp_id");
  return rpId;
}

function checkEpoch(epoch: unknown): number {
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) throw new PrekeyError("prekey_epoch");
  return epoch;
}

export function encodePrekeyBundle(b: PrekeyBundle): Uint8Array {
  if (!(b.kem instanceof Uint8Array) || b.kem.byteLength !== PREKEY_KEM_BYTES) throw new PrekeyError("prekey_encoding");
  if (!(b.x25519 instanceof Uint8Array) || b.x25519.byteLength !== PREKEY_X25519_BYTES || isZero(b.x25519)) throw new PrekeyError("prekey_encoding");
  if (!(b.nonce instanceof Uint8Array) || b.nonce.byteLength !== PREKEY_NONCE_BYTES || isZero(b.nonce)) throw new PrekeyError("prekey_encoding");
  const epoch = new Uint8Array(8);
  new DataView(epoch.buffer).setBigUint64(0, BigInt(checkEpoch(b.epoch)), false);
  return concat(enc.encode("RVE2"), Uint8Array.of(PREKEY_VERSION, PREKEY_KIND), b.kem, b.x25519, epoch, b.nonce);
}

export function decodePrekeyBundle(bytes: Uint8Array): PrekeyBundle {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== PREKEY_BUNDLE_BYTES) throw new PrekeyError("prekey_encoding");
  if (bytes[0] !== 0x52 || bytes[1] !== 0x56 || bytes[2] !== 0x45 || bytes[3] !== 0x32 || bytes[4] !== PREKEY_VERSION || bytes[5] !== PREKEY_KIND) {
    throw new PrekeyError("prekey_encoding");
  }
  let at = 6;
  const kem = bytes.slice(at, (at += PREKEY_KEM_BYTES));
  const x25519 = bytes.slice(at, (at += PREKEY_X25519_BYTES));
  const e = new DataView(bytes.buffer, bytes.byteOffset + at, 8).getBigUint64(0, false);
  at += 8;
  const nonce = bytes.slice(at, at + PREKEY_NONCE_BYTES);
  if (e > BigInt(Number.MAX_SAFE_INTEGER) || isZero(x25519) || isZero(nonce)) throw new PrekeyError("prekey_encoding");
  return { kem, x25519, epoch: Number(e), nonce };
}

/** The engine bundle (pq_ratchet.rs initiator_init input) of a prekey. */
export function engineBundleOf(b: PrekeyBundle): Uint8Array {
  return concat(enc.encode("RVE2"), Uint8Array.of(1, 2), b.x25519, b.kem);
}

/** Prekey fields from the engine bundle pq_ratchet.rs responder_init produced. */
export function prekeyFromEngineBundle(engine: Uint8Array, epoch: number, nonce: Uint8Array): PrekeyBundle {
  if (!(engine instanceof Uint8Array) || engine.byteLength !== ENGINE_BUNDLE_BYTES || engine[4] !== 1 || engine[5] !== 2) throw new PrekeyError("prekey_encoding");
  return { x25519: engine.slice(6, 6 + PREKEY_X25519_BYTES), kem: engine.slice(6 + PREKEY_X25519_BYTES), epoch, nonce };
}

export const prekeyIdOf = (nonce: Uint8Array) => `pqk_${hex(nonce.subarray(0, 16))}`;
export const isPrekeyId = (v: unknown): v is string => typeof v === "string" && PREKEY_ID_RE.test(v);

export function prekeyStatement(rpId: string, handle: string, bundle: Uint8Array): Uint8Array {
  const h = prekeyHandle(handle);
  if (!h) throw new PrekeyError("prekey_handle");
  if (!(bundle instanceof Uint8Array) || bundle.byteLength !== PREKEY_BUNDLE_BYTES) throw new PrekeyError("prekey_encoding");
  return concat(enc.encode(PREKEY_STATEMENT_HEADER), lp(enc.encode(checkRpId(rpId))), lp(enc.encode(`@${h}`)), bundle);
}

/** WebAuthn challenge the member's passkey signs for this bundle. */
export const prekeyChallenge = (rpId: string, handle: string, bundle: Uint8Array) => sha256(prekeyStatement(rpId, handle, bundle));

export function prekeyContext(rpId: string, handle: string, epoch: number, nonce: Uint8Array): string {
  const h = prekeyHandle(handle);
  if (!h) throw new PrekeyError("prekey_handle");
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== PREKEY_NONCE_BYTES) throw new PrekeyError("prekey_encoding");
  return `rout.pqr.prekey.v1|${checkRpId(rpId)}|@${h}|${checkEpoch(epoch)}|${hex(nonce)}`;
}

/** Within [now − PREKEY_MAX_AGE_EPOCHS, now + PREKEY_FUTURE_EPOCHS]. */
export function prekeyFresh(epoch: number, now: number): boolean {
  const today = utcEpochAt(now);
  return epoch >= today - PREKEY_MAX_AGE_EPOCHS && epoch <= today + PREKEY_FUTURE_EPOCHS;
}

// ---- Published document --------------------------------------------------------

export type PrekeyMds3 = { fmt: string; attested: boolean; statusSafe: boolean; certifiedL3: boolean };
export type PrekeyPasskey = {
  credentialId: string;
  algorithm: number;
  publicKey: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  mds3: PrekeyMds3;
};
export type PrekeyDocument = {
  type: typeof PREKEY_TYPE;
  version: typeof PREKEY_VERSION;
  handle: string;
  rpId: string;
  prekeyId: string;
  epoch: { seconds: number; origin: string; value: number };
  bundle: string;
  passkey: PrekeyPasskey;
  publishedAt: string;
};

export type PrekeyAssertion = { credentialId: string; algorithm: number; authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array };

export function buildPrekeyDocument(p: {
  handle: string; rpId: string; bundle: Uint8Array; assertion: PrekeyAssertion; passkeyPublicKey: Uint8Array; mds3: PrekeyMds3; publishedAt: string;
}): PrekeyDocument {
  const h = prekeyHandle(p.handle);
  if (!h) throw new PrekeyError("prekey_handle");
  const b = decodePrekeyBundle(p.bundle);
  return {
    type: PREKEY_TYPE,
    version: PREKEY_VERSION,
    handle: `@${h}`,
    rpId: checkRpId(p.rpId),
    prekeyId: prekeyIdOf(b.nonce),
    epoch: { seconds: EPOCH_SECONDS, origin: EPOCH_ORIGIN, value: b.epoch },
    bundle: b64u(p.bundle),
    passkey: {
      credentialId: p.assertion.credentialId,
      algorithm: p.assertion.algorithm,
      publicKey: b64u(p.passkeyPublicKey),
      authenticatorData: b64u(p.assertion.authenticatorData),
      clientDataJSON: b64u(p.assertion.clientDataJSON),
      signature: b64u(p.assertion.signature),
      mds3: { fmt: p.mds3.fmt, attested: p.mds3.attested, statusSafe: p.mds3.statusSafe, certifiedL3: p.mds3.certifiedL3 },
    },
    publishedAt: p.publishedAt,
  };
}

export type PrekeyExpectation = EndorsementCheck & { handle: string; now?: number };
export type PrekeyVerified = { ok: true; handle: string; prekeyId: string; bundle: PrekeyBundle; engineBundle: Uint8Array; context: string };
export type PrekeyRejection = {
  ok: false;
  reason: "shape" | "handle" | "rp_id" | "encoding" | "prekey_id" | "stale" | "mds3" | "cose" | "algorithm" | "client_data" | "type" | "challenge" | "origin" | "flags" | "signature";
};

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = 8192): v is string => typeof v === "string" && v.length <= max;

/**
 * Every check before a handshake. `expect` is what the initiator asked for
 * (handle, the app's RP id and origins); nothing in the document overrides it.
 */
export async function verifyPrekeyDocument(doc: unknown, expect: PrekeyExpectation): Promise<PrekeyVerified | PrekeyRejection> {
  if (!isObj(doc) || doc.type !== PREKEY_TYPE || doc.version !== PREKEY_VERSION || !isObj(doc.passkey) || !isObj(doc.passkey.mds3) || !isObj(doc.epoch)) {
    return { ok: false, reason: "shape" };
  }
  const p = doc.passkey;
  const m = p.mds3 as Record<string, unknown>;
  if (!isStr(doc.handle, 64) || !isStr(doc.rpId, 253) || !isStr(doc.bundle, 4096) || !isStr(doc.prekeyId, 64) || !isStr(p.credentialId, 1366)
    || !CREDENTIAL_ID_RE.test(p.credentialId) || typeof p.algorithm !== "number" || !isStr(p.publicKey, 2048) || !isStr(p.authenticatorData, 4096)
    || !isStr(p.clientDataJSON, 4096) || !isStr(p.signature, 1024)) {
    return { ok: false, reason: "shape" };
  }
  const want = prekeyHandle(expect.handle);
  if (!want || prekeyHandle(doc.handle) !== want || doc.handle !== `@${want}`) return { ok: false, reason: "handle" };
  if (doc.rpId !== expect.rpId) return { ok: false, reason: "rp_id" };
  let bundleBytes: Uint8Array;
  let bundle: PrekeyBundle;
  let publicKey: Uint8Array, authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array;
  try {
    bundleBytes = fromB64u(doc.bundle);
    bundle = decodePrekeyBundle(bundleBytes);
    publicKey = fromB64u(p.publicKey);
    authenticatorData = fromB64u(p.authenticatorData);
    clientDataJSON = fromB64u(p.clientDataJSON);
    signature = fromB64u(p.signature);
  } catch {
    return { ok: false, reason: "encoding" };
  }
  if (doc.prekeyId !== prekeyIdOf(bundle.nonce)) return { ok: false, reason: "prekey_id" };
  if ((doc.epoch as Record<string, unknown>).value !== bundle.epoch) return { ok: false, reason: "encoding" };
  if (!prekeyFresh(bundle.epoch, expect.now ?? Date.now())) return { ok: false, reason: "stale" };
  if (m.attested !== true || m.statusSafe !== true) return { ok: false, reason: "mds3" };
  const challenge = prekeyChallenge(expect.rpId, want, bundleBytes);
  const v = await verifyPasskeyAssertion(challenge, { publicKey, algorithm: p.algorithm, authenticatorData, clientDataJSON, signature }, expect);
  if (!v.ok) return { ok: false, reason: v.reason === "rp_id" ? "rp_id" : v.reason };
  return {
    ok: true,
    handle: want,
    prekeyId: doc.prekeyId,
    bundle,
    engineBundle: engineBundleOf(bundle),
    context: prekeyContext(expect.rpId, want, bundle.epoch, bundle.nonce),
  };
}
