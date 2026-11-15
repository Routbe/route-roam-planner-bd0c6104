/**
 * Host discovery anchor (Stap 7g): /@host/zkp-anchor.json publishes, per
 * registered host device, the anchor PK_0 of its forward-secure key chain and
 * a WebAuthn assertion of the host's passkey over that anchor. The passkey's
 * hardware attestation was verified against FIDO MDS3 at registration (0271);
 * the attestation itself is a certificate chain and cannot sign, so the
 * passkey's own assertion is the signature (owner decision 2026-11-15).
 *
 * Statement (byte-identical to db/0274 anon_anchor_statement):
 *   "ROUT-ZKP-ANCHOR-V1" || lp(device id) || lp(key id) || lp(tree id)
 *     || PK_0 (96) || enclave anchor signer PK (96) || nullifier root signer PK (96)
 *   lp(x) = I2OSP(len(x), 4) || x
 * challenge = base64url(SHA-256(statement)), carried in clientDataJSON.
 *
 * verifyAnchorEndorsement checks everything a guest can check without ROUT:
 * clientDataJSON type/challenge/origin, the RP id hash and the user-presence
 * and user-verification flags in authenticatorData, and the signature over
 * authenticatorData || SHA-256(clientDataJSON) under the published COSE key
 * (ES256, EdDSA or RS256). The MDS3 verdict is ROUT's statement about that
 * key (the attestation object itself is not kept); the enclave anchor
 * signature and the epoch links are checked in the crypto worker
 * (host_key.verify_anchor, epochPublicKey).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";

export const ANCHOR_STATEMENT_HEADER = "ROUT-ZKP-ANCHOR-V1";
export const ZKP_ANCHOR_TYPE = "rout.zkp-anchor";
export const ZKP_ANCHOR_VERSION = 1;
export const COSE_ALGORITHMS = [-7, -8, -257] as const;
export type CoseAlgorithm = (typeof COSE_ALGORITHMS)[number];

const enc = new TextEncoder();
const dec = new TextDecoder();
const ID_RE = { hd: /^hd_[0-9a-f]{64}$/, hk: /^hk_[0-9a-f]{64}$/, st: /^st_[0-9a-f]{64}$/ };

export type AnchorStatementInput = {
  deviceId: string;
  keyId: string;
  treeId: string;
  anchorPublicKey: Uint8Array;
  anchorSignerPublicKey: Uint8Array;
  rootSignerPublicKey: Uint8Array;
};

export class ZkpAnchorError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "ZkpAnchorError";
  }
}

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

export function b64u(bytes: Uint8Array): string {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new ZkpAnchorError("anchor_encoding");
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0));
}

export const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(h: unknown, len?: number): Uint8Array {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-f]*$/.test(h)) throw new ZkpAnchorError("anchor_encoding");
  const out = Uint8Array.from(h.match(/.{2}/g) ?? [], (x) => parseInt(x, 16));
  if (len !== undefined && out.byteLength !== len) throw new ZkpAnchorError("anchor_encoding");
  return out;
}

/** Canonical bytes the host passkey signs (via the WebAuthn challenge). */
export function anchorStatement(a: AnchorStatementInput): Uint8Array {
  if (!ID_RE.hd.test(a.deviceId) || !ID_RE.hk.test(a.keyId) || !ID_RE.st.test(a.treeId)) throw new ZkpAnchorError("anchor_ids");
  for (const k of [a.anchorPublicKey, a.anchorSignerPublicKey, a.rootSignerPublicKey]) {
    if (!(k instanceof Uint8Array) || k.byteLength !== 96) throw new ZkpAnchorError("anchor_keys");
  }
  return concat(enc.encode(ANCHOR_STATEMENT_HEADER), lp(enc.encode(a.deviceId)), lp(enc.encode(a.keyId)), lp(enc.encode(a.treeId)),
    a.anchorPublicKey, a.anchorSignerPublicKey, a.rootSignerPublicKey);
}

/** The WebAuthn challenge for the host's passkey assertion over this anchor. */
export function anchorChallenge(a: AnchorStatementInput): Uint8Array {
  return sha256(anchorStatement(a));
}

// ---- COSE keys (minimal CBOR) --------------------------------------------------

type Cbor = number | bigint | Uint8Array | string | Map<Cbor, Cbor>;

function readCbor(b: Uint8Array, at: { i: number }, depth = 0): Cbor {
  if (depth > 4 || at.i >= b.byteLength) throw new ZkpAnchorError("cose_malformed");
  const head = b[at.i++]!;
  const major = head >> 5;
  let info = head & 31;
  let n: number;
  if (info < 24) n = info;
  else if (info === 24) n = b[at.i++]!;
  else if (info === 25) { n = (b[at.i]! << 8) | b[at.i + 1]!; at.i += 2; }
  else if (info === 26) { n = new DataView(b.buffer, b.byteOffset + at.i).getUint32(0, false); at.i += 4; }
  else throw new ZkpAnchorError("cose_malformed");
  if (at.i > b.byteLength) throw new ZkpAnchorError("cose_malformed");
  switch (major) {
    case 0: return n;
    case 1: return -1 - n;
    case 2:
    case 3: {
      if (at.i + n > b.byteLength) throw new ZkpAnchorError("cose_malformed");
      const v = b.slice(at.i, at.i + n);
      at.i += n;
      return major === 2 ? v : dec.decode(v);
    }
    case 5: {
      if (n > 16) throw new ZkpAnchorError("cose_malformed");
      const m = new Map<Cbor, Cbor>();
      for (let k = 0; k < n; k++) {
        const key = readCbor(b, at, depth + 1);
        m.set(key, readCbor(b, at, depth + 1));
      }
      return m;
    }
    default:
      throw new ZkpAnchorError("cose_malformed");
  }
}

export type CoseKey =
  | { alg: -7; x: Uint8Array; y: Uint8Array }
  | { alg: -8; x: Uint8Array }
  | { alg: -257; n: Uint8Array; e: Uint8Array };

export function parseCoseKey(bytes: Uint8Array): CoseKey {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 32 || bytes.byteLength > 1024) throw new ZkpAnchorError("cose_malformed");
  const at = { i: 0 };
  const m = readCbor(bytes, at);
  if (!(m instanceof Map) || at.i !== bytes.byteLength) throw new ZkpAnchorError("cose_malformed");
  const kty = m.get(1);
  const alg = m.get(3);
  const bin = (k: number) => {
    const v = m.get(k);
    if (!(v instanceof Uint8Array)) throw new ZkpAnchorError("cose_malformed");
    return v;
  };
  if (kty === 2 && alg === -7 && m.get(-1) === 1) {
    const x = bin(-2);
    const y = bin(-3);
    if (x.byteLength !== 32 || y.byteLength !== 32) throw new ZkpAnchorError("cose_malformed");
    return { alg: -7, x, y };
  }
  if (kty === 1 && alg === -8 && m.get(-1) === 6) {
    const x = bin(-2);
    if (x.byteLength !== 32) throw new ZkpAnchorError("cose_malformed");
    return { alg: -8, x };
  }
  if (kty === 3 && alg === -257) {
    const n = bin(-1);
    const e = bin(-2);
    if (n.byteLength < 256 || n.byteLength > 512 || e.byteLength < 1 || e.byteLength > 8) throw new ZkpAnchorError("cose_malformed");
    return { alg: -257, n, e };
  }
  throw new ZkpAnchorError("cose_unsupported");
}

async function verifyWithCose(key: CoseKey, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    if (key.alg === -7) {
      const pk = concat(Uint8Array.of(4), key.x, key.y);
      // Authenticators do not normalise S; WebAuthn signatures are DER.
      return p256.verify(sig, data, pk, { format: "der", lowS: false });
    }
    if (key.alg === -8) return ed25519.verify(sig, data, key.x);
    const k = await crypto.subtle.importKey("jwk", { kty: "RSA", n: b64u(key.n), e: b64u(key.e), alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", k, sig as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}

// ---- Endorsement check --------------------------------------------------------

export type AnchorEndorsement = {
  publicKey: Uint8Array; // COSE key of the host passkey
  algorithm: number;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
};
export type EndorsementCheck = { rpId: string; origins: readonly string[] };
export type EndorsementVerdict =
  | { ok: true }
  | { ok: false; reason: "cose" | "algorithm" | "client_data" | "type" | "challenge" | "origin" | "rp_id" | "flags" | "signature" };

/** Every check a guest can run on one device anchor without trusting ROUT. */
export async function verifyAnchorEndorsement(a: AnchorStatementInput, e: AnchorEndorsement, check: EndorsementCheck): Promise<EndorsementVerdict> {
  return verifyPasskeyAssertion(anchorChallenge(a), e, check);
}

/**
 * One WebAuthn assertion over `challenge` (32 bytes, e.g. SHA-256 of a
 * statement): clientDataJSON type/challenge/origin, RP id hash, UP+UV flags
 * and the signature under the given COSE key. Shared by the ZKP anchor and
 * the PQ prekey bundle (crypto-enclave/prekey-bundle.ts).
 */
export async function verifyPasskeyAssertion(challenge: Uint8Array, e: AnchorEndorsement, check: EndorsementCheck): Promise<EndorsementVerdict> {
  let key: CoseKey;
  try {
    key = parseCoseKey(e.publicKey);
  } catch {
    return { ok: false, reason: "cose" };
  }
  if (key.alg !== e.algorithm) return { ok: false, reason: "algorithm" };
  let cd: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(dec.decode(e.clientDataJSON));
    if (typeof parsed !== "object" || parsed === null) return { ok: false, reason: "client_data" };
    cd = parsed as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "client_data" };
  }
  if (cd.type !== "webauthn.get") return { ok: false, reason: "type" };
  if (!(challenge instanceof Uint8Array) || challenge.byteLength !== 32 || cd.challenge !== b64u(challenge)) return { ok: false, reason: "challenge" };
  if (typeof cd.origin !== "string" || !check.origins.includes(cd.origin) || cd.crossOrigin === true) return { ok: false, reason: "origin" };
  const ad = e.authenticatorData;
  if (!(ad instanceof Uint8Array) || ad.byteLength < 37) return { ok: false, reason: "rp_id" };
  const rpHash = sha256(enc.encode(check.rpId));
  let same = 0;
  for (let i = 0; i < 32; i++) same |= ad[i]! ^ rpHash[i]!;
  if (same !== 0) return { ok: false, reason: "rp_id" };
  // UP (0x01) and UV (0x04): a present, verified host signed this anchor.
  if ((ad[32]! & 0x05) !== 0x05) return { ok: false, reason: "flags" };
  const signed = concat(ad, sha256(e.clientDataJSON));
  return (await verifyWithCose(key, signed, e.signature)) ? { ok: true } : { ok: false, reason: "signature" };
}

// ---- Published document --------------------------------------------------------

export type ZkpAnchorLink = { from: number; to: number; publicKey: string; signature: string };
export type ZkpAnchorDevice = {
  deviceId: string;
  keyId: string;
  treeId: string;
  anchorPublicKey: string;
  enclaveAnchor: { signerPublicKey: string; signature: string };
  rootSignerPublicKey: string;
  epoch: number;
  currentPublicKey: string;
  retired: boolean;
  registeredAt: string;
  links: ZkpAnchorLink[];
  passkey: {
    credentialId: string;
    algorithm: number;
    publicKey: string;
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    mds3: { fmt: string; attested: boolean; statusSafe: boolean; certifiedL3: boolean };
  };
};
export type ZkpAnchorDocument = {
  type: typeof ZKP_ANCHOR_TYPE;
  version: typeof ZKP_ANCHOR_VERSION;
  host: string;
  rpId: string;
  epoch: { seconds: number; origin: string; current: number };
  devices: ZkpAnchorDevice[];
};

/** Statement fields of one published device (hex → bytes). */
export function deviceStatement(d: ZkpAnchorDevice): AnchorStatementInput {
  return {
    deviceId: d.deviceId,
    keyId: d.keyId,
    treeId: d.treeId,
    anchorPublicKey: fromHex(d.anchorPublicKey, 96),
    anchorSignerPublicKey: fromHex(d.enclaveAnchor.signerPublicKey, 96),
    rootSignerPublicKey: fromHex(d.rootSignerPublicKey, 96),
  };
}

/** A guest's check of one published device: the passkey endorsement and ROUT's MDS3 statement. */
export async function verifyZkpAnchorDevice(d: ZkpAnchorDevice, check: EndorsementCheck): Promise<EndorsementVerdict | { ok: false; reason: "mds3" | "encoding" }> {
  let statement: AnchorStatementInput;
  let endorsement: AnchorEndorsement;
  try {
    statement = deviceStatement(d);
    endorsement = {
      publicKey: fromB64u(d.passkey.publicKey),
      algorithm: d.passkey.algorithm,
      authenticatorData: fromB64u(d.passkey.authenticatorData),
      clientDataJSON: fromB64u(d.passkey.clientDataJSON),
      signature: fromB64u(d.passkey.signature),
    };
  } catch {
    return { ok: false, reason: "encoding" };
  }
  if (!d.passkey.mds3.attested || !d.passkey.mds3.statusSafe) return { ok: false, reason: "mds3" };
  return verifyAnchorEndorsement(statement, endorsement, check);
}
