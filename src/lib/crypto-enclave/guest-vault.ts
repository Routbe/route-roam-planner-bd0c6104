/**
 * Guest vault (Stap 7g, owner decision 2026-11-15). Runs only in the crypto
 * worker. An anonymous guest's secrets exist on this device only, and on disk
 * only as AES-256-GCM ciphertext in IndexedDB "vault_guest_storage"; nothing
 * is written to localStorage, sessionStorage or the server.
 *
 * Secret origin (one passkey of the guest, never an account):
 *   ikm = WebAuthn PRF output (extension "prf", eval.first = GUEST_PRF_SALT)
 *       | fallback: the assertion signature over GUEST_FALLBACK_CHALLENGE, but
 *         only when two separate assertions return the identical signature.
 *   master_seed = HKDF-SHA256(ikm, "rout.v1.guest.master-seed", method || 0x00 || credential id)
 *   SK_guest    = HKDF-SHA256(master_seed, "rout.v1.guest.sk", "sk-guest")
 *   storage key = HKDF-SHA256(master_seed, "rout.v1.guest.storage", "aes-256-gcm")
 *                 imported non-extractable; its raw bytes are wiped at once.
 *
 * Why the fallback demands two equal signatures: an assertion signs
 * authenticatorData (with the signature counter) || SHA-256(clientDataJSON),
 * and most authenticators sign ECDSA with a random nonce. Only an
 * authenticator that signs deterministically (Ed25519, RFC 6979 ECDSA) over an
 * unchanged counter yields the same bytes again; any other would derive a new
 * seed on every visit and lose the guest's bookings. Such authenticators are
 * refused (guest_vault_no_stable_secret) instead of silently degrading.
 *
 * Records (key "<scope>|<name>", value { v: 1, iv, ct }):
 *   seed            master_seed || SK_guest; opening it proves the right
 *                   passkey (a wrong one fails AES-GCM or the comparison)
 *   booking:<h>     one booking in progress (nullifier, booking nonce,
 *                   prover blind, pseudonym, accepted credential)
 * scope = SHA-256("rout.v1.guest.scope|" || credential id), AAD binds scope
 * and record name, every plaintext is padded to a multiple of 4096 bytes so
 * stored sizes do not reveal how many credential messages a booking holds.
 */
import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { wipe } from "@/lib/crypto/wipe";
import type { GuestSlotData } from "./anon-booking";
import { GUEST_FALLBACK_CHALLENGE, GUEST_PRF_SALT, GUEST_VAULT_DB, GUEST_VAULT_STORE } from "./guest-vault-constants";

const enc = new TextEncoder();
const dec = new TextDecoder();

export { GUEST_FALLBACK_CHALLENGE, GUEST_PRF_SALT, GUEST_VAULT_DB, GUEST_VAULT_STORE };
export const GUEST_SECRET_BYTES = 32;
export const PRF_OUTPUT_BYTES = 32;
export const MIN_SIGNATURE_BYTES = 64;
export const MAX_SIGNATURE_BYTES = 1024;
export const RECORD_BUCKET_BYTES = 4096;
export const MAX_RECORD_BYTES = 65_536;
const GCM_IV_BYTES = 12;
const CREDENTIAL_ID_RE = /^[A-Za-z0-9_-]{16,1366}$/;
const HANDLE_RE = /^[A-Za-z0-9_-]{8,64}$/;

export type GuestVaultErrorCode =
  | "guest_vault_input"
  | "guest_vault_no_stable_secret"
  | "guest_vault_wrong_passkey"
  | "guest_vault_locked"
  | "guest_vault_storage";

export class GuestVaultError extends Error {
  constructor(readonly code: GuestVaultErrorCode) {
    super(code);
    this.name = "GuestVaultError";
  }
}

export type GuestSecretInput = { credentialId: string; prf?: Uint8Array; signatures?: Uint8Array[] };
export type GuestSecretMethod = "prf" | "signature";
export type GuestSecrets = { scope: string; method: GuestSecretMethod; masterSeed: Uint8Array; skGuest: Uint8Array; storageKey: Uint8Array };

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let d = 0;
  for (let i = 0; i < a.byteLength; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function hkdf(ikm: Uint8Array, salt: string, info: Uint8Array): Uint8Array {
  const prk = extract(sha256, ikm, enc.encode(salt));
  try {
    return expand(sha256, prk, info, GUEST_SECRET_BYTES);
  } finally {
    wipe(prk);
  }
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Storage scope of one guest passkey (public; never the credential id itself). */
export function guestScope(credentialId: string): string {
  if (typeof credentialId !== "string" || !CREDENTIAL_ID_RE.test(credentialId)) throw new GuestVaultError("guest_vault_input");
  return hex(sha256(enc.encode(`rout.v1.guest.scope|${credentialId}`)));
}

/**
 * master_seed, SK_guest and the storage key from one passkey's output. The
 * input bytes stay the caller's (the worker wipes its request); the caller
 * wipes the three returned secrets.
 */
export function deriveGuestSecrets(input: GuestSecretInput): GuestSecrets {
  const scope = guestScope(input?.credentialId);
  let method: GuestSecretMethod;
  let ikm: Uint8Array;
  if (input.prf !== undefined) {
    if (!(input.prf instanceof Uint8Array) || input.prf.byteLength !== PRF_OUTPUT_BYTES) throw new GuestVaultError("guest_vault_input");
    method = "prf";
    ikm = input.prf;
  } else {
    const s = input.signatures;
    if (!Array.isArray(s) || s.length !== 2) throw new GuestVaultError("guest_vault_input");
    for (const x of s) {
      if (!(x instanceof Uint8Array) || x.byteLength < MIN_SIGNATURE_BYTES || x.byteLength > MAX_SIGNATURE_BYTES) throw new GuestVaultError("guest_vault_input");
    }
    if (!constantTimeEqual(s[0]!, s[1]!)) throw new GuestVaultError("guest_vault_no_stable_secret");
    method = "signature";
    ikm = s[0]!;
  }
  const idBytes = enc.encode(input.credentialId);
  const info = new Uint8Array(method.length + 1 + idBytes.byteLength);
  info.set(enc.encode(method));
  info.set(idBytes, method.length + 1);
  const masterSeed = hkdf(ikm, "rout.v1.guest.master-seed", info);
  const skGuest = hkdf(masterSeed, "rout.v1.guest.sk", enc.encode("sk-guest"));
  const storageKey = hkdf(masterSeed, "rout.v1.guest.storage", enc.encode("aes-256-gcm"));
  return { scope, method, masterSeed, skGuest, storageKey };
}

// ---- Padding and record encryption -------------------------------------------

/** u32 BE length || data || zeros, to the next multiple of 4096 bytes. */
export function padRecord(data: Uint8Array): Uint8Array {
  const total = Math.ceil((4 + data.byteLength) / RECORD_BUCKET_BYTES) * RECORD_BUCKET_BYTES;
  if (total > MAX_RECORD_BYTES) throw new GuestVaultError("guest_vault_input");
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, data.byteLength, false);
  out.set(data, 4);
  return out;
}

/** The data of a padded record as a fresh buffer; the padded input is wiped. */
export function unpadRecord(padded: Uint8Array): Uint8Array {
  try {
    if (padded.byteLength < 4 || padded.byteLength % RECORD_BUCKET_BYTES !== 0) throw new GuestVaultError("guest_vault_storage");
    const n = new DataView(padded.buffer, padded.byteOffset).getUint32(0, false);
    if (n > padded.byteLength - 4) throw new GuestVaultError("guest_vault_storage");
    for (let i = 4 + n; i < padded.byteLength; i++) if (padded[i] !== 0) throw new GuestVaultError("guest_vault_storage");
    return padded.slice(4, 4 + n);
  } finally {
    wipe(padded);
  }
}

export type GuestRecord = { v: 1; iv: Uint8Array; ct: Uint8Array };

export interface GuestRecordStorage {
  get(key: string): Promise<GuestRecord | undefined>;
  put(key: string, record: GuestRecord): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

const aad = (scope: string, name: string) => enc.encode(`rout.guest-vault.v1|${scope}|${name}`);

async function sealRecord(key: CryptoKey, scope: string, name: string, data: Uint8Array): Promise<GuestRecord> {
  const padded = padRecord(data);
  try {
    const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(scope, name) }, key, padded as BufferSource));
    return { v: 1, iv, ct };
  } finally {
    wipe(padded);
  }
}

/** Plaintext (caller wipes) or null when the record does not authenticate under this key and name. */
async function openRecord(key: CryptoKey, scope: string, name: string, r: unknown): Promise<Uint8Array | null> {
  if (!isRecord(r)) return null;
  let padded: Uint8Array;
  try {
    padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: r.iv as BufferSource, additionalData: aad(scope, name) }, key, r.ct as BufferSource));
  } catch {
    return null;
  }
  try {
    return unpadRecord(padded);
  } catch {
    return null;
  }
}

function isRecord(r: unknown): r is GuestRecord {
  if (typeof r !== "object" || r === null) return false;
  const x = r as Record<string, unknown>;
  return x.v === 1 && x.iv instanceof Uint8Array && x.iv.byteLength === GCM_IV_BYTES && x.ct instanceof Uint8Array
    && x.ct.byteLength >= RECORD_BUCKET_BYTES + 16 && x.ct.byteLength <= MAX_RECORD_BYTES + 16;
}

// ---- Booking encoding ---------------------------------------------------------

const BOOKING_VERSION = 1;

class Writer {
  private parts: Uint8Array[] = [];
  u8(v: number) { this.parts.push(Uint8Array.of(v)); }
  u16(v: number) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, false); this.parts.push(b); }
  u64(v: bigint) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, v, false); this.parts.push(b); }
  bytes(b: Uint8Array) { this.parts.push(b); }
  str(s: string) { const b = enc.encode(s); if (b.byteLength > 0xffff) throw new GuestVaultError("guest_vault_input"); this.u16(b.byteLength); this.parts.push(b); }
  done(): Uint8Array {
    const n = this.parts.reduce((a, p) => a + p.byteLength, 0);
    const out = new Uint8Array(n);
    let at = 0;
    for (const p of this.parts) { out.set(p, at); at += p.byteLength; }
    return out;
  }
}

class Reader {
  private at = 0;
  constructor(private readonly b: Uint8Array) {}
  private need(n: number) { if (this.at + n > this.b.byteLength) throw new GuestVaultError("guest_vault_storage"); }
  u8() { this.need(1); return this.b[this.at++]!; }
  u16() { this.need(2); const v = new DataView(this.b.buffer, this.b.byteOffset + this.at).getUint16(0, false); this.at += 2; return v; }
  u64() { this.need(8); const v = new DataView(this.b.buffer, this.b.byteOffset + this.at).getBigUint64(0, false); this.at += 8; return v; }
  bytes(n: number) { this.need(n); const v = this.b.slice(this.at, this.at + n); this.at += n; return v; }
  str() { return dec.decode(this.bytes(this.u16())); }
  end() { if (this.at !== this.b.byteLength) throw new GuestVaultError("guest_vault_storage"); }
}

/** Serialises a booking slot; the result holds secrets (caller wipes). */
export function encodeGuestBooking(s: GuestSlotData): Uint8Array {
  const w = new Writer();
  w.u8(BOOKING_VERSION);
  w.str(s.hostId);
  w.str(s.keyId);
  for (const b of [s.nullifier, s.bookingNonce, s.seed, s.proverBlind, s.pseudonym]) {
    if (b.byteLength !== 32) throw new GuestVaultError("guest_vault_input");
    w.bytes(b);
  }
  w.u64(BigInt(s.expiresAt));
  const c = s.credential;
  w.u8(c ? 1 : 0);
  if (c) {
    w.u64(BigInt(c.epoch));
    w.u64(c.slot);
    w.bytes(c.publicKey);
    w.bytes(c.signature);
    w.u8(c.messages.length);
    for (const m of c.messages) {
      w.u16(m.byteLength);
      w.bytes(m);
    }
  }
  return w.done();
}

export function decodeGuestBooking(b: Uint8Array): GuestSlotData {
  const r = new Reader(b);
  if (r.u8() !== BOOKING_VERSION) throw new GuestVaultError("guest_vault_storage");
  const hostId = r.str();
  const keyId = r.str();
  const [nullifier, bookingNonce, seed, proverBlind, pseudonym] = [r.bytes(32), r.bytes(32), r.bytes(32), r.bytes(32), r.bytes(32)];
  const expires = r.u64();
  if (expires > BigInt(Number.MAX_SAFE_INTEGER)) throw new GuestVaultError("guest_vault_storage");
  let credential: GuestSlotData["credential"] = null;
  if (r.u8() === 1) {
    const epoch = r.u64();
    if (epoch > BigInt(Number.MAX_SAFE_INTEGER)) throw new GuestVaultError("guest_vault_storage");
    const slot = r.u64();
    const publicKey = r.bytes(96);
    const signature = r.bytes(80);
    const n = r.u8();
    const messages: Uint8Array[] = [];
    for (let i = 0; i < n; i++) messages.push(r.bytes(r.u16()));
    credential = { keyId, epoch: Number(epoch), slot, messages, signature, publicKey };
  }
  r.end();
  return { hostId, keyId, nullifier, bookingNonce, seed, proverBlind, pseudonym, credential, expiresAt: Number(expires) };
}

export function wipeGuestBooking(s: GuestSlotData): void {
  wipe(s.nullifier, s.bookingNonce, s.seed, s.proverBlind, s.pseudonym);
  if (s.credential) wipe(s.credential.signature, ...s.credential.messages);
}

// ---- IndexedDB adapter ----------------------------------------------------------

function openGuestDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(GUEST_VAULT_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(GUEST_VAULT_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbTx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  if (typeof indexedDB === "undefined") throw new GuestVaultError("guest_vault_storage");
  const db = await openGuestDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(GUEST_VAULT_STORE, mode);
      const req = fn(t.objectStore(GUEST_VAULT_STORE));
      t.oncomplete = () => resolve(req.result);
      t.onabort = () => reject(t.error ?? new GuestVaultError("guest_vault_storage"));
      t.onerror = () => reject(t.error);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

/** IndexedDB "vault_guest_storage": only { v, iv, ct } values are ever written. */
export function indexedDbGuestStorage(): GuestRecordStorage {
  return {
    async get(key) {
      const v = await idbTx("readonly", (s) => s.get(key));
      return isRecord(v) ? { v: 1, iv: v.iv, ct: v.ct } : undefined;
    },
    async put(key, record) {
      if (!isRecord(record)) throw new GuestVaultError("guest_vault_input");
      await idbTx("readwrite", (s) => s.put({ v: 1, iv: record.iv, ct: record.ct }, key));
    },
    async delete(key) {
      await idbTx("readwrite", (s) => s.delete(key));
    },
    async keys(prefix) {
      const all = await idbTx("readonly", (s) => s.getAllKeys(IDBKeyRange.bound(prefix, `${prefix}\uffff`)));
      return all.filter((k): k is string => typeof k === "string" && k.startsWith(prefix));
    },
  };
}

// ---- The worker-held vault -------------------------------------------------------

type OpenVault = { scope: string; method: GuestSecretMethod; key: CryptoKey; skGuest: Uint8Array; storage: GuestRecordStorage };
export type UnlockedGuestVault = { scope: string; method: GuestSecretMethod; created: boolean; bookings: { handle: string; data: GuestSlotData }[]; dropped: number };

/**
 * The open guest vault of this worker: the non-extractable storage key and
 * SK_guest. lock() (also from secure.wipe) zero-fills SK_guest and forgets
 * the key; the stored ciphertext stays.
 */
export class GuestVault {
  private open: OpenVault | null = null;

  constructor(private readonly storageFactory: () => GuestRecordStorage = indexedDbGuestStorage) {}

  get isOpen(): boolean {
    return this.open !== null;
  }

  get scope(): string | null {
    return this.open?.scope ?? null;
  }

  /** A copy of SK_guest for one booking's pseudonym (the caller wipes it), or null when locked. */
  bookingSeed(): Uint8Array | null {
    return this.open ? this.open.skGuest.slice() : null;
  }

  async unlock(input: GuestSecretInput, now = Date.now()): Promise<UnlockedGuestVault> {
    this.lock();
    const s = deriveGuestSecrets(input);
    const seedBytes = new Uint8Array(64);
    const bookings: { handle: string; data: GuestSlotData }[] = [];
    try {
      let key: CryptoKey;
      try {
        key = await crypto.subtle.importKey("raw", s.storageKey as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
      } finally {
        wipe(s.storageKey);
      }
      const storage = this.storageFactory();
      seedBytes.set(s.masterSeed);
      seedBytes.set(s.skGuest, 32);
      let created = false;
      const stored = await storage.get(`${s.scope}|seed`).catch(() => {
        throw new GuestVaultError("guest_vault_storage");
      });
      if (stored) {
        const opened = await openRecord(key, s.scope, "seed", stored);
        const same = opened !== null && constantTimeEqual(opened, seedBytes);
        wipe(opened);
        if (!same) throw new GuestVaultError("guest_vault_wrong_passkey");
      } else {
        await storage.put(`${s.scope}|seed`, await sealRecord(key, s.scope, "seed", seedBytes)).catch(() => {
          throw new GuestVaultError("guest_vault_storage");
        });
        created = true;
      }
      let dropped = 0;
      const prefix = `${s.scope}|booking:`;
      for (const k of await storage.keys(prefix)) {
        const handle = k.slice(prefix.length);
        const plain = HANDLE_RE.test(handle) ? await openRecord(key, s.scope, `booking:${handle}`, await storage.get(k)) : null;
        let data: GuestSlotData | null = null;
        if (plain) {
          try {
            data = decodeGuestBooking(plain);
          } catch {
            data = null;
          } finally {
            wipe(plain);
          }
        }
        if (!data || data.expiresAt <= now) {
          if (data) wipeGuestBooking(data);
          await storage.delete(k);
          dropped++;
          continue;
        }
        bookings.push({ handle, data });
      }
      this.open = { scope: s.scope, method: s.method, key, skGuest: s.skGuest, storage };
      return { scope: s.scope, method: s.method, created, bookings, dropped };
    } catch (e) {
      wipe(s.skGuest);
      for (const b of bookings) wipeGuestBooking(b.data);
      throw e;
    } finally {
      wipe(s.storageKey, s.masterSeed, seedBytes);
    }
  }

  private live(): OpenVault {
    if (!this.open) throw new GuestVaultError("guest_vault_locked");
    return this.open;
  }

  /** Stores (or replaces) one booking as ciphertext. */
  async putBooking(handle: string, data: GuestSlotData): Promise<void> {
    const v = this.live();
    if (!HANDLE_RE.test(handle)) throw new GuestVaultError("guest_vault_input");
    const plain = encodeGuestBooking(data);
    try {
      await v.storage.put(`${v.scope}|booking:${handle}`, await sealRecord(v.key, v.scope, `booking:${handle}`, plain));
    } finally {
      wipe(plain);
    }
  }

  async deleteBooking(handle: string): Promise<void> {
    const v = this.live();
    await v.storage.delete(`${v.scope}|booking:${handle}`);
  }

  /** Zero-fills SK_guest and drops the key. Returns whether a vault was open. */
  lock(): boolean {
    if (!this.open) return false;
    wipe(this.open.skGuest);
    this.open = null;
    return true;
  }
}

/** The guest vault of this worker (locked by secure.wipe). */
export const guestVault = new GuestVault();
