/**
 * Stap 8: encrypted persistence of hybrid PQ ratchet sessions (pq-ratchet.ts)
 * so a session survives a page reload. Lives only in the crypto worker.
 *
 * Storage: IndexedDB database "vault_ratchet_sessions", object store
 * "sessions", key `${userId}|${sessionId}`, value always { v: 1, iv, ct }.
 *
 * Key: HKDF-SHA256(ikm = PRF master seed || host_device_key seed,
 *                  salt = "rout.pqr.vault.v1", info = "rout.pqr.vault.member|" userId)
 *      → non-extractable AES-256-GCM key. Without a device key (guest):
 *      ikm = PRF seed, info = "rout.pqr.vault.guest|" userId. The two roles
 *      never derive the same key.
 * Record: AES-256-GCM(key, iv 12 random, AAD = "rout.pqr.session.v1|" userId "|" sessionId,
 *         u32 BE length || state (9888) || zeros) padded to a fixed 12 KiB
 *         bucket, so every record has the same size.
 * close: the record is first overwritten with an all-zero record of the same
 *        size, then deleted. Every owned plaintext/ikm buffer is zero-filled.
 */
import { wipe } from "@/lib/crypto/wipe";
import { PQR_STATE_BYTES } from "./pq-ratchet";

export const PQ_VAULT_DB = "vault_ratchet_sessions";
export const PQ_VAULT_STORE = "sessions";
export const PQ_VAULT_BUCKET_BYTES = 12 * 1024;
export const PQ_VAULT_SEED_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SALT = new TextEncoder().encode("rout.pqr.vault.v1");
const enc = new TextEncoder();
const SESSION_ID = /^pqs_[0-9a-f]{32}$/;
const OWNER = /^[A-Za-z0-9._:-]{1,200}$/;

export type PqVaultRecord = { v: 1; iv: Uint8Array; ct: Uint8Array };
export interface PqVaultStorage {
  get(key: string): Promise<PqVaultRecord | undefined>;
  put(key: string, record: PqVaultRecord): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

export class PqVaultError extends Error {
  constructor(readonly code: "pq_vault_locked" | "pq_vault_input" | "pq_vault_storage" | "pq_vault_decrypt") {
    super(code);
    this.name = "PqVaultError";
  }
}

const isRecord = (v: unknown): v is PqVaultRecord =>
  typeof v === "object" && v !== null && (v as PqVaultRecord).v === 1
  && (v as PqVaultRecord).iv instanceof Uint8Array && (v as PqVaultRecord).ct instanceof Uint8Array;

const recordKey = (owner: string, sessionId: string) => `${owner}|${sessionId}`;
const aad = (owner: string, sessionId: string) => enc.encode(`rout.pqr.session.v1|${owner}|${sessionId}`);

function checkIds(owner: unknown, sessionId?: unknown) {
  if (typeof owner !== "string" || !OWNER.test(owner)) throw new PqVaultError("pq_vault_input");
  if (sessionId !== undefined && (typeof sessionId !== "string" || !SESSION_ID.test(sessionId))) throw new PqVaultError("pq_vault_input");
}

const ab = (b: Uint8Array): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

/** Derives the non-extractable vault key. Wipes every intermediate it owns. */
export async function derivePqVaultKey(owner: string, prfSeed: Uint8Array, deviceSeed: Uint8Array | null): Promise<CryptoKey> {
  checkIds(owner);
  if (!(prfSeed instanceof Uint8Array) || prfSeed.byteLength !== PQ_VAULT_SEED_BYTES) throw new PqVaultError("pq_vault_input");
  if (deviceSeed !== null && (!(deviceSeed instanceof Uint8Array) || deviceSeed.byteLength !== PQ_VAULT_SEED_BYTES)) throw new PqVaultError("pq_vault_input");
  const ikm = new Uint8Array(prfSeed.byteLength + (deviceSeed?.byteLength ?? 0));
  ikm.set(prfSeed, 0);
  if (deviceSeed) ikm.set(deviceSeed, prfSeed.byteLength);
  const info = enc.encode(`rout.pqr.vault.${deviceSeed ? "member" : "guest"}|${owner}`);
  const ikmBuf = ab(ikm);
  try {
    const base = await crypto.subtle.importKey("raw", ikmBuf, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: SALT, info },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    wipe(ikm);
    new Uint8Array(ikmBuf).fill(0);
  }
}

export class PqSessionVault {
  private key: CryptoKey | null = null;
  private owner: string | null = null;

  constructor(private readonly storage: () => PqVaultStorage = indexedDbPqVaultStorage) {}

  get isOpen(): boolean {
    return this.key !== null;
  }

  isOpenFor(owner: string): boolean {
    return this.key !== null && this.owner === owner;
  }

  /** Seeds are consumed: the caller's buffers are zero-filled. */
  async unlock(owner: string, prfSeed: Uint8Array, deviceSeed: Uint8Array | null): Promise<void> {
    try {
      const k = await derivePqVaultKey(owner, prfSeed, deviceSeed);
      this.key = k;
      this.owner = owner;
    } finally {
      wipe(prfSeed);
      if (deviceSeed) wipe(deviceSeed);
    }
  }

  lock(): boolean {
    const was = this.key !== null;
    this.key = null;
    this.owner = null;
    return was;
  }

  private need(owner: string): CryptoKey {
    if (!this.key || this.owner !== owner) throw new PqVaultError("pq_vault_locked");
    return this.key;
  }

  /** Encrypts and writes one state; resolves only after the write committed. */
  async save(owner: string, sessionId: string, state: Uint8Array): Promise<void> {
    checkIds(owner, sessionId);
    if (!(state instanceof Uint8Array) || state.byteLength !== PQR_STATE_BYTES) throw new PqVaultError("pq_vault_input");
    const key = this.need(owner);
    const padded = new Uint8Array(PQ_VAULT_BUCKET_BYTES);
    new DataView(padded.buffer).setUint32(0, state.byteLength, false);
    padded.set(state, 4);
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    let ct: Uint8Array;
    try {
      ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(owner, sessionId) }, key, padded));
    } finally {
      wipe(padded);
    }
    try {
      await this.storage().put(recordKey(owner, sessionId), { v: 1, iv, ct });
    } catch {
      throw new PqVaultError("pq_vault_storage");
    }
  }

  /** Decrypts one record; the returned state is owned by the caller. */
  async load(owner: string, sessionId: string): Promise<Uint8Array | null> {
    checkIds(owner, sessionId);
    const key = this.need(owner);
    let rec: PqVaultRecord | undefined;
    try {
      rec = await this.storage().get(recordKey(owner, sessionId));
    } catch {
      throw new PqVaultError("pq_vault_storage");
    }
    if (!rec) return null;
    if (!isRecord(rec) || rec.iv.byteLength !== IV_BYTES || rec.ct.byteLength !== PQ_VAULT_BUCKET_BYTES + TAG_BYTES) throw new PqVaultError("pq_vault_decrypt");
    let padded: Uint8Array;
    try {
      padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ab(rec.iv), additionalData: aad(owner, sessionId) }, key, ab(rec.ct)));
    } catch {
      throw new PqVaultError("pq_vault_decrypt");
    }
    try {
      const n = new DataView(padded.buffer).getUint32(0, false);
      if (n !== PQR_STATE_BYTES) throw new PqVaultError("pq_vault_decrypt");
      for (let i = 4 + n; i < padded.byteLength; i++) if (padded[i] !== 0) throw new PqVaultError("pq_vault_decrypt");
      return padded.slice(4, 4 + n);
    } finally {
      wipe(padded);
    }
  }

  async sessionIds(owner: string): Promise<string[]> {
    checkIds(owner);
    this.need(owner);
    const prefix = `${owner}|`;
    try {
      return (await this.storage().keys(prefix)).map((k) => k.slice(prefix.length)).filter((id) => SESSION_ID.test(id));
    } catch {
      throw new PqVaultError("pq_vault_storage");
    }
  }

  /** Overwrites the record with zeros of the same size, then deletes it. Works while locked. */
  async erase(owner: string, sessionId: string): Promise<boolean> {
    checkIds(owner, sessionId);
    const k = recordKey(owner, sessionId);
    try {
      const s = this.storage();
      const existing = await s.get(k);
      if (!existing) return false;
      await s.put(k, { v: 1, iv: new Uint8Array(IV_BYTES), ct: new Uint8Array(PQ_VAULT_BUCKET_BYTES + TAG_BYTES) });
      await s.delete(k);
      return true;
    } catch {
      throw new PqVaultError("pq_vault_storage");
    }
  }
}

// ---- IndexedDB adapter ----------------------------------------------------------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(PQ_VAULT_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(PQ_VAULT_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  if (typeof indexedDB === "undefined") throw new PqVaultError("pq_vault_storage");
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(PQ_VAULT_STORE, mode);
      const req = fn(t.objectStore(PQ_VAULT_STORE));
      t.oncomplete = () => resolve(req.result);
      t.onabort = () => reject(t.error ?? new PqVaultError("pq_vault_storage"));
      t.onerror = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

/** IndexedDB "vault_ratchet_sessions": only { v, iv, ct } values are ever written. */
export function indexedDbPqVaultStorage(): PqVaultStorage {
  return {
    async get(key) {
      const v = await tx("readonly", (s) => s.get(key));
      return isRecord(v) ? { v: 1, iv: v.iv, ct: v.ct } : undefined;
    },
    async put(key, record) {
      if (!isRecord(record)) throw new PqVaultError("pq_vault_input");
      await tx("readwrite", (s) => s.put({ v: 1, iv: record.iv, ct: record.ct }, key));
    },
    async delete(key) {
      await tx("readwrite", (s) => s.delete(key));
    },
    async keys(prefix) {
      const all = await tx("readonly", (s) => s.getAllKeys(IDBKeyRange.bound(prefix, `${prefix}\uffff`)));
      return all.filter((k): k is string => typeof k === "string" && k.startsWith(prefix));
    },
  };
}

export const pqSessionVault = new PqSessionVault();
