// @vitest-environment node
/**
 * Stap 7g guest vault: WebAuthn PRF (and the guarded signature fallback) →
 * master seed, SK_guest and an AES-256-GCM key; bookings in IndexedDB
 * "vault_guest_storage" only as ciphertext; a reload restores a booking whose
 * presentation still verifies. Runs the committed, pinned rout-zk engine.
 */
import "fake-indexeddb/auto";
import { randomBytes } from "@noble/hashes/utils.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { guestBookings } from "./anon-booking";
import { type EpochLink, type HostKeyAnchor } from "./forward-secure";
import {
  deriveGuestSecrets,
  GUEST_VAULT_DB,
  GUEST_VAULT_STORE,
  GuestVault,
  GuestVaultError,
  padRecord,
  RECORD_BUCKET_BYTES,
  unpadRecord,
  type GuestRecordStorage,
} from "./guest-vault";
import { GUEST_FALLBACK_CHALLENGE, GUEST_PRF_SALT } from "./guest-vault-constants";
import { lastZkMemoryForTest } from "./zk-engine";

const CRED = "Q3JlZGVudGlhbElkLWd1ZXN0LTAx";
const CRED2 = "Q3JlZGVudGlhbElkLWd1ZXN0LTAy";
const HOST = "00000000-0000-4000-8000-0000000007f1";
const KEY = `hk_${"ab".repeat(32)}`;
const SLOT = 29_400_000;
const enc = new TextEncoder();
const SERVICE = () => [enc.encode("service:massage-60")];

async function ok<T>(p: Promise<{ ok: boolean; result?: unknown; code?: string }>): Promise<T> {
  const r = await p;
  if (!r.ok) throw new Error(String(r.code));
  return r.result as T;
}
const code = async (p: Promise<{ ok: boolean; code?: string }>) => (await p).code;

/** Every raw key and value stored in vault_guest_storage, read straight from IndexedDB. */
async function dumpGuestDb(): Promise<{ key: string; value: Record<string, unknown> }[]> {
  const db = await new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open(GUEST_VAULT_DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(GUEST_VAULT_STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  try {
    const t = db.transaction(GUEST_VAULT_STORE, "readonly").objectStore(GUEST_VAULT_STORE);
    const [keys, values] = await Promise.all([
      new Promise<IDBValidKey[]>((res) => { const r = t.getAllKeys(); r.onsuccess = () => res(r.result); }),
      new Promise<unknown[]>((res) => { const r = t.getAll(); r.onsuccess = () => res(r.result); }),
    ]);
    return keys.map((k, i) => ({ key: String(k), value: values[i] as Record<string, unknown> }));
  } finally {
    db.close();
  }
}
const contains = (hay: Uint8Array, needle: Uint8Array) => Buffer.from(hay).includes(Buffer.from(needle));

describe("guest secret derivation", () => {
  it("PRF output → deterministic master seed, SK_guest and storage key, bound to the credential", () => {
    const prf = randomBytes(32);
    const a = deriveGuestSecrets({ credentialId: CRED, prf });
    const b = deriveGuestSecrets({ credentialId: CRED, prf });
    expect(a.method).toBe("prf");
    expect(a.masterSeed).toEqual(b.masterSeed);
    expect(a.skGuest).toEqual(b.skGuest);
    expect(a.storageKey).toEqual(b.storageKey);
    expect(new Set([a.masterSeed, a.skGuest, a.storageKey].map((x) => Buffer.from(x).toString("hex"))).size).toBe(3);
    expect(deriveGuestSecrets({ credentialId: CRED2, prf }).masterSeed).not.toEqual(a.masterSeed);
    expect(deriveGuestSecrets({ credentialId: CRED, prf: randomBytes(32) }).masterSeed).not.toEqual(a.masterSeed);
    expect(a.scope).toMatch(/^[0-9a-f]{64}$/);
    expect(a.scope).not.toContain(CRED);
  });

  it("fallback: HKDF over the assertion signature only when two assertions gave identical bytes", () => {
    const sig = randomBytes(72);
    const s = deriveGuestSecrets({ credentialId: CRED, signatures: [sig, sig.slice()] });
    expect(s.method).toBe("signature");
    expect(s.masterSeed).toEqual(deriveGuestSecrets({ credentialId: CRED, signatures: [sig, sig.slice()] }).masterSeed);
    // Same bytes as PRF output give a different seed (method is bound in).
    expect(deriveGuestSecrets({ credentialId: CRED, prf: sig.slice(0, 32) }).masterSeed).not.toEqual(deriveGuestSecrets({ credentialId: CRED, signatures: [sig.slice(0, 64), sig.slice(0, 64)] }).masterSeed);
    // A randomised (ECDSA) signer: refused, never a silently changing seed.
    expect(() => deriveGuestSecrets({ credentialId: CRED, signatures: [sig, randomBytes(72)] })).toThrow(expect.objectContaining({ code: "guest_vault_no_stable_secret" }));
    expect(() => deriveGuestSecrets({ credentialId: CRED, signatures: [sig] })).toThrow(GuestVaultError);
    expect(() => deriveGuestSecrets({ credentialId: CRED, signatures: [randomBytes(10), randomBytes(10)] })).toThrow(GuestVaultError);
    expect(() => deriveGuestSecrets({ credentialId: CRED, prf: randomBytes(31) })).toThrow(GuestVaultError);
    expect(() => deriveGuestSecrets({ credentialId: "short", prf: randomBytes(32) })).toThrow(GuestVaultError);
  });

  it("PRF salt and fallback challenge are fixed 32-byte values of their own", () => {
    expect(GUEST_PRF_SALT).toHaveLength(32);
    expect(GUEST_FALLBACK_CHALLENGE).toHaveLength(32);
    expect(GUEST_PRF_SALT).not.toEqual(GUEST_FALLBACK_CHALLENGE);
  });

  it("pads every record to a multiple of 4096 bytes and refuses tampered padding", () => {
    expect(padRecord(new Uint8Array(10))).toHaveLength(RECORD_BUCKET_BYTES);
    expect(padRecord(new Uint8Array(RECORD_BUCKET_BYTES - 4))).toHaveLength(RECORD_BUCKET_BYTES);
    expect(padRecord(new Uint8Array(RECORD_BUCKET_BYTES - 3))).toHaveLength(2 * RECORD_BUCKET_BYTES);
    const p = padRecord(Uint8Array.of(1, 2, 3));
    expect(unpadRecord(p.slice())).toEqual(Uint8Array.of(1, 2, 3));
    const bad = p.slice();
    bad[100] = 1;
    expect(() => unpadRecord(bad)).toThrow();
  });
});

describe("GuestVault storage", () => {
  const memory = () => {
    const m = new Map<string, { v: 1; iv: Uint8Array; ct: Uint8Array }>();
    const s: GuestRecordStorage = {
      get: async (k) => m.get(k),
      put: async (k, r) => void m.set(k, r),
      delete: async (k) => void m.delete(k),
      keys: async (p) => [...m.keys()].filter((k) => k.startsWith(p)),
    };
    return { m, s };
  };

  it("opens only with the same passkey output; lock zero-fills SK_guest", async () => {
    const { s } = memory();
    const v = new GuestVault(() => s);
    const prf = randomBytes(32);
    expect((await v.unlock({ credentialId: CRED, prf: prf.slice() })).created).toBe(true);
    const held = (v as unknown as { open: { skGuest: Uint8Array } }).open.skGuest;
    expect(held.some((b) => b !== 0)).toBe(true);
    expect(v.lock()).toBe(true);
    expect(held.every((b) => b === 0)).toBe(true);
    expect(v.bookingSeed()).toBeNull();
    expect((await v.unlock({ credentialId: CRED, prf: prf.slice() })).created).toBe(false);
    v.lock();
    await expect(v.unlock({ credentialId: CRED, prf: randomBytes(32) })).rejects.toMatchObject({ code: "guest_vault_wrong_passkey" });
    expect(v.isOpen).toBe(false);
  });
});

describe("guest vault through the crypto worker (pinned rout-zk)", () => {
  const trap: string[] = [];
  beforeAll(async () => {
    // Any touch of localStorage / sessionStorage during these flows is recorded and fails the test.
    for (const name of ["localStorage", "sessionStorage"]) {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        get() {
          trap.push(name);
          return undefined;
        },
      });
    }
    const { handle } = await ok<{ handle: string }>(runEnclaveOp("masterKey.generate", {}));
    await ok(runEnclaveOp("masterKey.commitPending", { handle, userId: HOST }));
    await ok(runEnclaveOp("host_key.init", { userId: HOST, keyId: KEY }));
    await ok(runEnclaveOp("host_key.advance_epoch", { userId: HOST, keyId: KEY, toEpoch: 20_772 }));
  }, 120_000);
  afterEach(() => expect(trap).toEqual([]));

  it("source never names localStorage or sessionStorage", () => {
    for (const f of ["guest-vault.ts", "guest-vault-constants.ts", "guest-passkey.ts"]) {
      const src = readFileSync(join(__dirname, f), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
      expect(src).not.toMatch(/localStorage|sessionStorage/);
    }
  });

  it("a booking survives a reload only as AES-256-GCM ciphertext and still presents", async () => {
    const prf = randomBytes(32);
    const opened = await ok<{ created: boolean; restored: unknown[]; method: string }>(runEnclaveOp("guest_vault.unlock", { credentialId: CRED, prf: prf.slice() }));
    expect(opened).toMatchObject({ created: true, restored: [], method: "prf" });

    const g = await ok<{ handle: string; commitmentWithProof: Uint8Array; persisted: boolean }>(runEnclaveOp("anon_guest.begin", { hostId: KEY, keyId: KEY }));
    expect(g.persisted).toBe(true);
    const cred = await ok<{ epoch: number; signature: Uint8Array }>(runEnclaveOp("host_key.sign_slot_credential", {
      userId: HOST, keyId: KEY, epoch: 20_772, slot: SLOT, messages: SERVICE(), commitmentWithProof: g.commitmentWithProof.slice(),
    }));
    const chain = await ok<{ anchor: HostKeyAnchor; links: EpochLink[] }>(runEnclaveOp("host_key.chain", { userId: HOST, keyId: KEY }));
    const copyChain = () => ({ anchor: { keyId: chain.anchor.keyId, publicKey: chain.anchor.publicKey.slice() }, links: chain.links.map((l) => ({ ...l, publicKey: l.publicKey.slice(), signature: l.signature.slice() })) });
    expect(await ok(runEnclaveOp("anon_guest.accept", { handle: g.handle, ...copyChain(), epoch: cred.epoch, slot: SLOT, messages: SERVICE(), signature: cred.signature.slice() }))).toEqual({ valid: true, persisted: true });

    // What is on disk: only { v, iv, ct }, padded, and none of the secrets in any key or value.
    const slot = guestBookings.exportSlot(g.handle)!;
    const secrets = [slot.nullifier, slot.bookingNonce, slot.proverBlind, slot.pseudonym, slot.seed, prf];
    const rows = await dumpGuestDb();
    expect(rows.map((r) => r.key.split("|")[1]).sort()).toEqual([`booking:${g.handle}`, "seed"]);
    for (const r of rows) {
      expect(Object.keys(r.value).sort()).toEqual(["ct", "iv", "v"]);
      const ct = r.value.ct as Uint8Array;
      expect((ct.byteLength - 16) % RECORD_BUCKET_BYTES).toBe(0);
      for (const s of secrets) {
        expect(contains(ct, s)).toBe(false);
        expect(contains(enc.encode(r.key), s)).toBe(false);
      }
      expect(r.key).not.toContain(CRED);
    }
    // The pseudonym seed is SK_guest of this passkey, not random.
    expect(slot.seed).toEqual(deriveGuestSecrets({ credentialId: CRED, prf: prf.slice() }).skGuest);

    // "Reload": lock wipes everything in memory; unlocking with the same passkey restores it.
    expect(await ok(runEnclaveOp("guest_vault.lock", {}))).toMatchObject({ locked: true });
    expect(guestBookings.get(g.handle)).toBeUndefined();
    expect(slot.nullifier.some((b) => b !== 0)).toBe(true); // our export copy, not the worker's
    expect(await code(runEnclaveOp("guest_vault.unlock", { credentialId: CRED, prf: randomBytes(32) }))).toBe("decrypt_failed");
    const back = await ok<{ restored: { handle: string; accepted: boolean }[] }>(runEnclaveOp("guest_vault.unlock", { credentialId: CRED, prf: prf.slice() }));
    expect(back.restored).toEqual([expect.objectContaining({ handle: g.handle, accepted: true, keyId: KEY })]);

    const challenge = randomBytes(32);
    const p = await ok<{ presentation: Uint8Array; nullifier: Uint8Array; epoch: number; messages: Uint8Array[] }>(
      runEnclaveOp("anon_guest.present", { handle: g.handle, challenge: challenge.slice(), windowStart: SLOT - 15, windowEnd: SLOT + 15 }));
    expect(lastZkMemoryForTest()!.every((b) => b === 0)).toBe(true);
    expect(p.nullifier).toEqual(slot.nullifier);
    const valid = await ok<{ valid: boolean }>(runEnclaveOp("anon_host.verify_presentation", {
      ...copyChain(), epoch: p.epoch, presentation: p.presentation.slice(), messages: p.messages.map((m) => m.slice()),
      nullifier: p.nullifier.slice(), challenge: challenge.slice(), windowStart: SLOT - 15, windowEnd: SLOT + 15,
    }));
    expect(valid).toEqual({ valid: true });

    // Discard removes the ciphertext too; secure.wipe locks the vault.
    expect(await ok(runEnclaveOp("anon_guest.discard", { handle: g.handle }))).toEqual({ discarded: true });
    expect((await dumpGuestDb()).map((r) => r.key.split("|")[1])).toEqual(["seed"]);
    await ok(runEnclaveOp("secure.wipe", {}));
    expect(await ok<{ persisted: boolean }>(runEnclaveOp("anon_guest.begin", { hostId: KEY, keyId: KEY })).then((r) => r.persisted)).toBe(false);
  }, 120_000);

  it("refuses a non-deterministic fallback signer in the worker", async () => {
    expect(await code(runEnclaveOp("guest_vault.unlock", { credentialId: CRED2, signatures: [randomBytes(72), randomBytes(72)] }))).toBe("no_stable_secret");
  });
});
