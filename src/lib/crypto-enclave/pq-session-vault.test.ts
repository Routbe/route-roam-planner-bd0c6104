// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { PqSessionVault, PqVaultError, PQ_VAULT_BUCKET_BYTES, type PqVaultRecord, type PqVaultStorage } from "./pq-session-vault";
import { PQR_STATE_BYTES } from "./pq-ratchet";

const U = "00000000-0000-4000-8000-0000000000v1".replace("v1", "c1");
const S1 = `pqs_${"a".repeat(32)}`;
const S2 = `pqs_${"b".repeat(32)}`;
const seed = (x: number) => new Uint8Array(32).fill(x);
const state = (x: number) => new Uint8Array(PQR_STATE_BYTES).fill(x);

function memStorage() {
  const m = new Map<string, PqVaultRecord>();
  const writes: { key: string; record: PqVaultRecord }[] = [];
  const s: PqVaultStorage = {
    async get(k) { return m.get(k); },
    async put(k, r) { writes.push({ key: k, record: { v: 1, iv: r.iv.slice(), ct: r.ct.slice() } }); m.set(k, r); },
    async delete(k) { m.delete(k); },
    async keys(p) { return [...m.keys()].filter((k) => k.startsWith(p)); },
  };
  return { m, writes, s };
}

describe("pq-session-vault (Stap 8): encrypted IndexedDB session records", () => {
  it("saves fixed-size records, overwrites, and restores after a simulated reload", async () => {
    const vault = new PqSessionVault();
    await vault.unlock(U, seed(1), seed(2));
    await vault.save(U, S1, state(7));
    await vault.save(U, S1, state(9)); // overwrite
    await vault.save(U, S2, state(3));
    // Reload: a fresh vault object, same seeds.
    const after = new PqSessionVault();
    await after.unlock(U, seed(1), seed(2));
    expect((await after.sessionIds(U)).sort()).toEqual([S1, S2]);
    expect((await after.load(U, S1))!.every((b) => b === 9)).toBe(true);
    expect((await after.load(U, S2))!.every((b) => b === 3)).toBe(true);
    await after.erase(U, S1);
    await after.erase(U, S2);
  });

  it("records are AES-GCM ciphertext of one fixed bucket, bound to member and session", async () => {
    const { s, m } = memStorage();
    const vault = new PqSessionVault(() => s);
    await vault.unlock(U, seed(1), seed(2));
    await vault.save(U, S1, state(0x41));
    const rec = m.get(`${U}|${S1}`)!;
    expect(rec.ct.byteLength).toBe(PQ_VAULT_BUCKET_BYTES + 16);
    expect(Buffer.from(rec.ct).includes(Buffer.from(state(0x41).subarray(0, 64)))).toBe(false);
    // Moved to another session id: refused.
    m.set(`${U}|${S2}`, rec);
    await expect(vault.load(U, S2)).rejects.toBeInstanceOf(PqVaultError);
    // Another seed (or a guest key without device seed) does not open it.
    const other = new PqSessionVault(() => s);
    await other.unlock(U, seed(1), null);
    await expect(other.load(U, S1)).rejects.toBeInstanceOf(PqVaultError);
  });

  it("close: overwrites the record with zeros of the same size, then deletes it; seeds are wiped", async () => {
    const { s, m, writes } = memStorage();
    const vault = new PqSessionVault(() => s);
    const prf = seed(5);
    const dev = seed(6);
    await vault.unlock(U, prf, dev);
    expect(prf.every((b) => b === 0) && dev.every((b) => b === 0)).toBe(true);
    await vault.save(U, S1, state(1));
    const size = m.get(`${U}|${S1}`)!.ct.byteLength;
    expect(await vault.erase(U, S1)).toBe(true);
    const last = writes[writes.length - 1]!;
    expect(last.record.ct.byteLength).toBe(size);
    expect(last.record.ct.every((b) => b === 0) && last.record.iv.every((b) => b === 0)).toBe(true);
    expect(m.has(`${U}|${S1}`)).toBe(false);
    expect(await vault.erase(U, S1)).toBe(false);
  });

  it("locked or another member: no save, no load", async () => {
    const vault = new PqSessionVault(() => memStorage().s);
    await expect(vault.save(U, S1, state(1))).rejects.toMatchObject({ code: "pq_vault_locked" });
    await vault.unlock(U, seed(1), seed(2));
    await expect(vault.load("00000000-0000-4000-8000-0000000000d1", S1)).rejects.toMatchObject({ code: "pq_vault_locked" });
    vault.lock();
    await expect(vault.load(U, S1)).rejects.toMatchObject({ code: "pq_vault_locked" });
  });
});
