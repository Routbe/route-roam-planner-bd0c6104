// @vitest-environment node
/**
 * Stap 7f end to end: one complete anonymous guest booking through the real
 * crypto-worker ops (locally built rout-zk, ABI 5) and db/0273 on a
 * PGlite replay of db/. Nothing touches Neon; CODE_SCHEMA_LEVEL stays 0272.
 * Skipped unless ROUT_ZK_DEV_WASM points at a local build
 * (wasm/rout-zk/build.sh --dev /tmp/rout_zk.wasm), because the committed pin
 * is still null and the loader refuses unpinned bytes.
 */
import "fake-indexeddb/auto";
import { PGlite } from "@electric-sql/pglite";
import { randomBytes } from "@noble/hashes/utils.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const dev = vi.hoisted(() => {
  const path = process.env.ROUT_ZK_DEV_WASM;
  if (!path) return null;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const bytes = (require("node:fs") as typeof import("node:fs")).readFileSync(path);
  return { base64: bytes.toString("base64"), sha384: createHash("sha384").update(bytes).digest("hex") };
});
vi.mock("@/lib/crypto-enclave/zk-wasm-pin", () => ({ ROUT_ZK_WASM_SHA384: dev?.sha384 ?? null }));
vi.mock("@/lib/crypto-enclave/zk-wasm-bytes", () => ({ ROUT_ZK_WASM_BASE64: dev?.base64 ?? null }));

import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { migrationDefinerGuardSql } from "../../scripts/security-definer-policy";
import { runEnclaveOp } from "@/lib/crypto-enclave/enclave-core";
import { hostKeys, HSK_ENVELOPE_BYTES, type EpochLink, type HostKeyAnchor } from "@/lib/crypto-enclave/forward-secure";
import { ledgerEventsFromJson, verifyAnonLedger } from "@/lib/crypto-enclave/anon-ledger";
import { SMT_DEPTH, SMT_NODE_BYTES, smtEmptyPath, type SignedRoot } from "@/lib/crypto-enclave/smt";
import { lastZkMemoryForTest } from "@/lib/crypto-enclave/zk-engine";

const ROOT = join(__dirname, "..", "..");
const SQL = readFileSync(join(ROOT, "db", "0273_anonymous_booking_engine.sql"), "utf8");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (h: string) => new Uint8Array(Buffer.from(h.replace(/^\\x/, ""), "hex"));
const enc = new TextEncoder();
const allZero = () => lastZkMemoryForTest()!.every((b) => b === 0);
const SLOT = 29_400_000; // unix minutes of the booked slot
const SERVICE = [enc.encode("service:massage-60")];

async function ok<T>(p: Promise<{ ok: boolean; result?: unknown; code?: string }>): Promise<T> {
  const r = await p;
  if (!r.ok) throw new Error(String(r.code));
  return r.result as T;
}
const code = async (p: Promise<{ ok: boolean; code?: string }>) => (await p).code;

/** The untrusted SMT node store (the database's role later), as plain bytes. */
class Store {
  nodes = new Map<string, Uint8Array>();
  constructor(readonly empty: Uint8Array) {}
  private prefix(n: Uint8Array, h: number) {
    const p = n.slice();
    for (let i = 0; i < h; i++) p[31 - (i >> 3)]! &= ~(1 << (i & 7));
    return p;
  }
  private get(h: number, p: Uint8Array) {
    return this.nodes.get(`${h}:${hex(p)}`) ?? this.empty.subarray(h * SMT_NODE_BYTES, (h + 1) * SMT_NODE_BYTES);
  }
  siblings(n: Uint8Array) {
    const out = new Uint8Array(SMT_DEPTH * SMT_NODE_BYTES);
    for (let h = 0; h < SMT_DEPTH; h++) {
      const p = this.prefix(n, h);
      p[31 - (h >> 3)]! ^= 1 << (h & 7);
      out.set(this.get(h, p), h * SMT_NODE_BYTES);
    }
    return out;
  }
  apply(n: Uint8Array, path: Uint8Array) {
    for (let h = 0; h <= SMT_DEPTH; h++) this.nodes.set(`${h}:${hex(this.prefix(n, h))}`, path.slice(h * SMT_NODE_BYTES, (h + 1) * SMT_NODE_BYTES));
  }
}

describe.skipIf(!dev)("anonymous guest booking end to end (worker + 0273 on PGlite)", () => {
  let db: PGlite;
  const HOST = "00000000-0000-4000-8000-0000000007f1";
  const AUTH = "00000000-0000-4000-9000-0000000007f1";

  const call = async <T = { ok: boolean; why: string; epoch: number | null; ver: number | null }>(userId: string, query: string, params: unknown[] = []): Promise<T> => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
      const r = await db.query<{ a: T }>(query, params);
      await db.exec("commit");
      return r.rows[0]!.a;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const stepUp = async () => {
    const p = crypto.randomUUID();
    await db.query("insert into vault_enclave.step_up_proofs (proof_id, user_id, method, verified_at) values ($1, $2, 'passkey', clock_timestamp())", [p, HOST]);
    return p;
  };
  /** The public chain exactly as an anonymous guest reads it from the database. */
  const publicChain = async (keyId: string) => {
    const c = await call<{ anchorPublicKey: string; links: { from: number; to: number; publicKey: string; signature: string }[] }>("", "select vault_enclave.anon_host_chain($1) as a", [keyId]);
    const anchor: HostKeyAnchor = { keyId, publicKey: unhex(c.anchorPublicKey) };
    const links: EpochLink[] = c.links.map((l) => ({ from: l.from, to: l.to, publicKey: unhex(l.publicKey), signature: unhex(l.signature) }));
    return { anchor, links };
  };
  const copyChain = (c: { anchor: HostKeyAnchor; links: EpochLink[] }) => ({
    anchor: { keyId: c.anchor.keyId, publicKey: c.anchor.publicKey.slice() },
    links: c.links.map((l) => ({ ...l, publicKey: l.publicKey.slice(), signature: l.signature.slice() })),
  });
  const copyRoot = (s: SignedRoot): SignedRoot => ({ ...s, root: s.root.slice(), publicKey: s.publicKey.slice(), signature: s.signature.slice() });

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    for (const step of planMigrations(listMigrationFiles(dir), new Set())) {
      if (step.action === "run" && step.file !== "0273_anonymous_booking_engine.sql") await db.exec(`begin;\n${readFileSync(join(dir, step.file), "utf8")}\n;commit;`);
    }
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql("0273_anonymous_booking_engine.sql")};\ncommit;`);
    await db.query(`insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values ($1, 'h', 'host7f@example.test', true, now(), now())`, [AUTH]);
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, 'host7f@example.test', $2)", [HOST, AUTH]);
    const { handle } = await ok<{ handle: string }>(runEnclaveOp("masterKey.generate", {}));
    await ok(runEnclaveOp("masterKey.commitPending", { handle, userId: HOST }));
  }, 300_000);
  afterAll(async () => db?.close());

  it("books two anonymous guests into a 2-seat pool, refuses a double spend and a third seat, and survives a reload", async () => {
    const keyId = `hk_${hex(randomBytes(32))}`;
    const treeId = `st_${hex(randomBytes(32))}`;
    const poolId = `cp_${hex(randomBytes(32))}`;

    // ---- Host setup: chain, tree, anchor binding, all stored only as public material + a device-sealed state.
    const init = await ok<{ anchor: HostKeyAnchor; epoch: number; sealedState: Uint8Array }>(runEnclaveOp("host_key.init", { userId: HOST, keyId }));
    expect(init.sealedState).toHaveLength(HSK_ENVELOPE_BYTES);
    expect([...init.sealedState.subarray(0, 7)]).toEqual([0x52, 0x56, 0x45, 0x31, 1, 9, 2]); // RVE1, hsk, member device
    const { signedRoot: genesis } = await ok<{ signedRoot: SignedRoot }>(runEnclaveOp("smt.genesis", { userId: HOST, treeId }));
    const anchorSig = await ok<{ signerPublicKey: Uint8Array; signature: Uint8Array }>(runEnclaveOp("host_key.sign_anchor", { userId: HOST, keyId, treeId }));
    expect(await ok(runEnclaveOp("host_key.verify_anchor", { anchor: { keyId, publicKey: init.anchor.publicKey.slice() }, treeId, signerPublicKey: anchorSig.signerPublicKey.slice(), signature: anchorSig.signature.slice() }))).toEqual({ valid: true });
    expect(await ok(runEnclaveOp("host_key.verify_anchor", { anchor: { keyId, publicKey: init.anchor.publicKey.slice() }, treeId: `st_${hex(randomBytes(32))}`, signerPublicKey: anchorSig.signerPublicKey.slice(), signature: anchorSig.signature.slice() }))).toEqual({ valid: false });
    expect(await call(HOST, "select vault_enclave.anon_host_key_init($1, $2, $3, $4, $5, $6, $7, $8, $9) as a",
      [await stepUp(), keyId, init.anchor.publicKey, anchorSig.signerPublicKey, anchorSig.signature, init.sealedState, treeId, genesis.publicKey, genesis.signature])).toMatchObject({ ok: true, epoch: 0 });

    const adv = await ok<{ epoch: number; link: EpochLink; sealedState: Uint8Array }>(runEnclaveOp("host_key.advance_epoch", { userId: HOST, keyId, toEpoch: 1 }));
    expect(await call(HOST, "select vault_enclave.anon_host_key_advance($1, $2, $3, $4, $5, $6, $7) as a",
      [keyId, 0, 0, 1, adv.link.publicKey, adv.link.signature, adv.sealedState])).toMatchObject({ ok: true, epoch: 1 });

    const pool = await ok<{ commitment: Uint8Array; proof: Uint8Array }>(runEnclaveOp("capacity.open", { userId: HOST, poolId, capacity: 2 }));
    expect(allZero()).toBe(true);
    expect(await ok(runEnclaveOp("capacity.verify_open", { poolId, commitment: pool.commitment.slice(), proof: pool.proof.slice() }))).toEqual({ valid: true });
    expect(await call(HOST, "select vault_enclave.anon_capacity_open($1, $2, $3, $4) as a", [treeId, poolId, pool.commitment, pool.proof])).toMatchObject({ ok: true });

    const store = new Store(await smtEmptyPath());
    let root = genesis;
    let head = 0;
    let remaining = 2;
    let remainingCommitment = pool.commitment;
    const pseudonyms: string[] = [];

    /** One guest, from first contact to recorded arrival. */
    const book = async () => {
      // Guest device: commitment to a fresh nullifier, per-booking pseudonym.
      const g = await ok<{ handle: string; commitmentWithProof: Uint8Array; pseudonym: Uint8Array }>(runEnclaveOp("anon_guest.begin", { hostId: keyId, keyId }));
      expect(allZero()).toBe(true);
      // Host signs the slot blind: it never sees the nullifier.
      const cred = await ok<{ epoch: number; signature: Uint8Array }>(runEnclaveOp("host_key.sign_slot_credential", {
        userId: HOST, keyId, epoch: 1, slot: SLOT, messages: SERVICE.map((m) => m.slice()), commitmentWithProof: g.commitmentWithProof.slice(),
      }));
      // Guest verifies against the chain it read anonymously from the database.
      const chain = await publicChain(keyId);
      expect(await ok(runEnclaveOp("anon_guest.accept", { handle: g.handle, ...copyChain(chain), epoch: cred.epoch, slot: SLOT, messages: SERVICE.map((m) => m.slice()), signature: cred.signature.slice() }))).toEqual({ valid: true });

      // Arrival: fresh host challenge, guest proves the slot is in the window without revealing it.
      const challenge = randomBytes(32);
      const p = await ok<{ presentation: Uint8Array; nullifier: Uint8Array; pseudonym: Uint8Array; epoch: number; messages: Uint8Array[] }>(
        runEnclaveOp("anon_guest.present", { handle: g.handle, challenge: challenge.slice(), windowStart: SLOT - 15, windowEnd: SLOT + 15 }));
      expect(allZero()).toBe(true);
      expect(Buffer.from(p.presentation).includes(Buffer.from(new Uint8Array(new BigUint64Array([BigInt(SLOT)]).buffer).reverse()))).toBe(false);
      const verify = (over: Record<string, unknown> = {}) => ok<{ valid: boolean }>(runEnclaveOp("anon_host.verify_presentation", {
        ...copyChain(chain), epoch: p.epoch, minEpoch: 1, presentation: p.presentation.slice(), messages: p.messages.map((m) => m.slice()),
        nullifier: p.nullifier.slice(), challenge: challenge.slice(), windowStart: SLOT - 15, windowEnd: SLOT + 15, ...over,
      })).then((r) => r.valid);
      expect(await verify()).toBe(true);
      expect(await verify({ challenge: randomBytes(32) })).toBe(false); // replayed elsewhere
      expect(await verify({ windowStart: SLOT + 1, windowEnd: SLOT + 30 })).toBe(false); // another window
      expect(await verify({ minEpoch: 2 })).toBe(false); // expired epoch
      expect(await code(runEnclaveOp("anon_guest.present", { handle: g.handle, challenge: randomBytes(32), windowStart: SLOT + 16, windowEnd: SLOT + 60 }))).toBe("invalid_input");

      // Host: nullifier not yet spent, spend it, take one seat, record everything in one transaction.
      expect(await ok(runEnclaveOp("smt.verify_non_membership", { userId: HOST, signedRoot: copyRoot(root), nullifier: p.nullifier.slice(), siblings: store.siblings(p.nullifier) }))).toEqual({ valid: true });
      const ins = await ok<{ inserted: boolean; signedRoot: SignedRoot; path: Uint8Array }>(runEnclaveOp("smt.insert_nullifier", { userId: HOST, signedRoot: copyRoot(root), nullifier: p.nullifier.slice(), siblings: store.siblings(p.nullifier) }));
      expect(ins.inserted).toBe(true);
      const step = 3 - remaining;
      const take = await ok<{ takeCommitment: Uint8Array; remainingCommitment: Uint8Array; proof: Uint8Array }>(runEnclaveOp("capacity.take", { userId: HOST, poolId, step, remainingBefore: remaining, take: 1 }));
      expect(await ok(runEnclaveOp("capacity.verify_take", { poolId, step, before: remainingCommitment.slice(), take: take.takeCommitment.slice(), after: take.remainingCommitment.slice(), proof: take.proof.slice() }))).toEqual({ valid: true });
      const rec = await call(HOST, "select vault_enclave.anon_booking_record($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) as a", [
        treeId, head, ins.signedRoot.root, ins.signedRoot.signature, p.nullifier, p.pseudonym, p.epoch, p.presentation,
        poolId, step, take.takeCommitment, take.remainingCommitment, take.proof,
      ]);
      expect(rec).toMatchObject({ ok: true, why: "ok", epoch: head + 1, ver: step });
      store.apply(p.nullifier, ins.path);
      root = ins.signedRoot;
      head += 1;
      remaining -= 1;
      remainingCommitment = take.remainingCommitment;
      pseudonyms.push(hex(p.pseudonym));

      // Double spend of the same credential: a new valid presentation, but the nullifier is spent everywhere.
      const again = await ok<{ presentation: Uint8Array; nullifier: Uint8Array; pseudonym: Uint8Array }>(runEnclaveOp("anon_guest.present", { handle: g.handle, challenge: randomBytes(32), windowStart: SLOT - 15, windowEnd: SLOT + 15 }));
      expect(hex(again.presentation)).not.toBe(hex(p.presentation)); // presentations are unlinkable bytes
      expect(await ok(runEnclaveOp("smt.verify_non_membership", { userId: HOST, signedRoot: copyRoot(root), nullifier: again.nullifier.slice(), siblings: store.siblings(again.nullifier) }))).toEqual({ valid: false });
      expect((await ok<{ inserted: boolean }>(runEnclaveOp("smt.insert_nullifier", { userId: HOST, signedRoot: copyRoot(root), nullifier: again.nullifier.slice(), siblings: store.siblings(again.nullifier) }))).inserted).toBe(false);
      const dup = await call(HOST, "select vault_enclave.anon_booking_record($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) as a", [
        treeId, head, randomBytes(32), randomBytes(80), again.nullifier, randomBytes(32), 1, again.presentation, null, null, null, null, null,
      ]);
      expect(dup.why).toBe("spent");
      expect(await ok(runEnclaveOp("anon_guest.discard", { handle: g.handle }))).toEqual({ discarded: true });
    };

    await book();
    await book();
    // The pool is full: no proof exists for a third seat.
    expect(await code(runEnclaveOp("capacity.take", { userId: HOST, poolId, step: 3, remainingBefore: 0, take: 1 }))).toBe("invalid_input");
    // Claiming seats that are not there yields commitments that do not chain onto the published remainder.
    const lie = await ok<{ takeCommitment: Uint8Array; remainingCommitment: Uint8Array; proof: Uint8Array }>(runEnclaveOp("capacity.take", { userId: HOST, poolId, step: 3, remainingBefore: 5, take: 1 }));
    expect(await ok(runEnclaveOp("capacity.verify_take", { poolId, step: 3, before: remainingCommitment.slice(), take: lie.takeCommitment.slice(), after: lie.remainingCommitment.slice(), proof: lie.proof.slice() }))).toEqual({ valid: false });

    // The host sees only per-booking pseudonyms: distinct, and nothing else about the guests.
    expect(new Set(pseudonyms).size).toBe(2);
    const tokens = await db.query<{ p: string }>("select encode(pseudonym, 'hex') as p from vault_enclave.anon_booking_tokens where tree_id = $1 order by root_epoch", [treeId]);
    expect(tokens.rows.map((r) => r.p)).toEqual(pseudonyms);

    // The whole ledger verifies on the client, including every capacity proof in the engine.
    const l = await call<{ ok: boolean; headHash: string; events: unknown[] }>(HOST, "select vault_enclave.anon_ledger($1, $2, $3) as a", [treeId, -1, 100]);
    const v = verifyAnonLedger(treeId, ledgerEventsFromJson(l.events));
    if (!v.ok) throw new Error(`ledger ${v.error}`);
    expect(v.bookings).toBe(2);
    expect(hex(v.headHash)).toBe(l.headHash);
    for (const s of v.capacity) {
      const r = s.kind === "open"
        ? await ok<{ valid: boolean }>(runEnclaveOp("capacity.verify_open", { poolId: s.poolId, commitment: s.commitment.slice(), proof: s.proof.slice() }))
        : await ok<{ valid: boolean }>(runEnclaveOp("capacity.verify_take", { poolId: s.poolId, step: s.step, before: s.before.slice(), take: s.take.slice(), after: s.after.slice(), proof: s.proof.slice() }));
      expect(r.valid).toBe(true);
    }

    // Reload: the worker forgets SK_1; it comes back only from the device-sealed envelope in the database.
    expect(hostKeys.wipeAll()).toBeGreaterThan(0);
    const st = await call<{ granted: boolean; epoch: number; state_envelope: string }>(HOST, "select to_jsonb(s) as a from vault_enclave.anon_host_key_state($1) s", [keyId]);
    const sealed = unhex(st.state_envelope);
    const chain = await publicChain(keyId);
    // A tampered envelope, an old one (rollback to epoch 0) and a wrong epoch are refused.
    const bad = sealed.slice();
    bad[bad.length - 1]! ^= 1;
    expect(await code(runEnclaveOp("host_key.restore", { userId: HOST, keyId, epoch: 1, sealedState: bad, ...copyChain(chain) }))).toBe("decrypt_failed");
    expect(await code(runEnclaveOp("host_key.restore", { userId: HOST, keyId, epoch: 0, sealedState: init.sealedState.slice(), anchor: copyChain(chain).anchor, links: [] }))).toBe("invalid_input");
    const back = await ok<{ epoch: number; publicKey: Uint8Array }>(runEnclaveOp("host_key.restore", { userId: HOST, keyId, epoch: 1, sealedState: sealed, ...copyChain(chain) }));
    expect(back.epoch).toBe(1);
    expect(hex(back.publicKey)).toBe(hex(chain.links[0]!.publicKey));
    // Another member's device key cannot open it.
    const OTHER = "00000000-0000-4000-8000-0000000007f2";
    const { handle } = await ok<{ handle: string }>(runEnclaveOp("masterKey.generate", {}));
    await ok(runEnclaveOp("masterKey.commitPending", { handle, userId: OTHER }));
    expect(await code(runEnclaveOp("host_key.restore", { userId: OTHER, keyId, epoch: 1, sealedState: unhex(st.state_envelope), ...copyChain(chain) }))).toBe("decrypt_failed");
    // The restored key signs again under the published epoch key.
    const g = await ok<{ handle: string; commitmentWithProof: Uint8Array }>(runEnclaveOp("anon_guest.begin", { hostId: keyId, keyId }));
    const cred = await ok<{ signature: Uint8Array }>(runEnclaveOp("host_key.sign_slot_credential", { userId: HOST, keyId, epoch: 1, slot: SLOT, messages: SERVICE.map((m) => m.slice()), commitmentWithProof: g.commitmentWithProof.slice() }));
    expect(await ok(runEnclaveOp("anon_guest.accept", { handle: g.handle, ...copyChain(chain), epoch: 1, slot: SLOT, messages: SERVICE.map((m) => m.slice()), signature: cred.signature.slice() }))).toEqual({ valid: true });
    expect(allZero()).toBe(true);
  }, 300_000);
});
