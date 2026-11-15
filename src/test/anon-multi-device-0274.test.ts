// @vitest-environment node
/**
 * db/0274 (Stap 7g, multi-device host keys; released after the owner's GO) and its rollback, on
 * PGlite over a replay of db/ (… 0267 → 0270 → 0271 → 0272 → 0273), then
 * 0274 → rollback → 0274. HELD: 0274 stays in db-pending/ and
 * CODE_SCHEMA_LEVEL stays 0273 until the owner's GO. Nothing touches Neon.
 *
 * Part one checks what SQL enforces with random bytes of the exact sizes.
 * Part two runs the real crypto worker (pinned rout-zk) and a test
 * authenticator: device registration with a passkey assertion over PK_0,
 * the public zkp-anchor.json document verified like a guest would, two
 * independent device chains, and the 00:00 UTC ratchet writing the new
 * sealed SK_t,dev into that device's vault_enclave row.
 */
import "fake-indexeddb/auto";
import { PGlite } from "@electric-sql/pglite";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { catalogJson, diffCatalogs, readCatalog, type Catalog } from "../../scripts/schema-catalog";
import { migrationDefinerGuardSql, migrationDefinerViolations } from "../../scripts/security-definer-policy";
import { contextStatements } from "@/lib/db-context";
import { ENCLAVE_MERGE_TABLES } from "@/lib/account-merge-rules";
import { CODE_SCHEMA_LEVEL } from "@/lib/schema-version";
import { HSK_ENVELOPE_BYTES, hostKeys, type EpochLink, type HostKeyAnchor } from "@/lib/crypto-enclave/forward-secure";
import type { SignedRoot } from "@/lib/crypto-enclave/smt";
import { runEnclaveOp } from "@/lib/crypto-enclave/enclave-core";
import { lastZkMemoryForTest } from "@/lib/crypto-enclave/zk-engine";
import { AnonHostChainStore } from "@/lib/anon-booking/host-chain-store.server";
import { readZkpAnchorDocument } from "@/lib/anon-booking/zkp-anchor.server";
import { anchorChallenge, b64u, verifyZkpAnchorDevice, type AnchorStatementInput } from "@/lib/anon-booking/zkp-anchor";
import { DailyEpochRatchet } from "@/lib/anon-booking/epoch-ratchet";
import { utcEpochAt } from "@/lib/anon-booking/epoch-clock";
import { assertOver, makeAuthenticator, type TestAuthenticator } from "./webauthn-test-authenticator";

const ROOT = join(__dirname, "..", "..");
const FILE = "0274_multi_device_host_keys.sql";
const SQL = readFileSync(join(ROOT, "db", FILE), "utf8");
const ROLLBACK = readFileSync(join(ROOT, "db-pending", "0274_multi_device_host_keys_rollback.sql"), "utf8");
const SQL_0273 = readFileSync(join(ROOT, "db", "0273_anonymous_booking_engine.sql"), "utf8");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (h: string) => new Uint8Array(Buffer.from(h.replace(/^\\x/, ""), "hex"));
const id = (p: "hk" | "st" | "hd") => `${p}_${hex(randomBytes(32))}`;
const hsk = () => {
  const e = randomBytes(HSK_ENVELOPE_BYTES);
  e.set([0x52, 0x56, 0x45, 0x31, 1, 9, 2]);
  return e;
};
const pakEnvelope = () => {
  const e = randomBytes(1663);
  e.set([0x52, 0x56, 0x45, 0x31, 1, 8, 1]);
  return e;
};
const CHECK = { rpId: "rout.be", origins: ["https://rout.be"] };
const NEW_ACTIONS = ["anon_device_list", "anon_device_register", "anon_device_revoke"];

type Answer = { op: string; ok: boolean; why: string; epoch: number | null; ver: number | null };
type Member = { id: string; auth: string; handle: string };

describe("0274 multi-device host keys on a replay of db/ (held in db-pending/)", () => {
  let db: PGlite;
  let users = 0;
  let at0273: { catalog: Catalog; hash: string };

  const call = async <T = Answer>(userId: string, query: string, params: readonly unknown[] = []): Promise<T> => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      if (userId) for (const st of contextStatements({ userId, workspaceId: null })) await db.query(st.query, st.params);
      const r = await db.query<{ a: T }>(query, params as unknown[]);
      await db.exec("commit");
      return r.rows[0]!.a;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const rowsAs = async (userId: string, query: string, params: readonly unknown[]) => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      if (userId) for (const st of contextStatements({ userId, workspaceId: null })) await db.query(st.query, st.params);
      const r = await db.query<Record<string, unknown>>(query, params as unknown[]);
      await db.exec("commit");
      return r.rows;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const store = () => new AnonHostChainStore((u, q, p) => rowsAs(u, q, p), CHECK);

  const newUser = async (handle?: string): Promise<Member> => {
    users += 1;
    const n = users.toString(16).padStart(12, "0");
    const member = `00000000-0000-4000-8000-${n}`;
    const auth = `00000000-0000-4000-9000-${n}`;
    const h = handle ?? `host${n}`;
    await db.query(`insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values ($1, 'h', $2, true, now(), now())`, [auth, `h${n}@example.test`]);
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, $2, $3)", [member, `h${n}@example.test`, auth]);
    await db.query("insert into public.profiles (id, username) values ($1, $2) on conflict (id) do update set username = excluded.username", [member, h]);
    return { id: member, auth, handle: h };
  };
  /** A passkey of `m` with the authenticator's COSE key and an MDS3 verdict (or none). */
  const passkey = async (m: Member, a: TestAuthenticator, verdict: { attested: boolean; statusSafe: boolean | null; fmt?: string } | null = { attested: true, statusSafe: true }) => {
    const cred = b64u(randomBytes(20));
    await db.query(`insert into neon_auth.passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") values ($1, $2, $3, $4, 0, 'singleDevice', false)`,
      [crypto.randomUUID(), Buffer.from(a.cose).toString("base64"), m.auth, cred]);
    if (verdict) {
      await db.query("insert into vault_enclave.passkey_attestations (credential_id, auth_user_id, fmt, attested, status_safe, certified_l3, envelope) values ($1, $2, $3, $4, $5, false, $6)",
        [cred, m.auth, verdict.fmt ?? (verdict.attested ? "packed" : "none"), verdict.attested, verdict.statusSafe, pakEnvelope()]);
    }
    return cred;
  };
  const proof = async (m: Member, ageSeconds = 0) => {
    const p = crypto.randomUUID();
    await db.query(`insert into vault_enclave.step_up_proofs (proof_id, user_id, method, verified_at) values ($1, $2, 'passkey', clock_timestamp() - make_interval(secs => $3))`, [p, m.id, ageSeconds]);
    return p;
  };

  type Reg = AnchorStatementInput & { anchorSig: Uint8Array; state: Uint8Array; genesisSig: Uint8Array };
  const freshReg = (deviceId = id("hd")): Reg => ({
    deviceId, keyId: id("hk"), treeId: id("st"), anchorPublicKey: randomBytes(96), anchorSignerPublicKey: randomBytes(96),
    rootSignerPublicKey: randomBytes(96), anchorSig: randomBytes(80), state: hsk(), genesisSig: randomBytes(80),
  });
  const REGISTER = "select vault_enclave.anon_host_device_register($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) as a";
  const registerRaw = async (m: Member, r: Reg, o: { proof?: string | null; cred: string; auth: TestAuthenticator; flags?: number; challenge?: Uint8Array; alg?: number }) => {
    let challenge = o.challenge;
    if (!challenge) {
      try {
        challenge = anchorChallenge(r);
      } catch {
        challenge = randomBytes(32); // malformed ids: the database refuses before it looks at the assertion
      }
    }
    const a = await assertOver(o.auth, challenge, { flags: o.flags });
    return call(m.id, REGISTER, [o.proof === undefined ? await proof(m) : o.proof, r.deviceId, r.keyId, r.anchorPublicKey, r.anchorSignerPublicKey, r.anchorSig,
      r.state, r.treeId, r.rootSignerPublicKey, r.genesisSig, o.cred, o.alg ?? o.auth.alg, a.authenticatorData, a.clientDataJSON, a.signature]);
  };

  const fingerprint = async () => {
    const catalog = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
    const fns = await db.query(`select n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) as args,
        coalesce(p.proacl::text, '') as acl, coalesce(array_to_string(p.proconfig, ','), '') as cfg, p.prosecdef, md5(pg_get_functiondef(p.oid)) as def
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname in ('public', 'vault_enclave', 'neon_auth', 'auth', 'storage') and p.prokind = 'f' order by 1, 2, 3`);
    const idx = await db.query(`select indexname, indexdef from pg_indexes where schemaname = 'vault_enclave' order by 1`);
    const text = catalogJson(catalog) + JSON.stringify(fns.rows) + JSON.stringify(idx.rows);
    return { catalog, hash: hex(sha256(new TextEncoder().encode(text))) };
  };

  let ES: TestAuthenticator;
  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    const run = planMigrations(listMigrationFiles(dir), new Set()).filter((s) => s.action === "run" && s.file < FILE).map((s) => s.file);
    expect(run.slice(-5)).toEqual(["0267_card_recovery_factor_tap.sql", "0270_opaque_password_pow.sql", "0271_fido_mds3_attestation.sql", "0272_dynamic_recovery_v4.sql", "0273_anonymous_booking_engine.sql"]);
    for (const file of run) await db.exec(`begin;\n${readFileSync(join(dir, file), "utf8")}\n;commit;`);
    at0273 = await fingerprint();
    ES = await makeAuthenticator(-7);
  }, 300_000);
  afterAll(async () => db?.close());

  it("0274 is released: in db/ (not db-pending/), CODE_SCHEMA_LEVEL is 0274, the rollback stays held back", () => {
    expect(CODE_SCHEMA_LEVEL >= "0274").toBe(true);
    expect(readdirSync(join(ROOT, "db")).filter((f) => f.startsWith("0274"))).toEqual([FILE]);
    expect(existsSync(join(ROOT, "db-pending", FILE))).toBe(false);
    expect(existsSync(join(ROOT, "db-pending", "0274_multi_device_host_keys_rollback.sql"))).toBe(true);
  });

  it("0273 → 0274 → rollback → 0273 schema exactly; the rollback is idempotent; 0274 applies again identically", async () => {
    expect(migrationDefinerViolations(FILE, SQL)).toEqual([]);
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    const at0274 = await fingerprint();
    expect(at0274.hash).not.toBe(at0273.hash);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    const back = await fingerprint();
    expect(diffCatalogs(at0273.catalog, back.catalog)).toEqual([]);
    expect(back.hash).toBe(at0273.hash);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    expect((await fingerprint()).hash).toBe(at0273.hash);
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    expect((await fingerprint()).hash).toBe(at0274.hash);
  }, 120_000);

  it("rights: new tables unreachable, RLS with one restrictive deny_all, helpers closed, entry points only for rout_app", async () => {
    for (const t of ["anon_host_devices", "anon_anchor_endorsements"]) {
      const r = await db.query<{ s: boolean; i: boolean; p: boolean; rls: boolean; pol: string }>(
        `select has_table_privilege('rout_app', $1, 'select') as s, has_table_privilege('rout_app', $1, 'insert') as i,
                has_table_privilege('public', $1, 'select') as p, (select relrowsecurity from pg_class where oid = $1::regclass) as rls,
                (select string_agg(polname || ':' || polpermissive || ':' || pg_get_expr(polqual, polrelid), ',') from pg_policy where polrelid = $1::regclass) as pol`,
        [`vault_enclave.${t}`]);
      expect(r.rows[0]).toEqual({ s: false, i: false, p: false, rls: true, pol: "deny_all:false:false" });
      await expect(call("", `select count(*) as a from vault_enclave.${t}`)).rejects.toThrow(/permission/);
    }
    const fns = await db.query<{ n: string; app: boolean; pub: boolean }>(
      `select p.proname as n, has_function_privilege('rout_app', p.oid, 'execute') as app, has_function_privilege('public', p.oid, 'execute') as pub
         from pg_proc p join pg_namespace s on s.oid = p.pronamespace where s.nspname = 'vault_enclave' and p.proname like 'anon\\_%' order by 1`);
    expect(fns.rows.filter((r) => r.pub)).toEqual([]);
    expect(fns.rows.filter((r) => r.app).map((r) => r.n)).toEqual(["anon_booking_check", "anon_booking_record", "anon_capacity_open", "anon_host_anchor_public",
      "anon_host_chain", "anon_host_device_register", "anon_host_device_revoke", "anon_host_devices_mine", "anon_host_key_advance", "anon_host_key_init",
      "anon_host_key_retire", "anon_host_key_state", "anon_host_passkey", "anon_ledger", "anon_pseudonym_invalidate"]);
    const fks = await db.query<{ d: string }>(`select c.confdeltype::text as d from pg_constraint c join pg_class r on r.oid = c.conrelid
       join pg_namespace n on n.oid = r.relnamespace where n.nspname = 'vault_enclave' and r.relname like 'anon\\_%' and c.contype = 'f'`);
    expect(fks.rows.filter((r) => r.d !== "r")).toEqual([]);
  });

  it("every new anon table of 0274 has a reviewed merge strategy", () => {
    const tables = [...SQL.matchAll(/create table vault_enclave\.(anon_\w+)/g)].map((m) => m[1]!).sort();
    for (const t of tables) expect(ENCLAVE_MERGE_TABLES[t], t).toBeDefined();
  });

  it("the audit action check keeps every 0273 value and adds exactly the three device actions", async () => {
    const quoted = (s: string) => [...s.matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1]!);
    const at = SQL_0273.indexOf("add constraint audit_logs_action_check");
    const before = quoted(SQL_0273.slice(at, SQL_0273.indexOf("));", at)));
    const live = (await db.query<{ d: string }>(`select pg_get_constraintdef(oid) as d from pg_constraint where conname = 'audit_logs_action_check' and conrelid = 'vault_enclave.audit_logs'::regclass`)).rows[0]!.d;
    const now = quoted(live);
    expect(before.filter((a) => !now.includes(a))).toEqual([]);
    expect(now.filter((a) => !before.includes(a)).sort()).toEqual(NEW_ACTIONS);
  });

  it("the SQL anchor statement and challenge are byte-identical to zkp-anchor.ts", async () => {
    const r = freshReg();
    const sql = await db.query<{ c: string }>("select vault_enclave.anon_b64u(sha256(vault_enclave.anon_anchor_statement($1, $2, $3, $4, $5, $6))) as c",
      [r.deviceId, r.keyId, r.treeId, r.anchorPublicKey, r.anchorSignerPublicKey, r.rootSignerPublicKey]);
    expect(sql.rows[0]!.c).toBe(b64u(anchorChallenge(r)));
  });

  let HOST: Member;
  let HOST_CRED: string;

  it("register: needs the caller's own MDS3-attested passkey, an assertion over exactly this anchor with UP+UV, and a fresh step-up", async () => {
    HOST = await newUser("anchorhost");
    const other = await newUser();
    HOST_CRED = await passkey(HOST, ES);
    const otherCred = await passkey(other, ES);
    const noVerdict = await passkey(HOST, ES, null);
    const unsafe = await passkey(HOST, ES, { attested: true, statusSafe: false });
    const notAttested = await passkey(HOST, ES, { attested: false, statusSafe: null });
    const r = freshReg();
    expect((await call("", REGISTER, Array(15).fill(null))).why).toBe("no_caller");
    expect((await registerRaw(HOST, { ...r, state: randomBytes(HSK_ENVELOPE_BYTES) }, { cred: HOST_CRED, auth: ES })).why).toBe("malformed");
    expect((await registerRaw(HOST, { ...r, deviceId: "hd_x" }, { cred: HOST_CRED, auth: ES })).why).toBe("malformed");
    expect((await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES, alg: -999 })).why).toBe("malformed");
    expect((await registerRaw(HOST, r, { cred: otherCred, auth: ES })).why).toBe("passkey");
    expect((await registerRaw(HOST, r, { cred: noVerdict, auth: ES })).why).toBe("attestation");
    expect((await registerRaw(HOST, r, { cred: unsafe, auth: ES })).why).toBe("attestation");
    expect((await registerRaw(HOST, r, { cred: notAttested, auth: ES })).why).toBe("attestation");
    expect((await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES, challenge: anchorChallenge(freshReg()) })).why).toBe("challenge");
    expect((await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES, flags: 0x01 })).why).toBe("flags");
    expect((await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES, proof: null })).why).toBe("stepup");
    expect((await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES, proof: await proof(HOST, 400) })).why).toBe("stepup");
    expect(await registerRaw(HOST, r, { cred: HOST_CRED, auth: ES })).toMatchObject({ ok: true, why: "ok", epoch: 0, ver: 0 });
    // The same device cannot hold a second live chain; ids are never reused.
    expect((await registerRaw(HOST, freshReg(r.deviceId), { cred: HOST_CRED, auth: ES })).why).toBe("busy");
    expect((await registerRaw(other, freshReg(r.deviceId), { cred: otherCred, auth: ES })).why).toBe("taken");
    expect((await registerRaw(HOST, { ...freshReg(), keyId: r.keyId }, { cred: HOST_CRED, auth: ES })).why).toBe("taken");
    const audit = await db.query<{ o: string; n: number }>("select outcome as o, count(*)::int as n from vault_enclave.audit_logs where action = 'anon_device_register' group by 1 order by 1");
    expect(audit.rows).toEqual([{ o: "denied", n: 15 }, { o: "granted", n: 1 }]);
  });

  it("several live devices, each its own chain advancing on its own; a 0273 chain and devices never mix; at most 16 devices", async () => {
    const second = freshReg();
    expect((await registerRaw(HOST, second, { cred: HOST_CRED, auth: ES })).ok).toBe(true);
    const devices = await call<{ ok: boolean; devices: { deviceId: string; keyId: string; epoch: number }[] }>(HOST.id, "select vault_enclave.anon_host_devices_mine() as a");
    expect(devices.devices).toHaveLength(2);
    const [d1, d2] = devices.devices;
    const ADV = "select vault_enclave.anon_host_key_advance($1, $2, $3, $4, $5, $6, $7) as a";
    expect(await call(HOST.id, ADV, [d1!.keyId, 0, 0, 5, randomBytes(96), randomBytes(80), hsk()])).toMatchObject({ ok: true, epoch: 5 });
    expect(await call(HOST.id, ADV, [d2!.keyId, 0, 0, 3, randomBytes(96), randomBytes(80), hsk()])).toMatchObject({ ok: true, epoch: 3 });
    const states = await db.query<{ n: number }>("select count(distinct key_id)::int as n from vault_enclave.anon_host_key_states where key_id = any($1)", [[d1!.keyId, d2!.keyId]]);
    expect(states.rows[0]!.n).toBe(2);
    // A 0273 single chain is refused while devices are live.
    const INIT = "select vault_enclave.anon_host_key_init($1, $2, $3, $4, $5, $6, $7, $8, $9) as a";
    expect((await call(HOST.id, INIT, [await proof(HOST), id("hk"), randomBytes(96), randomBytes(96), randomBytes(80), hsk(), id("st"), randomBytes(96), randomBytes(80)])).why).toBe("busy");
    // And a host with a 0273 chain cannot add devices.
    const legacy = await newUser();
    const lc = await passkey(legacy, ES);
    expect((await call(legacy.id, INIT, [await proof(legacy), id("hk"), randomBytes(96), randomBytes(96), randomBytes(80), hsk(), id("st"), randomBytes(96), randomBytes(80)])).ok).toBe(true);
    expect((await registerRaw(legacy, freshReg(), { cred: lc, auth: ES })).why).toBe("legacy_chain");
    // Device limit.
    const many = await newUser();
    const mc = await passkey(many, ES);
    for (let i = 0; i < 16; i++) expect((await registerRaw(many, freshReg(), { cred: mc, auth: ES })).ok).toBe(true);
    expect((await registerRaw(many, freshReg(), { cred: mc, auth: ES })).why).toBe("device_limit");
  }, 120_000);

  it("revoke: retires only that device's chain (fresh step-up), the device stays revoked forever", async () => {
    const victim = await newUser();
    const vc = await passkey(victim, ES);
    const a = freshReg();
    const b = freshReg();
    await registerRaw(victim, a, { cred: vc, auth: ES });
    await registerRaw(victim, b, { cred: vc, auth: ES });
    const REVOKE = "select vault_enclave.anon_host_device_revoke($1, $2) as a";
    expect((await call(victim.id, REVOKE, [null, a.deviceId])).why).toBe("stepup");
    expect((await call(HOST.id, REVOKE, [await proof(HOST), a.deviceId])).why).toBe("unknown");
    expect(await call(victim.id, REVOKE, [await proof(victim), a.deviceId])).toMatchObject({ ok: true });
    expect((await call(victim.id, REVOKE, [await proof(victim), a.deviceId])).why).toBe("revoked");
    const k = await db.query<{ key_id: string; r: boolean; s: number }>(`select key_id, retired_at is not null as r,
        (select count(*)::int from vault_enclave.anon_host_key_states s where s.key_id = k.key_id) as s from vault_enclave.anon_host_keys k where key_id = any($1) order by key_id`, [[a.keyId, b.keyId]]);
    const by = Object.fromEntries(k.rows.map((r) => [r.key_id, r]));
    expect(by[a.keyId]).toMatchObject({ r: true, s: 0 });
    expect(by[b.keyId]).toMatchObject({ r: false, s: 1 });
    expect((await registerRaw(victim, freshReg(a.deviceId), { cred: vc, auth: ES })).why).toBe("taken");
    const ledger = await db.query<{ kinds: string[] }>("select array_agg(kind order by seq) as kinds from vault_enclave.anon_ledger_events where tree_id = $1", [a.treeId]);
    expect(ledger.rows[0]!.kinds).toEqual(["genesis", "retire"]);
  });

  it("the public anchor document: only for a visible profile, only public material, and every device verifies like a guest checks it", async () => {
    const q = (sql: string, p: unknown[]) => rowsAs("", sql, p);
    const r = await readZkpAnchorDocument(q, "anchorhost", "rout.be");
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.document).toMatchObject({ type: "rout.zkp-anchor", version: 1, host: "@anchorhost", rpId: "rout.be", epoch: { seconds: 86_400 } });
    expect(r.document.devices).toHaveLength(2);
    for (const d of r.document.devices) expect(await verifyZkpAnchorDevice(d, CHECK)).toEqual({ ok: true });
    const json = JSON.stringify(r.document);
    expect(json).not.toContain(HOST.id);
    expect(json).not.toContain(HOST.auth);
    expect(await readZkpAnchorDocument(q, "nobody-here", "rout.be")).toEqual({ status: "not_found" });
    const quiet = await newUser("quiethost");
    expect(await readZkpAnchorDocument(q, quiet.handle, "rout.be")).toEqual({ status: "no_anchor" });
    await db.query("update public.profiles set is_banned = true where id = $1", [HOST.id]);
    expect(await readZkpAnchorDocument(q, "anchorhost", "rout.be")).toEqual({ status: "not_found" });
    await db.query("update public.profiles set is_banned = false where id = $1", [HOST.id]);
  });

  it("purge detaches devices and deletes endorsements; merge moves the secondary's devices revoked", async () => {
    const gone = await newUser();
    const gc = await passkey(gone, ES);
    const g = freshReg();
    await registerRaw(gone, g, { cred: gc, auth: ES });
    await db.query("insert into public.account_deletions (user_id, requested_at, purge_after) values ($1, now() - interval '31 days', now() - interval '1 day')", [gone.id]);
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.purge_user_id', $1, true)", [gone.id]);
      expect((await db.query<{ n: number }>("select public.rout_anon_booking_purge($1::uuid) as n", [gone.id])).rows[0]!.n).toBe(1);
      await db.exec("reset role");
      await db.query("delete from public.profiles where id = $1", [gone.id]);
      await db.query("delete from public.users where id = $1", [gone.id]);
      await db.query("delete from public.account_deletions where user_id = $1", [gone.id]);
      await db.exec("commit");
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
    const dev = await db.query<{ h: string | null; p: boolean; r: boolean }>("select host_user_id::text as h, purged_at is not null as p, revoked_at is not null as r from vault_enclave.anon_host_devices where device_id = $1", [g.deviceId]);
    expect(dev.rows[0]).toEqual({ h: null, p: true, r: true });
    expect((await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.anon_anchor_endorsements where key_id = $1", [g.keyId])).rows[0]!.n).toBe(0);
    expect((await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.anon_ledger_events where tree_id = $1", [g.treeId])).rows[0]!.n).toBe(2);

    const primary = await newUser();
    const secondary = await newUser();
    const sc = await passkey(secondary, ES);
    const s1 = freshReg();
    await registerRaw(secondary, s1, { cred: sc, auth: ES });
    await db.query("insert into public.account_merge_tickets(id,primary_user_id,preview_user_id,pin_hash,token_hash,expires_at) values($1,$2,$3,'ticket-7g','qr',now()+interval '5 minutes')", [crypto.randomUUID(), primary.id, secondary.id]);
    await db.query("insert into public.security_codes(user_id,purpose,code_hash,expires_at) values($1,'merge','email-proof-7g',now()+interval '10 minutes')", [secondary.id]);
    await db.exec("begin");
    let result: { ok: boolean };
    try {
      await db.exec("set local role rout_app");
      for (const st of contextStatements({ userId: secondary.id, workspaceId: null })) await db.query(st.query, st.params);
      result = (await db.query<{ r: { ok: boolean } }>("select public.execute_account_merge($1,$2,$3,$4) as r", ["ticket-7g", "email-proof-7g", "primary", "primary"])).rows[0]!.r;
      await db.exec("commit");
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
    expect(result).toMatchObject({ ok: true });
    const moved = await db.query<{ h: string; r: boolean }>("select host_user_id::text as h, revoked_at is not null as r from vault_enclave.anon_host_devices where device_id = $1", [s1.deviceId]);
    expect(moved.rows[0]).toEqual({ h: primary.id, r: true });
  });

  it("the rollback refuses while devices exist (nothing is dropped)", async () => {
    await expect(db.exec(`begin;\n${ROLLBACK}\n;commit;`)).rejects.toThrow(/0274 rollback/);
    await db.exec("rollback").catch(() => undefined);
    expect((await db.query<{ ok: boolean }>("select to_regclass('vault_enclave.anon_host_devices') is not null as ok")).rows[0]!.ok).toBe(true);
  });

  describe("end to end with the crypto worker (pinned rout-zk) and a passkey", () => {
    const enclaveOk = async <T>(op: string, args: Record<string, unknown>): Promise<T> => {
      const r = await runEnclaveOp(op as never, args);
      if (!r.ok) throw new Error(`${op}: ${r.code}`);
      return r.result as T;
    };

    it("registers two device chains, publishes them, and ratchets one at 00:00 UTC into its own vault_enclave row", async () => {
      const host = await newUser("e2ehost");
      const auth = await makeAuthenticator(-7);
      const cred = await passkey(host, auth);
      const { handle } = await enclaveOk<{ handle: string }>("masterKey.generate", {});
      await enclaveOk("masterKey.commitPending", { handle, userId: host.id });
      const s = store();
      expect(await s.devicesAvailable(host.id)).toBe(true);

      const register = async () => {
        const deviceId = id("hd");
        const keyId = id("hk");
        const treeId = id("st");
        const init = await enclaveOk<{ anchor: HostKeyAnchor; sealedState: Uint8Array }>("host_key.init", { userId: host.id, keyId });
        expect(init.sealedState).toHaveLength(HSK_ENVELOPE_BYTES);
        const genesis = await enclaveOk<{ signedRoot: SignedRoot }>("smt.genesis", { userId: host.id, treeId });
        const anchorSig = await enclaveOk<{ signerPublicKey: Uint8Array; signature: Uint8Array }>("host_key.sign_anchor", { userId: host.id, keyId, treeId });
        const statement: AnchorStatementInput = { deviceId, keyId, treeId, anchorPublicKey: init.anchor.publicKey, anchorSignerPublicKey: anchorSig.signerPublicKey, rootSignerPublicKey: genesis.signedRoot.publicKey };
        const a = await assertOver(auth, anchorChallenge(statement));
        const answer = await s.registerDevice(host.id, {
          ...statement, proofId: await proof(host), anchorSignature: anchorSig.signature, sealedState: init.sealedState, genesisSignature: genesis.signedRoot.signature,
          credentialId: cred, algorithm: -7, authenticatorData: a.authenticatorData, clientDataJSON: a.clientDataJSON, passkeySignature: a.signature,
        });
        expect(answer).toMatchObject({ ok: true, why: "ok" });
        return { deviceId, keyId, treeId };
      };
      const d1 = await register();
      const d2 = await register();
      // A forged assertion never reaches the database.
      const bad = await s.registerDevice(host.id, {
        deviceId: id("hd"), keyId: id("hk"), treeId: id("st"), anchorPublicKey: randomBytes(96), anchorSignerPublicKey: randomBytes(96), rootSignerPublicKey: randomBytes(96),
        proofId: await proof(host), anchorSignature: randomBytes(80), sealedState: hsk(), genesisSignature: randomBytes(80), credentialId: cred, algorithm: -7,
        ...(await assertOver(auth, randomBytes(32))), passkeySignature: randomBytes(72),
      });
      expect(bad).toMatchObject({ ok: false, why: "endorsement_challenge" });

      // Guests: the document verifies (passkey) and the enclave anchor signature verifies in the worker.
      const doc = await readZkpAnchorDocument((q, p) => rowsAs("", q, p), "e2ehost", "rout.be");
      expect(doc.status).toBe("ok");
      if (doc.status !== "ok") return;
      expect(doc.document.devices.map((d) => d.deviceId).sort()).toEqual([d1.deviceId, d2.deviceId].sort());
      for (const d of doc.document.devices) {
        expect(await verifyZkpAnchorDevice(d, CHECK)).toEqual({ ok: true });
        expect(await enclaveOk("host_key.verify_anchor", {
          anchor: { keyId: d.keyId, publicKey: unhex(d.anchorPublicKey) }, treeId: d.treeId,
          signerPublicKey: unhex(d.enclaveAnchor.signerPublicKey), signature: unhex(d.enclaveAnchor.signature),
        })).toEqual({ valid: true });
      }

      // 00:00 UTC on 2026-11-16: device 1 ratchets from its anchor to today.
      const now = Date.UTC(2026, 10, 16, 0, 0, 0, 0);
      const target = utcEpochAt(now);
      const held = hostKeys.get(host.id, d1.keyId)!.state;
      const before = held.slice();
      const ratchet = new DailyEpochRatchet({
        now: () => now,
        port: {
          heldEpoch: async () => (await enclaveOk<{ epoch: number }>("host_key.chain", { userId: host.id, keyId: d1.keyId })).epoch,
          advance: async (to) => enclaveOk<{ epoch: number; link: EpochLink; sealedState: Uint8Array }>("host_key.advance_epoch", { userId: host.id, keyId: d1.keyId, toEpoch: to }),
          persist: s.persistFor(host.id, d1.keyId),
        },
      });
      expect(await ratchet.ensureCurrent()).toEqual({ status: "advanced", epoch: target, target });
      // SK_{t-1} is gone: the engine memory reads back as zeros and the held buffer was overwritten in place.
      expect(lastZkMemoryForTest()!.every((b) => b === 0)).toBe(true);
      expect(hostKeys.get(host.id, d1.keyId)!.state).toBe(held);
      expect(Buffer.from(held).equals(Buffer.from(before))).toBe(false);
      // The device's own row holds the new sealed state; device 2 is untouched.
      const st1 = await s.state(host.id, d1.keyId);
      const st2 = await s.state(host.id, d2.keyId);
      expect(st1).toMatchObject({ granted: true, epoch: target, ver: 1 });
      expect(st2).toMatchObject({ granted: true, epoch: 0, ver: 0 });
      expect(await ratchet.ensureCurrent()).toMatchObject({ status: "current", epoch: target });

      // After a reload (wiped worker) the stored envelope restores exactly epoch `target` against the public chain.
      const chain = await call<{ links: { from: number; to: number; publicKey: string; signature: string }[]; anchorPublicKey: string }>("", "select vault_enclave.anon_host_chain($1) as a", [d1.keyId]);
      expect(chain.links.map((l) => [l.from, l.to])).toEqual([[0, target]]);
      await enclaveOk("secure.wipe", {});
      expect(held.every((b) => b === 0)).toBe(true);
      const restored = await enclaveOk<{ epoch: number }>("host_key.restore", {
        userId: host.id, keyId: d1.keyId, epoch: target, sealedState: st1.sealedState!,
        anchor: { keyId: d1.keyId, publicKey: unhex(chain.anchorPublicKey) },
        links: chain.links.map((l) => ({ from: l.from, to: l.to, publicKey: unhex(l.publicKey), signature: unhex(l.signature) })),
      });
      expect(restored.epoch).toBe(target);
    }, 180_000);
  });
});
