// @vitest-environment node
/**
 * db/0273 (Stap 7e/7f, anonymous booking engine; moved into db/ after the
 * owner's GO of 2026-11-15) and its rollback (db-pending/), on PGlite over a
 * replay of every migration in db/ before 0273 (… 0267 → 0270 → 0271 → 0272),
 * then 0273 → rollback → 0273. Nothing here touches Neon.
 *
 * The database stores signatures, roots and proofs but cannot verify pairings,
 * so these tests use random bytes of the exact sizes the crypto worker
 * produces (constants imported from the TS adapters) and check what SQL
 * itself enforces: caller binding, ownership, sizes, compare-and-swap,
 * uniqueness, append-only history, rights and the audit chain. A fast-check
 * property compares every answer against a reference model, and a bounded
 * model check runs every interleaving of two devices of one host.
 */
import { PGlite } from "@electric-sql/pglite";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import fc from "fast-check";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { catalogJson, diffCatalogs, readCatalog, type Catalog } from "../../scripts/schema-catalog";
import { migrationDefinerGuardSql, migrationDefinerViolations } from "../../scripts/security-definer-policy";
import { HOST_PUBLIC_KEY_BYTES, HOST_SIGNATURE_BYTES, MAX_CHAIN_LINKS, MAX_EPOCH_ADVANCE } from "@/lib/crypto-enclave/forward-secure";
import { PSEUDONYM_BYTES } from "@/lib/crypto-enclave/pseudonyms";
import { NULLIFIER_BYTES, ROOT_PUBLIC_KEY_BYTES, ROOT_SIGNATURE_BYTES, SMT_EMPTY_ROOT_HEX, SMT_NODE_BYTES } from "@/lib/crypto-enclave/smt";
import { CODE_SCHEMA_LEVEL } from "@/lib/schema-version";
import { CAPACITY_TAKE_PROOF_BYTES, ledgerEventsFromJson, verifyAnonLedger } from "@/lib/crypto-enclave/anon-ledger";
import { HSK_ENVELOPE_BYTES } from "@/lib/crypto-enclave/forward-secure";
import { contextStatements } from "@/lib/db-context";

const ROOT = join(__dirname, "..", "..");
const FILE = "0273_anonymous_booking_engine.sql";
const SQL = readFileSync(join(ROOT, "db", FILE), "utf8");
const ROLLBACK = readFileSync(join(ROOT, "db-pending", "0273_anonymous_booking_engine_rollback.sql"), "utf8");
const SQL_0272 = readFileSync(join(ROOT, "db", "0272_dynamic_recovery_v4.sql"), "utf8");

const HSK_BYTES = HSK_ENVELOPE_BYTES; // RVE1 overhead 1663 + SK_t (32) || epoch (8)
const PROOF_MIN = 272;
const WINDOW = 80 + 2 * 928; // committed slot + two range proofs (anon.rs)
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const id = (p: "hk" | "st" | "cp") => `${p}_${hex(randomBytes(32))}`;
const hsk = (kind = 9, holder = 2) => {
  const e = randomBytes(HSK_BYTES);
  e.set([0x52, 0x56, 0x45, 0x31, 1, kind, holder]);
  return e;
};
/** I2OSP(bbs_len, 8) || BBS proof || committed slot || two range proofs. */
const presentation = (undisclosed = 3, prefix?: number) => {
  const bbs = PROOF_MIN + 32 * undisclosed;
  const p = randomBytes(8 + bbs + WINDOW);
  new DataView(p.buffer).setBigUint64(0, BigInt(prefix ?? bbs), false);
  return p;
};

const ANON_ACTIONS = ["anon_booking_check", "anon_booking_record", "anon_capacity_open", "anon_host_key_advance", "anon_host_key_init", "anon_host_key_retire", "anon_host_merge", "anon_host_purge", "anon_host_state_read", "anon_ledger_read", "anon_pseudonym_invalidate"];

type Answer = { op: string; ok: boolean; why: string; epoch: number | null; ver: number | null; spent?: boolean; invalidated?: boolean };
type Chain = { keyId: string; treeId: string; anchorPk: Uint8Array };

describe("0273 anonymous booking engine on a replay of db/", () => {
  let db: PGlite;
  let users = 0;

  /** One call as rout_app inside its own transaction, with the member in the transaction context. */
  const call = async <T = Answer>(userId: string, query: string, params: unknown[] = []): Promise<T> => {
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
  const newUser = async () => {
    users += 1;
    const n = users.toString(16).padStart(12, "0");
    const member = `00000000-0000-4000-8000-${n}`;
    const auth = `00000000-0000-4000-9000-${n}`;
    await db.query(`insert into neon_auth."user" (id, name, email, "emailVerified", "createdAt", "updatedAt") values ($1, 'h', $2, true, now(), now())`, [auth, `h${n}@example.test`]);
    await db.query("insert into public.users (id, email, auth_user_id) values ($1, $2, $3)", [member, `h${n}@example.test`, auth]);
    return member;
  };
  const proof = async (user: string, ageSeconds = 0) => {
    const p = crypto.randomUUID();
    await db.query(`insert into vault_enclave.step_up_proofs (proof_id, user_id, method, verified_at) values ($1, $2, 'passkey', clock_timestamp() - make_interval(secs => $3))`, [p, user, ageSeconds]);
    return p;
  };

  const INIT = "select vault_enclave.anon_host_key_init($1, $2, $3, $4, $5, $6, $7, $8, $9) as a";
  const ADVANCE = "select vault_enclave.anon_host_key_advance($1, $2, $3, $4, $5, $6, $7) as a";
  const RECORD = "select vault_enclave.anon_booking_record($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) as a";
  const POOL_OPEN = "select vault_enclave.anon_capacity_open($1, $2, $3, $4) as a";
  const LEDGER = "select vault_enclave.anon_ledger($1, $2, $3) as a";
  const CHECK = "select vault_enclave.anon_booking_check($1, $2) as a";
  const INVALIDATE = "select vault_enclave.anon_pseudonym_invalidate($1, $2, $3) as a";
  const RETIRE = "select vault_enclave.anon_host_key_retire($1, $2) as a";
  const CHAIN = "select vault_enclave.anon_host_chain($1) as a";
  const STATE = "select to_jsonb(s) as a from vault_enclave.anon_host_key_state($1) s";

  const initArgs = (p: string | null, c: Chain, over: Partial<Record<number, unknown>> = {}) => {
    const a: unknown[] = [p, c.keyId, c.anchorPk, randomBytes(ROOT_PUBLIC_KEY_BYTES), randomBytes(HOST_SIGNATURE_BYTES), hsk(), c.treeId, randomBytes(ROOT_PUBLIC_KEY_BYTES), randomBytes(ROOT_SIGNATURE_BYTES)];
    for (const [i, v] of Object.entries(over)) a[Number(i)] = v;
    return a;
  };
  const freshChain = (): Chain => ({ keyId: id("hk"), treeId: id("st"), anchorPk: randomBytes(HOST_PUBLIC_KEY_BYTES) });
  const initHost = async (user: string) => {
    const c = freshChain();
    const a = await call(user, INIT, initArgs(await proof(user), c));
    expect(a).toMatchObject({ ok: true, why: "ok", epoch: 0, ver: 0 });
    return c;
  };
  const advance = (user: string, c: Chain, ver: number, from: number, to: number, pk: Uint8Array = randomBytes(HOST_PUBLIC_KEY_BYTES), sig: Uint8Array = randomBytes(HOST_SIGNATURE_BYTES), state: Uint8Array = hsk()) =>
    call(user, ADVANCE, [c.keyId, ver, from, to, pk, sig, state]);
  type PoolStep = { poolId: string; step: number; take?: Uint8Array; remaining?: Uint8Array; proof?: Uint8Array };
  const record = (user: string, c: Chain, head: number, o: { nullifier?: Uint8Array; pseudonym?: Uint8Array; credentialEpoch?: number; root?: Uint8Array; sig?: Uint8Array; proof?: Uint8Array; pool?: PoolStep; raw?: unknown[] } = {}) =>
    call(user, RECORD, [c.treeId, head, o.root ?? randomBytes(SMT_NODE_BYTES), o.sig ?? randomBytes(ROOT_SIGNATURE_BYTES),
      o.nullifier ?? randomBytes(NULLIFIER_BYTES), o.pseudonym ?? randomBytes(PSEUDONYM_BYTES), o.credentialEpoch ?? 0, o.proof ?? presentation(),
      ...(o.raw ?? (o.pool
        ? [o.pool.poolId, o.pool.step, o.pool.take ?? randomBytes(48), o.pool.remaining ?? randomBytes(48), o.pool.proof ?? randomBytes(CAPACITY_TAKE_PROOF_BYTES)]
        : [null, null, null, null, null]))]);
  const head = async (user: string, c: Chain) => (await call(user, CHECK, [c.treeId, randomBytes(NULLIFIER_BYTES)])).epoch!;
  const keyState = (user: string, c: Chain) => call<{ granted: boolean; epoch: number | null; ver: number | null; state_envelope: string | null }>(user, STATE, [c.keyId]);

  const fingerprint = async () => {
    const catalog = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
    const fns = await db.query(`select n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) as args,
        coalesce(p.proacl::text, '') as acl, coalesce(array_to_string(p.proconfig, ','), '') as cfg, p.prosecdef
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname in ('public', 'vault_enclave', 'neon_auth', 'auth', 'storage') order by 1, 2, 3`);
    const text = catalogJson(catalog) + JSON.stringify(fns.rows);
    return { catalog, hash: hex(sha256(new TextEncoder().encode(text))) };
  };

  let HOST: string;
  let OTHER: string;
  let at0272: { catalog: Catalog; hash: string };

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    const run = planMigrations(listMigrationFiles(dir), new Set()).filter((s) => s.action === "run" && s.file < FILE).map((s) => s.file);
    expect(run.slice(-4)).toEqual(["0267_card_recovery_factor_tap.sql", "0270_opaque_password_pow.sql", "0271_fido_mds3_attestation.sql", "0272_dynamic_recovery_v4.sql"]);
    for (const file of run) await db.exec(`begin;\n${readFileSync(join(dir, file), "utf8")}\n;commit;`);
    HOST = await newUser();
    OTHER = await newUser();
    at0272 = await fingerprint();
  }, 300_000);
  afterAll(async () => db?.close());

  it("0273 is released: in db/ (not db-pending/), CODE_SCHEMA_LEVEL is at least 0273, the rollback stays held back", () => {
    expect(Number(CODE_SCHEMA_LEVEL)).toBeGreaterThanOrEqual(273);
    expect(readdirSync(join(ROOT, "db")).filter((f) => f.startsWith("0273"))).toEqual([FILE]);
    expect(existsSync(join(ROOT, "db-pending", FILE))).toBe(false);
    expect(existsSync(join(ROOT, "db-pending", "0273_anonymous_booking_engine_rollback.sql"))).toBe(true);
  });

  it("0272 → 0273 → rollback leaves a schema identical to 0272; the rollback is idempotent; 0273 applies again identically", async () => {
    expect(migrationDefinerViolations(FILE, SQL)).toEqual([]);
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    const at0273 = await fingerprint();
    expect(at0273.hash).not.toBe(at0272.hash);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    const back = await fingerprint();
    expect(diffCatalogs(at0272.catalog, back.catalog)).toEqual([]);
    expect(back.hash).toBe(at0272.hash);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    expect((await fingerprint()).hash).toBe(at0272.hash);
    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    expect((await fingerprint()).hash).toBe(at0273.hash);
  });

  it("rights: rout_app and PUBLIC reach no table and no helper; RLS is on with one restrictive deny_all policy", async () => {
    const tables = ["anon_host_keys", "anon_host_key_states", "anon_epoch_links", "anon_smt_trees", "anon_smt_roots", "anon_booking_tokens", "anon_pseudonym_invalidations", "anon_capacity_pools", "anon_ledger_events"];
    for (const t of tables) {
      const r = await db.query<{ s: boolean; i: boolean; p: boolean; rls: boolean; pol: string }>(
        `select has_table_privilege('rout_app', $1, 'select') as s, has_table_privilege('rout_app', $1, 'insert') as i,
                has_table_privilege('public', $1, 'select') as p, (select relrowsecurity from pg_class where oid = $1::regclass) as rls,
                (select string_agg(polname || ':' || polpermissive || ':' || pg_get_expr(polqual, polrelid), ',') from pg_policy where polrelid = $1::regclass) as pol`,
        [`vault_enclave.${t}`]);
      expect(r.rows[0]).toEqual({ s: false, i: false, p: false, rls: true, pol: "deny_all:false:false" });
      await expect(call(HOST, `select count(*) as a from vault_enclave.${t}`)).rejects.toThrow(/permission/);
    }
    const helpers = await db.query<{ n: string; e: boolean }>(
      `select p.proname as n, has_function_privilege('rout_app', p.oid, 'execute') as e from pg_proc p join pg_namespace s on s.oid = p.pronamespace
        where s.nspname = 'vault_enclave' and p.proname like 'anon\\_%' order by 1`);
    const open = helpers.rows.filter((r) => r.e).map((r) => r.n);
    expect(open).toEqual(["anon_booking_check", "anon_booking_record", "anon_capacity_open", "anon_host_chain", "anon_host_key_advance", "anon_host_key_init", "anon_host_key_retire", "anon_host_key_state", "anon_ledger", "anon_pseudonym_invalidate"]);
    // Lifecycle: the purge entry point only for rout_app, the merge hook only for the merge executor.
    const life = await db.query<{ pa: boolean; pp: boolean; ma: boolean; mp: boolean; me: boolean }>(
      `select has_function_privilege('rout_app', 'public.rout_anon_booking_purge(uuid)', 'execute') as pa,
              has_function_privilege('public', 'public.rout_anon_booking_purge(uuid)', 'execute') as pp,
              has_function_privilege('rout_app', 'public.rout_anon_booking_merge(uuid, uuid)', 'execute') as ma,
              has_function_privilege('public', 'public.rout_anon_booking_merge(uuid, uuid)', 'execute') as mp,
              has_function_privilege('rout_merge_executor', 'public.rout_anon_booking_merge(uuid, uuid)', 'execute') as me`);
    expect(life.rows[0]).toEqual({ pa: true, pp: false, ma: false, mp: false, me: true });
    // No foreign key of an anonymous table cascades or nulls on delete.
    const fks = await db.query<{ c: string; d: string }>(`select c.conname as c, c.confdeltype::text as d from pg_constraint c
        join pg_class r on r.oid = c.conrelid join pg_namespace n on n.oid = r.relnamespace
       where n.nspname = 'vault_enclave' and r.relname like 'anon\\_%' and c.contype = 'f'`);
    expect(fks.rows.length).toBeGreaterThanOrEqual(9);
    expect(fks.rows.filter((r) => r.d !== "r")).toEqual([]);
    const pub = await db.query<{ n: number }>(`select count(*)::int as n from pg_proc p join pg_namespace s on s.oid = p.pronamespace
        where s.nspname = 'vault_enclave' and has_function_privilege('public', p.oid, 'execute')`);
    expect(pub.rows[0]!.n).toBe(0);
    const anyTable = await db.query<{ n: number }>(`select count(*)::int as n from pg_class c join pg_namespace s on s.oid = c.relnamespace
        where s.nspname = 'vault_enclave' and c.relkind = 'r' and (has_table_privilege('rout_app', c.oid, 'select') or has_table_privilege('rout_app', c.oid, 'insert'))`);
    expect(anyTable.rows[0]!.n).toBe(0);
  });

  it("the audit action check keeps every 0272 value and adds exactly the eleven anon actions", async () => {
    const quoted = (s: string) => [...s.matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1]!);
    const block = SQL_0272.slice(SQL_0272.indexOf("add constraint audit_logs_action_check"), SQL_0272.indexOf("));", SQL_0272.indexOf("add constraint audit_logs_action_check")));
    const before = quoted(block);
    const live = (await db.query<{ d: string }>(`select pg_get_constraintdef(oid) as d from pg_constraint where conname = 'audit_logs_action_check' and conrelid = 'vault_enclave.audit_logs'::regclass`)).rows[0]!.d;
    const now = quoted(live);
    expect(before.length).toBeGreaterThan(30);
    expect(before.filter((a) => !now.includes(a))).toEqual([]);
    expect(now.filter((a) => !before.includes(a)).sort()).toEqual(ANON_ACTIONS);
  });

  it("no caller in the transaction context: every entry point answers no_caller", async () => {
    const c = freshChain();
    const nobody = "";
    expect((await call(nobody, INIT, initArgs(null, c))).why).toBe("no_caller");
    expect((await advance(nobody, c, 0, 0, 1)).why).toBe("no_caller");
    expect((await record(nobody, c, 0)).why).toBe("no_caller");
    expect((await call(nobody, CHECK, [c.treeId, randomBytes(32)])).why).toBe("no_caller");
    expect((await call(nobody, INVALIDATE, [c.treeId, randomBytes(32), "cancelled"])).why).toBe("no_caller");
    expect((await call(nobody, RETIRE, [null, c.keyId])).why).toBe("no_caller");
    expect((await keyState(nobody, c)).granted).toBe(false);
    // A well-formed id of a member who does not exist counts as no caller as well.
    expect((await call("00000000-0000-4000-8000-ffffffffffff", INIT, initArgs(null, c))).why).toBe("no_caller");
  });

  let chain: Chain;

  it("init binds PK_0 to the caller and needs a fresh passkey step-up of the caller", async () => {
    chain = freshChain();
    expect((await call(HOST, INIT, initArgs(null, chain))).why).toBe("stepup");
    expect((await call(HOST, INIT, initArgs(await proof(HOST, 400), chain))).why).toBe("stepup");
    expect((await call(HOST, INIT, initArgs(await proof(OTHER), chain))).why).toBe("stepup");
    const p = await proof(HOST);
    expect((await call(HOST, INIT, initArgs(p, chain, { 1: "hk_short" }))).why).toBe("malformed");
    expect((await call(HOST, INIT, initArgs(p, chain, { 2: randomBytes(95) }))).why).toBe("malformed");
    expect((await call(HOST, INIT, initArgs(p, chain, { 5: hsk(9, 1) }))).why).toBe("malformed"); // never the server vault (7f)
    expect((await call(HOST, INIT, initArgs(p, chain, { 5: hsk(9, 3) }))).why).toBe("malformed"); // only the member device
    expect((await call(HOST, INIT, initArgs(p, chain, { 5: randomBytes(1695).fill(0x52, 0, 1) }))).why).toBe("malformed"); // 7e size
    expect((await call(HOST, INIT, initArgs(p, chain, { 5: hsk(5, 1) }))).why).toBe("malformed"); // kind must be hsk (9)
    expect(await call(HOST, INIT, initArgs(p, chain))).toMatchObject({ ok: true, epoch: 0, ver: 0 });
    // The proof is spent; a second live chain is refused; ids are never reused.
    expect((await call(HOST, INIT, initArgs(p, freshChain()))).why).toBe("busy");
    expect((await call(OTHER, INIT, initArgs(await proof(OTHER), { ...freshChain(), keyId: chain.keyId }))).why).toBe("taken");
    expect((await call(OTHER, INIT, initArgs(await proof(OTHER), { ...freshChain(), treeId: chain.treeId }))).why).toBe("taken");
    const genesis = await db.query<{ r: string; e: number }>("select encode(root, 'hex') as r, epoch::int as e from vault_enclave.anon_smt_roots where tree_id = $1", [chain.treeId]);
    expect(genesis.rows).toEqual([{ r: SMT_EMPTY_ROOT_HEX, e: 0 }]);
    const owner = await db.query<{ h: string }>("select host_user_id::text as h from vault_enclave.anon_host_keys where key_id = $1", [chain.keyId]);
    expect(owner.rows[0]!.h).toBe(HOST);
  });

  it("advance: compare-and-swap on ver and epoch, the state envelope is replaced in place, a retry gets its answer", async () => {
    const before = await keyState(HOST, chain);
    expect(before).toMatchObject({ granted: true, epoch: 0, ver: 0 });
    expect((await advance(OTHER, chain, 0, 0, 1)).why).toBe("unknown");
    expect((await advance(HOST, chain, 1, 0, 1)).why).toBe("conflict");
    expect((await advance(HOST, chain, 0, 1, 2)).why).toBe("conflict");
    expect((await advance(HOST, chain, 0, 0, 0)).why).toBe("malformed");
    expect((await advance(HOST, chain, 0, 0, MAX_EPOCH_ADVANCE + 1)).why).toBe("malformed");
    expect((await advance(HOST, chain, 0, 0, 1, chain.anchorPk)).why).toBe("malformed"); // same key again
    const pk = randomBytes(HOST_PUBLIC_KEY_BYTES);
    const sig = randomBytes(HOST_SIGNATURE_BYTES);
    const state = hsk();
    expect(await advance(HOST, chain, 0, 0, 1, pk, sig, state)).toMatchObject({ ok: true, why: "ok", epoch: 1, ver: 1 });
    expect(await advance(HOST, chain, 0, 0, 1, pk, sig, hsk())).toMatchObject({ ok: true, why: "replay", epoch: 1, ver: 1 });
    const after = await keyState(HOST, chain);
    expect(after).toMatchObject({ granted: true, epoch: 1, ver: 1 });
    expect(after.state_envelope).toBe(`\\x${hex(state)}`);
    const copies = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.anon_host_key_states where key_id = $1", [chain.keyId]);
    expect(copies.rows[0]!.n).toBe(1);
    expect(await advance(HOST, chain, 1, 1, 3)).toMatchObject({ ok: true, epoch: 3, ver: 2 }); // epoch 2 skipped: no key
    expect((await keyState(OTHER, chain)).granted).toBe(false);
  });

  it("the public chain is readable without a caller and holds only public keys and signatures", async () => {
    const pub = await call<Record<string, unknown>>("", CHAIN, [chain.keyId]);
    expect(pub).toMatchObject({ found: true, keyId: chain.keyId, epoch: 3, retired: false, anchorPublicKey: hex(chain.anchorPk) });
    expect((pub.links as { from: number; to: number }[]).map((l) => [l.from, l.to])).toEqual([[0, 1], [1, 3]]);
    expect(Object.keys(pub).sort()).toEqual(["anchorPublicKey", "anchorSignature", "anchorSignerPublicKey", "currentPublicKey", "epoch", "found", "keyId", "links", "retired"]);
    expect(await call("", CHAIN, [id("hk")])).toEqual({ found: false });
    expect(await call("", CHAIN, ["'; select 1; --"])).toEqual({ found: false });
  });

  const spentNullifier = randomBytes(NULLIFIER_BYTES);
  const usedPseudonym = randomBytes(PSEUDONYM_BYTES);

  it("record: one root step per booking; double spending, reused pseudonyms, unpublished epochs and stale heads are refused", async () => {
    const root = randomBytes(SMT_NODE_BYTES);
    const sig = randomBytes(ROOT_SIGNATURE_BYTES);
    const pr = presentation(5);
    const first = { nullifier: spentNullifier, pseudonym: usedPseudonym, credentialEpoch: 1, root, sig, proof: pr };
    expect((await record(OTHER, chain, 0, first)).why).toBe("unknown");
    expect((await record(HOST, chain, 0, { ...first, proof: randomBytes(PROOF_MIN + 31) })).why).toBe("malformed");
    expect((await record(HOST, chain, 0, { ...first, proof: presentation(5, PROOF_MIN + 32 * 4) })).why).toBe("malformed"); // prefix lies
    expect((await record(HOST, chain, 0, { ...first, proof: presentation(5).subarray(0, 8 + PROOF_MIN + 160 + WINDOW - 1) })).why).toBe("malformed");
    expect((await record(HOST, chain, 0, { ...first, raw: [id("cp"), null, null, null, null] })).why).toBe("malformed"); // half a pool step
    expect((await record(HOST, chain, 0, { ...first, raw: [null, 1, null, null, null] })).why).toBe("malformed");
    expect((await record(HOST, chain, 0, { ...first, nullifier: randomBytes(31) })).why).toBe("malformed");
    expect((await record(HOST, chain, 0, { ...first, credentialEpoch: 2 })).why).toBe("epoch"); // skipped epoch
    expect((await record(HOST, chain, 0, { ...first, credentialEpoch: 4 })).why).toBe("epoch"); // future epoch
    expect((await record(HOST, chain, 1, first)).why).toBe("conflict");
    expect(await record(HOST, chain, 0, first)).toMatchObject({ ok: true, why: "ok", epoch: 1 });
    expect(await record(HOST, chain, 0, first)).toMatchObject({ ok: true, why: "replay", epoch: 1 });
    expect((await record(HOST, chain, 1, { nullifier: spentNullifier })).why).toBe("spent");
    expect((await record(HOST, chain, 0, { nullifier: spentNullifier })).why).toBe("spent");
    expect((await record(HOST, chain, 1, { pseudonym: usedPseudonym })).why).toBe("pseudonym_taken");
    expect((await record(HOST, chain, 0)).why).toBe("conflict");
    expect(await record(HOST, chain, 1, { credentialEpoch: 3 })).toMatchObject({ ok: true, epoch: 2 });
    expect(await record(HOST, chain, 2, { credentialEpoch: 0 })).toMatchObject({ ok: true, epoch: 3 });
    const roots = await db.query<{ e: number }>("select epoch::int as e from vault_enclave.anon_smt_roots where tree_id = $1 order by epoch", [chain.treeId]);
    expect(roots.rows.map((r) => r.e)).toEqual([0, 1, 2, 3]);
    const guestColumns = await db.query<{ c: string }>(`select column_name as c from information_schema.columns where table_schema = 'vault_enclave' and table_name = 'anon_booking_tokens' order by ordinal_position`);
    expect(guestColumns.rows.map((r) => r.c)).toEqual(["token_id", "tree_id", "root_epoch", "nullifier", "pseudonym", "credential_epoch", "presentation", "created_at"]);
  });

  it("check and invalidate: only on the caller's own tree; invalidation is idempotent", async () => {
    expect(await call(HOST, CHECK, [chain.treeId, spentNullifier])).toMatchObject({ ok: true, epoch: 3, spent: true, invalidated: false });
    expect(await call(HOST, CHECK, [chain.treeId, randomBytes(32)])).toMatchObject({ ok: true, spent: false });
    expect((await call(OTHER, CHECK, [chain.treeId, spentNullifier])).why).toBe("unknown");
    expect((await call(HOST, INVALIDATE, [chain.treeId, usedPseudonym, "whatever"])).why).toBe("malformed");
    expect((await call(HOST, INVALIDATE, [chain.treeId, randomBytes(32), "cancelled"])).why).toBe("unknown");
    expect((await call(OTHER, INVALIDATE, [chain.treeId, usedPseudonym, "cancelled"])).why).toBe("unknown");
    expect(await call(HOST, INVALIDATE, [chain.treeId, usedPseudonym, "cancelled"])).toMatchObject({ ok: true, why: "ok" });
    expect(await call(HOST, INVALIDATE, [chain.treeId, usedPseudonym, "abuse"])).toMatchObject({ ok: true, why: "already" });
    expect(await call(HOST, CHECK, [chain.treeId, spentNullifier])).toMatchObject({ spent: true, invalidated: true });
  });

  it("history rows are append-only even for the owner, and nothing cascades: deleting a host account without the purge fails", async () => {
    const gone = await newUser();
    const c = await initHost(gone);
    expect((await record(gone, c, 0)).ok).toBe(true);
    expect((await call(gone, POOL_OPEN, [c.treeId, id("cp"), randomBytes(48), randomBytes(928)])).ok).toBe(true);
    for (const t of ["anon_epoch_links", "anon_smt_roots", "anon_booking_tokens", "anon_pseudonym_invalidations", "anon_ledger_events", "anon_host_keys", "anon_smt_trees", "anon_capacity_pools"]) {
      await expect(db.query(`delete from vault_enclave.${t}`)).rejects.toThrow(/anon_append_only/);
      await expect(db.query(`truncate vault_enclave.${t} cascade`)).rejects.toThrow(/anon_append_only/);
    }
    await expect(db.query("update vault_enclave.anon_smt_roots set root = root")).rejects.toThrow(/anon_append_only/);
    await expect(db.query("update vault_enclave.anon_booking_tokens set credential_epoch = 0")).rejects.toThrow(/anon_append_only/);
    await expect(db.query("update vault_enclave.anon_ledger_events set kind = kind")).rejects.toThrow(/anon_append_only/);
    // A purge that forgot the anonymous tables must fail, not drop spent nullifiers.
    await expect(db.query("delete from public.users where id = $1", [gone])).rejects.toThrow(/foreign key/);
  });

  /** The account purge transaction of src/lib/account-purge.ts, reduced to the anonymous step and the user row. */
  const purge = async (user: string, due = true) => {
    await db.query("insert into public.account_deletions (user_id, requested_at, purge_after) values ($1, now() - interval '31 days', $2) on conflict (user_id) do update set purge_after = excluded.purge_after, cancelled_at = null, completed_at = null",
      [user, due ? new Date(Date.now() - 86_400_000).toISOString() : new Date(Date.now() + 86_400_000).toISOString()]);
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.purge_user_id', $1, true)", [user]);
      const n = (await db.query<{ n: number }>("select public.rout_anon_booking_purge($1::uuid) as n", [user])).rows[0]!.n;
      await db.exec("reset role");
      await db.query("delete from public.users where id = $1", [user]);
      await db.query("delete from public.account_deletions where user_id = $1", [user]);
      await db.exec("commit");
      return n;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };

  it("purge: only when due; retires the live chain, deletes every sealed state, detaches the chains and keeps all spent nullifiers", async () => {
    const gone = await newUser();
    const c = await initHost(gone);
    const nf = randomBytes(NULLIFIER_BYTES);
    expect((await record(gone, c, 0, { nullifier: nf })).ok).toBe(true);
    await expect(purge(gone, false)).rejects.toThrow(/anon_purge_not_due/);
    // Outside a purge transaction rout_app cannot call it for anyone.
    await expect(call(OTHER, "select public.rout_anon_booking_purge($1::uuid)::text as a", [gone])).rejects.toThrow(/anon_purge_not_due/);
    expect(await purge(gone)).toBe(1);
    const k = await db.query<{ h: string | null; p: boolean; r: boolean; s: number }>(
      `select host_user_id::text as h, purged_at is not null as p, retired_at is not null as r,
              (select count(*)::int from vault_enclave.anon_host_key_states where key_id = $1) as s
         from vault_enclave.anon_host_keys where key_id = $1`, [c.keyId]);
    expect(k.rows[0]).toEqual({ h: null, p: true, r: true, s: 0 });
    const kept = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.anon_booking_tokens where tree_id = $1 and nullifier = $2", [c.treeId, nf]);
    expect(kept.rows[0]!.n).toBe(1);
    const ledger = await db.query<{ kinds: string[] }>("select array_agg(kind order by seq) as kinds from vault_enclave.anon_ledger_events where tree_id = $1", [c.treeId]);
    expect(ledger.rows[0]!.kinds).toEqual(["genesis", "booking", "retire"]);
    // The public chain stays verifiable; no audit row names the purged member.
    expect(await call("", CHAIN, [c.keyId])).toMatchObject({ found: true, retired: true });
    const named = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.audit_logs where action = 'anon_host_purge' and actor_user_id is not null");
    expect(named.rows[0]!.n).toBe(0);
    // An account without chains purges with zero.
    expect(await purge(await newUser())).toBe(0);
  });

  it("merge: execute_account_merge retires the secondary's live chain, moves its chains to the primary and keeps the primary's", async () => {
    const primary = await newUser();
    const secondary = await newUser();
    const pc = await initHost(primary);
    const sc = await initHost(secondary);
    expect((await record(secondary, sc, 0)).ok).toBe(true);
    const ticket = crypto.randomUUID();
    await db.query("insert into public.account_merge_tickets(id,primary_user_id,preview_user_id,pin_hash,token_hash,expires_at) values($1,$2,$3,'ticket-7f','qr',now()+interval '5 minutes')", [ticket, primary, secondary]);
    await db.query("insert into public.security_codes(user_id,purpose,code_hash,expires_at) values($1,'merge','email-proof-7f',now()+interval '10 minutes')", [secondary]);
    // The hook is callable only by the merge executor and only for the signed-in secondary.
    await expect(call(secondary, "select public.rout_anon_booking_merge($1::uuid, $2::uuid)::text as a", [primary, secondary])).rejects.toThrow(/permission/);
    await db.exec("begin");
    let result: { ok: boolean; reason?: string };
    try {
      await db.exec("set local role rout_app");
      for (const st of contextStatements({ userId: secondary, workspaceId: null })) await db.query(st.query, st.params);
      result = (await db.query<{ r: { ok: boolean; reason?: string } }>("select public.execute_account_merge($1,$2,$3,$4) as r", ["ticket-7f", "email-proof-7f", "primary", "primary"])).rows[0]!.r;
      await db.exec("commit");
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
    expect(result).toMatchObject({ ok: true });
    const rows = await db.query<{ k: string; h: string; r: boolean; s: number }>(
      `select key_id as k, host_user_id::text as h, retired_at is not null as r,
              (select count(*)::int from vault_enclave.anon_host_key_states s where s.key_id = k.key_id) as s
         from vault_enclave.anon_host_keys k where key_id = any($1) order by key_id`, [[pc.keyId, sc.keyId]]);
    const byKey = Object.fromEntries(rows.rows.map((r) => [r.k, r]));
    expect(byKey[pc.keyId]).toMatchObject({ h: primary, r: false, s: 1 });
    expect(byKey[sc.keyId]).toMatchObject({ h: primary, r: true, s: 0 });
    // Primary still has exactly one live chain and reads the moved ledger.
    const l = await call<{ ok: boolean; events: { kind: string }[] }>(primary, LEDGER, [sc.treeId, -1, 100]);
    expect(l.ok).toBe(true);
    expect(l.events.map((e) => e.kind)).toEqual(["genesis", "booking", "retire"]);
  }, 60_000);

  it("capacity pools: opened once per tree, every booking step is compare-and-swap on the pool step", async () => {
    const u = await newUser();
    const c = await initHost(u);
    const otherOwner = await newUser();
    const other = { owner: otherOwner, chain: await initHost(otherOwner) };
    const poolId = id("cp");
    const c0 = randomBytes(48);
    const p0 = randomBytes(928);
    expect((await call(OTHER, POOL_OPEN, [c.treeId, poolId, c0, p0])).why).toBe("unknown");
    expect((await call(u, POOL_OPEN, [c.treeId, "cp_short", c0, p0])).why).toBe("malformed");
    expect((await call(u, POOL_OPEN, [c.treeId, poolId, c0, randomBytes(927)])).why).toBe("malformed");
    expect(await call(u, POOL_OPEN, [c.treeId, poolId, c0, p0])).toMatchObject({ ok: true, why: "ok", ver: 0 });
    expect(await call(u, POOL_OPEN, [c.treeId, poolId, c0, p0])).toMatchObject({ ok: true, why: "replay" });
    expect((await call(u, POOL_OPEN, [c.treeId, poolId, randomBytes(48), p0])).why).toBe("taken");
    // A pool of another tree, or an unknown one, is refused; a stale or skipped step conflicts.
    expect((await record(u, c, 0, { pool: { poolId: id("cp"), step: 1 } })).why).toBe("pool");
    const theirs = id("cp");
    expect((await call(other.owner, POOL_OPEN, [other.chain.treeId, theirs, c0, p0])).ok).toBe(true);
    expect((await record(u, c, 0, { pool: { poolId: theirs, step: 1 } })).why).toBe("pool");
    expect((await record(u, c, 0, { pool: { poolId, step: 2 } })).why).toBe("pool_conflict");
    expect((await record(u, c, 0, { pool: { poolId, step: 0 } })).why).toBe("malformed");
    const r1 = randomBytes(48);
    expect(await record(u, c, 0, { pool: { poolId, step: 1, remaining: r1 } })).toMatchObject({ ok: true, epoch: 1, ver: 1 });
    expect((await record(u, c, 1, { pool: { poolId, step: 1 } })).why).toBe("pool_conflict");
    expect(await record(u, c, 1)).toMatchObject({ ok: true, epoch: 2 }); // unpooled booking on the same tree
    expect(await record(u, c, 2, { pool: { poolId, step: 2 } })).toMatchObject({ ok: true, epoch: 3, ver: 2 });
    const pool = await db.query<{ step: number; rem: string }>("select step::int as step, encode(remaining_commitment, 'hex') as rem from vault_enclave.anon_capacity_pools where pool_id = $1", [poolId]);
    expect(pool.rows[0]!.step).toBe(2);
    expect(pool.rows[0]!.rem).not.toBe(hex(r1));
  });

  it("ledger: one hash chain per tree, recomputed byte for byte by the client verifier; only the owner reads it", async () => {
    const u = await newUser();
    const c = await initHost(u);
    const poolId = id("cp");
    expect((await call(u, POOL_OPEN, [c.treeId, poolId, randomBytes(48), randomBytes(928)])).ok).toBe(true);
    const ps = randomBytes(PSEUDONYM_BYTES);
    expect((await record(u, c, 0, { pseudonym: ps, pool: { poolId, step: 1 } })).ok).toBe(true);
    expect((await record(u, c, 1)).ok).toBe(true);
    expect((await call(u, INVALIDATE, [c.treeId, ps, "cancelled"])).ok).toBe(true);
    expect((await call(u, RETIRE, [await proof(u), c.keyId])).ok).toBe(true);
    expect((await call(OTHER, LEDGER, [c.treeId, -1, 100])).why).toBe("unknown");
    expect((await call(u, LEDGER, [c.treeId, -1, 0])).why).toBe("malformed");
    const l = await call<{ ok: boolean; headSeq: number; headHash: string; events: unknown[] }>(u, LEDGER, [c.treeId, -1, 100]);
    const events = ledgerEventsFromJson(l.events);
    expect(events.map((e) => e.kind)).toEqual(["genesis", "pool_open", "booking", "booking", "invalidate", "retire"]);
    const v = verifyAnonLedger(c.treeId, events);
    expect(v).toMatchObject({ ok: true, headSeq: 5, bookings: 2 });
    if (!v.ok) throw new Error("ledger");
    expect(hex(v.headHash)).toBe(l.headHash);
    expect(v.capacity.map((s) => s.kind)).toEqual(["open", "take"]);
    // Paging continues from a verified head.
    const page = await call<{ events: unknown[] }>(u, LEDGER, [c.treeId, 3, 100]);
    expect(ledgerEventsFromJson(page.events).map((e) => e.seq)).toEqual([4, 5]);
    // Any change to any event breaks the chain at that event.
    const tampered = events.map((e) => ({ ...e }));
    tampered[2] = { ...tampered[2]!, nullifier: randomBytes(32) };
    expect(verifyAnonLedger(c.treeId, tampered)).toMatchObject({ ok: false, at: 2, error: "hash" });
    expect(verifyAnonLedger(c.treeId, [events[0]!, events[2]!])).toMatchObject({ ok: false, error: "sequence" });
    expect(verifyAnonLedger(id("st"), events)).toMatchObject({ ok: false, at: 0, error: "hash" });
  });

  it("retire needs a fresh step-up, deletes the sealed state and freezes the chain; a new chain can start", async () => {
    expect((await call(HOST, RETIRE, [null, chain.keyId])).why).toBe("stepup");
    expect((await call(OTHER, RETIRE, [await proof(OTHER), chain.keyId])).why).toBe("unknown");
    expect(await call(HOST, RETIRE, [await proof(HOST), chain.keyId])).toMatchObject({ ok: true, why: "ok" });
    expect((await call(HOST, RETIRE, [await proof(HOST), chain.keyId])).why).toBe("retired");
    expect((await keyState(HOST, chain)).granted).toBe(false);
    const states = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.anon_host_key_states where key_id = $1", [chain.keyId]);
    expect(states.rows[0]!.n).toBe(0);
    expect((await advance(HOST, chain, 3, 3, 4)).why).toBe("retired");
    expect((await record(HOST, chain, 3)).why).toBe("retired");
    expect(await call("", CHAIN, [chain.keyId])).toMatchObject({ found: true, retired: true, epoch: 3 });
    await initHost(HOST);
  });

  it("a chain stops at MAX_CHAIN_LINKS links, the length guests can still verify", async () => {
    const u = await newUser();
    const c = await initHost(u);
    // Seed 1023 links directly as owner (same rows the entry point writes), then step through the entry point.
    await db.query(`insert into vault_enclave.anon_epoch_links (key_id, from_epoch, to_epoch, next_pk, link_sig)
      select $1, g - 1, g, gen_random_bytes(96), gen_random_bytes(80) from generate_series(1, $2::int) g`, [c.keyId, MAX_CHAIN_LINKS - 1]);
    await db.query("update vault_enclave.anon_host_keys set epoch = $2, ver = $2, current_pk = gen_random_bytes(96) where key_id = $1", [c.keyId, MAX_CHAIN_LINKS - 1]);
    const last = MAX_CHAIN_LINKS - 1;
    expect(await advance(u, c, last, last, last + 1)).toMatchObject({ ok: true, epoch: MAX_CHAIN_LINKS });
    expect((await advance(u, c, MAX_CHAIN_LINKS, MAX_CHAIN_LINKS, MAX_CHAIN_LINKS + 1)).why).toBe("chain_full");
  });

  it("property: every answer of a random operation sequence matches the reference model", async () => {
    type Op =
      | { t: "advance"; stale: boolean; jump: number }
      | { t: "record"; n: number; p: number; cred: number; stale: boolean }
      | { t: "invalidate"; p: number };
    const op: fc.Arbitrary<Op> = fc.oneof(
      fc.record({ t: fc.constant("advance" as const), stale: fc.boolean(), jump: fc.integer({ min: 1, max: 3 }) }),
      fc.record({ t: fc.constant("record" as const), n: fc.integer({ min: 0, max: 4 }), p: fc.integer({ min: 0, max: 4 }), cred: fc.integer({ min: 0, max: 8 }), stale: fc.boolean() }),
      fc.record({ t: fc.constant("invalidate" as const), p: fc.integer({ min: 0, max: 4 }) }),
    );
    await fc.assert(
      fc.asyncProperty(fc.array(op, { minLength: 1, maxLength: 12 }), async (ops) => {
        const u = await newUser();
        const c = await initHost(u);
        const nullifiers = Array.from({ length: 5 }, () => randomBytes(32));
        const pseudonyms = Array.from({ length: 5 }, () => randomBytes(32));
        const m = { epoch: 0, ver: 0, head: 0, published: new Set([0]), spent: new Set<number>(), used: new Set<number>(), invalid: new Set<number>() };
        for (const o of ops) {
          if (o.t === "advance") {
            const ver = o.stale && m.ver > 0 ? m.ver - 1 : m.ver;
            const a = await advance(u, c, ver, m.epoch, m.epoch + o.jump);
            const want = ver !== m.ver ? "conflict" : "ok";
            expect(a.why).toBe(want);
            if (want === "ok") { m.epoch += o.jump; m.ver += 1; m.published.add(m.epoch); }
          } else if (o.t === "record") {
            const h = o.stale ? m.head + 1 : m.head;
            const a = await record(u, c, h, { nullifier: nullifiers[o.n], pseudonym: pseudonyms[o.p], credentialEpoch: o.cred });
            const want = m.spent.has(o.n) ? "spent" : m.used.has(o.p) ? "pseudonym_taken"
              : o.cred > m.epoch || !m.published.has(o.cred) ? "epoch" : h !== m.head ? "conflict" : "ok";
            expect(a.why).toBe(want);
            if (want === "ok") { m.head += 1; m.spent.add(o.n); m.used.add(o.p); expect(a.epoch).toBe(m.head); }
          } else {
            const a = await call(u, INVALIDATE, [c.treeId, pseudonyms[o.p], "no_show"]);
            const want = !m.used.has(o.p) ? "unknown" : m.invalid.has(o.p) ? "already" : "ok";
            expect(a.why).toBe(want);
            if (want === "ok") m.invalid.add(o.p);
          }
        }
        const roots = await db.query<{ n: number; mx: number }>("select count(*)::int as n, max(epoch)::int as mx from vault_enclave.anon_smt_roots where tree_id = $1", [c.treeId]);
        expect(roots.rows[0]).toEqual({ n: m.head + 1, mx: m.head });
      }),
      { numRuns: 25 },
    );
  }, 300_000);

  /** Every interleaving of two step lists, each kept in its own order. */
  function interleavings<T>(a: T[], b: T[]): T[][] {
    if (a.length === 0) return [b];
    if (b.length === 0) return [a];
    return [...interleavings(a.slice(1), b).map((r) => [a[0]!, ...r]), ...interleavings(a, b.slice(1)).map((r) => [b[0]!, ...r])];
  }

  it("bounded model check: every interleaving of two devices recording (read head, then write) keeps one linear tree and spends a shared nullifier once", async () => {
    type Step = { dev: 0 | 1; kind: "read" | "write"; n: 0 | 1 };
    const dev = (d: 0 | 1): Step[] => [{ dev: d, kind: "read", n: 0 }, { dev: d, kind: "write", n: 0 }, { dev: d, kind: "read", n: 1 }, { dev: d, kind: "write", n: 1 }];
    const schedules = interleavings(dev(0), dev(1));
    expect(schedules.length).toBe(70);
    for (const schedule of schedules) {
      const u = await newUser();
      const c = await initHost(u);
      const shared = randomBytes(32);
      const nulls = [[randomBytes(32), shared], [randomBytes(32), shared]];
      const seen: [number, number] = [0, 0];
      let ok = 0;
      for (const s of schedule) {
        if (s.kind === "read") { seen[s.dev] = await head(u, c); continue; }
        const a = await record(u, c, seen[s.dev], { nullifier: nulls[s.dev]![s.n] });
        expect(["ok", "conflict", "spent"]).toContain(a.why);
        if (a.ok) { ok += 1; expect(a.epoch).toBe(seen[s.dev] + 1); }
      }
      const r = await db.query<{ e: number }>("select epoch::int as e from vault_enclave.anon_smt_roots where tree_id = $1 order by epoch", [c.treeId]);
      expect(r.rows.map((x) => x.e)).toEqual(Array.from({ length: ok + 1 }, (_, i) => i));
      const t = await db.query<{ n: number; s: number }>("select count(*)::int as n, count(*) filter (where nullifier = $2)::int as s from vault_enclave.anon_booking_tokens where tree_id = $1", [c.treeId, shared]);
      expect(t.rows[0]!.n).toBe(ok);
      expect(t.rows[0]!.s).toBeLessThanOrEqual(1);
    }
  }, 300_000);

  it("bounded model check: every interleaving of two devices advancing the same chain yields one linear chain of links", async () => {
    type Step = { dev: 0 | 1; kind: "read" | "write" };
    const dev = (d: 0 | 1): Step[] => [{ dev: d, kind: "read" }, { dev: d, kind: "write" }, { dev: d, kind: "read" }, { dev: d, kind: "write" }];
    const schedules = interleavings(dev(0), dev(1));
    for (const schedule of schedules) {
      const u = await newUser();
      const c = await initHost(u);
      const seen: { epoch: number; ver: number }[] = [{ epoch: 0, ver: 0 }, { epoch: 0, ver: 0 }];
      let ok = 0;
      for (const s of schedule) {
        if (s.kind === "read") { const st = await keyState(u, c); seen[s.dev] = { epoch: st.epoch!, ver: st.ver! }; continue; }
        const v = seen[s.dev]!;
        const a = await advance(u, c, v.ver, v.epoch, v.epoch + 1 + s.dev);
        expect(["ok", "conflict"]).toContain(a.why);
        if (a.ok) ok += 1;
      }
      const links = await db.query<{ f: number; t: number }>("select from_epoch::int as f, to_epoch::int as t from vault_enclave.anon_epoch_links where key_id = $1 order by from_epoch", [c.keyId]);
      expect(links.rows.length).toBe(ok);
      let at = 0;
      for (const l of links.rows) { expect(l.f).toBe(at); at = l.t; }
      const k = await keyState(u, c);
      expect(k).toMatchObject({ epoch: at, ver: ok });
    }
  }, 300_000);

  it("every anon writer ran and the hash-chained audit log holds all of them", async () => {
    const a = await db.query<{ action: string }>("select distinct action from vault_enclave.audit_logs where action like 'anon\\_%' order by 1");
    expect(a.rows.map((r) => r.action)).toEqual(ANON_ACTIONS);
    const ok = await db.query<{ ok: boolean }>("select vault_enclave.verify_audit_chain() as ok");
    expect(ok.rows[0]!.ok).toBe(true);
    const leaks = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.audit_logs where action like 'anon\\_%' and token_ref is not null");
    expect(leaks.rows[0]!.n).toBe(0);
  });

  it("the rollback refuses once anonymous booking data or audit entries exist", async () => {
    await expect(db.exec(`begin;\n${ROLLBACK}\n;commit;`)).rejects.toThrow(/not empty|immutable/);
    await db.exec("rollback").catch(() => undefined);
    expect((await db.query<{ r: string | null }>("select to_regclass('vault_enclave.anon_booking_tokens')::text as r")).rows[0]!.r).not.toBeNull();
  });
});
