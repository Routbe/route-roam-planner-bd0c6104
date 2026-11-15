// @vitest-environment node
/**
 * Stap 9: formal RLS non-interference.
 *
 * Part 1 runs scripts/formal-rls-verifier.ts on db/schema.snapshot.json, which
 * is the replay of db/ (0275 since the owner's GO of 2026-11-15). Z3 must prove
 * Eval(policy, u1, Row(u2)) = FALSE for every reachable obligation except the
 * reviewed exceptions, and it must catch deliberately broken policies.
 * Part 2 replays db/ on PGlite and attacks it as rout_app: cross-tenant reads and
 * writes, forged rows, every rout_app-callable SECURITY DEFINER function with
 * injection payloads and the other member's id, and the vault_enclave lockout.
 * It also shows that 0275 closes F4/F5/F7/F8a (the held rollback reopens them
 * and is idempotent). Nothing touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { readCatalog, type Catalog } from "../../scripts/schema-catalog";
import { migrationDefinerGuardSql, migrationDefinerViolations } from "../../scripts/security-definer-policy";
import { Verifier, loadSnapshot, type Report } from "../../scripts/formal-rls-verifier";
import { parsePolicyExpr } from "../../scripts/formal-rls/sql-expr";
import { F8A, INVOKER_VIEWS, KNOWN_OPEN } from "../../scripts/formal-rls/tenant-model";
import { CODE_SCHEMA_LEVEL } from "@/lib/schema-version";
import { contextStatements } from "@/lib/db-context";

const ROOT = join(__dirname, "..", "..");
const FILE = "0275_rls_non_interference_hardening.sql";
const SQL = readFileSync(join(ROOT, "db", FILE), "utf8");
const ROLLBACK = readFileSync(join(ROOT, "db-pending", "0275_rls_non_interference_hardening_rollback.sql"), "utf8");
/** Verifier findings that db/0275 closed (F4, F5, F7, F8a). */
const FIXED_BY_0275 = [
  "view:public.profile_handles:writable_definer_view", "view:public.public_profiles:writable_definer_view", "view:auth.users:definer_read",
  "rls:public.workspace_members:INSERT:check", "rls:public.workspace_members:UPDATE:check",
  ...F8A.map((t) => `rls:public.${t}:INSERT:check`),
];
const clone = (c: Catalog) => JSON.parse(JSON.stringify(c)) as Catalog;
const known = new Set(KNOWN_OPEN.map((k) => k.id));

describe("Z3 proof over the 0275 schema snapshot", () => {
  const snapshot = loadSnapshot(ROOT);
  let report: Report;
  beforeAll(async () => { report = await new Verifier(snapshot).run(); }, 120_000);

  it("0275 is in db/ at schema level 0275, with its rollback held in db-pending/", () => {
    expect(CODE_SCHEMA_LEVEL >= "0275").toBe(true);
    expect(readdirSync(join(ROOT, "db")).filter((f) => f.startsWith("0275"))).toEqual([FILE]);
    expect(existsSync(join(ROOT, "db-pending", FILE))).toBe(false);
    expect(existsSync(join(ROOT, "db-pending", "0275_rls_non_interference_hardening_rollback.sql"))).toBe(true);
    expect(migrationDefinerViolations(FILE, SQL)).toEqual([]);
  });

  it("proves every reachable obligation except the reviewed exceptions, with no unparsed policy", () => {
    const unproven = report.obligations.filter((o) => o.outcome.status === "unproven");
    expect(unproven.filter((o) => o.outcome.status === "unproven" && o.outcome.why === "unsupported")).toEqual([]);
    expect(report.smtChecks).toBeGreaterThan(500);
    expect(report.obligations.filter((o) => o.outcome.status === "proven" && o.outcome.via === "smt").length).toBeGreaterThan(450);
    expect(report.findings.map((f) => f.id).filter((id) => !known.has(id))).toEqual([]);
    expect(report.unusedModelEntries).toEqual([]);
  });

  it("vault_enclave is closed and every SECURITY DEFINER pins pg_catalog, pg_temp", () => {
    expect(report.enclave.tables).toBe(32);
    expect(report.enclave.findings).toEqual([]);
    expect(report.searchPath.definers).toBeGreaterThan(400);
    expect(report.searchPath.findings).toEqual([]);
  });

  it("an owner policy is proven non-interferent: user_id = rout_current_user_id() never admits a stranger's row", () => {
    const o = report.obligations.find((x) => x.table === "public.guestbook_entries" && x.cmd === "SELECT");
    expect(o?.outcome).toEqual({ status: "proven", via: "smt" });
    // Parent-scoped rows (calendar_events through connected_calendars, qr_scans through the pinned lemma) too.
    for (const t of ["public.calendar_events", "public.feedback_responses", "public.qr_scans"]) {
      expect(report.obligations.filter((x) => x.table === t && x.outcome.status !== "proven")).toEqual([]);
    }
  });

  const mutate = async (fn: (c: Catalog) => void) => {
    const c = clone(snapshot);
    fn(c);
    return new Verifier(c).run();
  };
  const policy = (c: Catalog, table: string, name: string) => c.tables.find((t) => t.schema === "public" && t.name === table)!.policies.find((p) => p.name === name)!;

  it("catches broken policies: a counterexample for each mutation", async () => {
    const g = snapshot.tables.find((t) => t.name === "guestbook_entries")!.policies.find((p) => p.cmd !== "ALL" || p.roles.includes("public"))!;
    const cases: [string, (c: Catalog) => void, string][] = [
      ["inverted owner check", (c) => { policy(c, "guestbook_entries", g.name).using = "(owner_id <> rout_current_user_id())"; }, "rls:public.guestbook_entries:SELECT:using"],
      ["any signed-in caller", (c) => { policy(c, "guestbook_entries", g.name).using = "((owner_id = rout_current_user_id()) OR (rout_current_user_id() IS NOT NULL))"; }, "rls:public.guestbook_entries:SELECT:using"],
      ["parent check dropped", (c) => { const t = c.tables.find((x) => x.name === "calendar_events")!; t.policies[0]!.using = "(EXISTS ( SELECT 1 FROM bookings b WHERE (b.id = calendar_events.calendar_id)))"; }, "rls:public.calendar_events"],
      ["NULL comparison is not TRUE, but IS NULL is", (c) => { policy(c, "guestbook_entries", g.name).using = "((owner_id = rout_current_user_id()) OR (rout_current_user_id() IS NULL))"; }, "rls:public.guestbook_entries:SELECT:using"],
      ["WITH CHECK lets a row be handed to someone else", (c) => { const t = c.tables.find((x) => x.name === "guestbook_entries")!; for (const p of t.policies) if (p.cmd === "ALL" || p.cmd === "UPDATE") p.check = "true"; }, "rls:public.guestbook_entries:UPDATE:check"],
      ["vault table granted to rout_app", (c) => { c.tables.find((t) => t.schema === "vault_enclave" && t.name === "server_keys")!.grants.rout_app = ["SELECT"]; }, "enclave:vault_enclave.server_keys:grants"],
      ["definer without pinned search_path", (c) => { const f = c.functions.find((x) => x.name === "rout_is_workspace_member")!; f.def = f.def.replace("SET search_path TO 'pg_catalog', 'pg_temp'", "SET search_path TO 'public'"); }, "search_path:public.rout_is_workspace_member"],
    ];
    for (const [label, fn, prefix] of cases) {
      const r = await mutate(fn);
      expect(r.findings.some((f) => f.id.startsWith(prefix)), label).toBe(true);
    }
  }, 240_000);

  it("the qr_scans lemma is pinned to the function body: a changed body makes the policy unproven", async () => {
    const r = await mutate((c) => { const f = c.functions.find((x) => x.name === "rout_accessible_tracked_qr_ids")!; f.def = f.def.replace("t.user_id = public.rout_current_user_id()", "true"); });
    expect(r.findings.some((f) => f.id.startsWith("rls:public.qr_scans:"))).toBe(true);
  }, 120_000);

  it("parses every policy expression in the snapshot", () => {
    for (const t of snapshot.tables) for (const p of t.policies) for (const e of [p.using, p.check]) if (e) expect(() => parsePolicyExpr(e), `${t.name}.${p.name}`).not.toThrow();
  });
});

// ---------------------------------------------------------------- PGlite attacks
const A = "00000000-0000-4000-8000-00000000000a";
const B = "00000000-0000-4000-8000-00000000000b";
const B_MARK = "bob-secret-7f3c";

describe("multi-tenant attacks on a replay of db/ (PGlite)", () => {
  let db: PGlite;
  const ids: Record<string, string> = {};

  const as = async <T = Record<string, unknown>>(user: string | null, query: string, params: unknown[] = []) => {
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      for (const st of contextStatements({ userId: user, workspaceId: null })) await db.query(st.query, st.params as unknown[]);
      const r = await db.query<T>(query, params);
      await db.exec("commit");
      return r;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const fingerprintB = async () => {
    const parts: string[] = [];
    for (const [t, w] of OWNED) parts.push(JSON.stringify((await db.query(`select to_jsonb(x) - 'updated_at' as r from public.${t} x where ${w} order by 1::text`, [B])).rows));
    return parts.join("|");
  };
  const OWNED: [string, string][] = [
    ["users", "id = $1"], ["profiles", "id = $1"], ["connected_calendars", "user_id = $1"],
    ["calendar_events", "calendar_id in (select id from public.connected_calendars where user_id = $1)"],
    ["feedback_forms", "user_id = $1"], ["feedback_responses", "form_id in (select id from public.feedback_forms where user_id = $1)"],
    ["tracked_qrs", "user_id = $1"], ["qr_scans", "tracked_qr_id in (select id from public.tracked_qrs where user_id = $1)"],
    ["guestbook_entries", "owner_id = $1"], ["workspace_members", "user_id = $1"],
  ];

  beforeAll(async () => {
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    for (const s of planMigrations(listMigrationFiles(dir), new Set())) if (s.action === "run") await db.exec(`begin;\n${readFileSync(join(dir, s.file), "utf8")}\n;commit;`);
    for (const [u, tag] of [[A, "alice"], [B, "bob"]] as const) {
      const mail = u === B ? `${B_MARK}@example.test` : "alice@example.test";
      await db.query(`insert into public.users (id, email) values ($1, $2)`, [u, mail]);
      await db.query(`insert into public.profiles (id, username) values ($1, $2) on conflict (id) do update set username = excluded.username`, [u, `${tag}rls`]);
      const cal = await db.query<{ id: string }>(`insert into public.connected_calendars (user_id, adapter, credentials_ciphertext, credentials_iv, label) values ($1, 'ics', $2, 'iv', $2) returning id`, [u, `${tag}-cal`]);
      ids[`${tag}Cal`] = cal.rows[0]!.id;
      await db.query(`insert into public.calendar_events (calendar_id, provider_id, start_utc, end_utc) values ($1, $2, now(), now() + interval '1 hour')`, [ids[`${tag}Cal`], (tag === "bob" ? "b" : "a").repeat(64)]);
      const form = await db.query<{ id: string }>(`insert into public.feedback_forms (user_id, title, profile_space, profile_handle) values ($1, $2, 'root', $3) returning id`, [u, `${tag} form`, `${tag}rls`]);
      ids[`${tag}Form`] = form.rows[0]!.id;
      await db.query(`insert into public.feedback_responses (form_id, comment) values ($1, $2)`, [ids[`${tag}Form`], u === B ? B_MARK : "hi"]);
      const qr = await db.query<{ id: string }>(`insert into public.tracked_qrs (user_id, slug, dashboard_token, target_type, target_url) values ($1, $2, $3, 'url', 'https://rout.be') returning id`, [u, `${tag}-qr`, `${tag}-token-${"x".repeat(20)}`]);
      ids[`${tag}Qr`] = qr.rows[0]!.id;
      await db.query(`insert into public.qr_scans (tracked_qr_id, country) values ($1, 'BE')`, [ids[`${tag}Qr`]]);
      const g = await db.query<{ id: string }>(`insert into public.guestbook_entries (owner_id, author_id, body) values ($1, $1, $2) returning id`, [u, u === B ? B_MARK : "hello"]);
      ids[`${tag}Guest`] = g.rows[0]!.id;
      const ws = await db.query<{ id: string }>(`insert into public.workspaces (name, slug) values ($1, $2) returning id`, [`${tag} ws`, `${tag}-ws-rls`]);
      ids[`${tag}Ws`] = ws.rows[0]!.id;
      await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner')`, [ids[`${tag}Ws`], u]);
    }
  }, 300_000);
  afterAll(async () => db?.close());

  it("rout_app is an ordinary role: no superuser, no BYPASSRLS, no membership in the executor roles, owns no table", async () => {
    const r = await db.query<Record<string, unknown>>(`select rolsuper, rolbypassrls, pg_has_role('rout_app', 'rout_merge_executor', 'member') as merge,
      pg_has_role('rout_app', 'rout_omni_worker', 'member') as omni,
      (select count(*)::int from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relowner = 'rout_app'::regrole and n.nspname in ('public','vault_enclave','auth','neon_auth')) as owned
      from pg_roles where rolname = 'rout_app'`);
    expect(r.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false, merge: false, omni: false, owned: 0 });
  });

  it("cross-tenant reads, updates and deletes reach none of Bob's rows (signed in as Alice, and signed out)", async () => {
    for (const user of [A, null]) {
      for (const [t, w] of OWNED) {
        if (t === "users" || t === "profiles") continue;
        const c = await as<{ n: number }>(user, `select count(*)::int as n from public.${t} where ${w}`, [B]);
        expect(c.rows[0]!.n, `${t} visible to ${user ?? "anonymous"}`).toBe(0);
        const u = await as(user, `update public.${t} set ${t === "workspace_members" ? "role = role" : "id = id"} where ${w}`, [B]).catch((e: Error) => e);
        expect(u instanceof Error ? 0 : u.affectedRows, `${t} update`).toBe(0);
        const d = await as(user, `delete from public.${t} where ${w}`, [B]).catch((e: Error) => e);
        expect(d instanceof Error ? 0 : d.affectedRows, `${t} delete`).toBe(0);
      }
      const own = await as<{ n: number }>(user, `select count(*)::int as n from public.users where id = $1`, [B]);
      expect(own.rows[0]!.n).toBe(0);
    }
    // Alice still sees her own rows, so the zeros above are not a blanket denial.
    const mine = await as<{ n: number }>(A, `select count(*)::int as n from public.guestbook_entries where owner_id = $1`, [A]);
    expect(mine.rows[0]!.n).toBe(1);
  });

  it("forged rows are refused: Bob as owner, Bob's parent rows, joining Bob's workspace, handing a row to Bob", async () => {
    const passed: string[] = [];
    const refuse = async (q: string, p: unknown[]) => {
      const r = await as(A, q, p).then(() => "accepted", (e: Error) => (/row-level security|permission denied/.test(e.message) ? "refused" : e.message));
      if (r !== "refused") passed.push(`${q} → ${r}`);
    };
    await refuse(`insert into public.guestbook_entries (owner_id, author_id, body) values ($1, $1, 'x')`, [B]);
    await refuse(`insert into public.feedback_responses (form_id, comment) values ($1, 'x')`, [ids.bobForm]);
    await refuse(`insert into public.calendar_events (calendar_id, provider_id, start_utc, end_utc) values ($1, $2, now(), now() + interval '1 hour')`, [ids.bobCal, "c".repeat(64)]);
    await refuse(`update public.guestbook_entries set owner_id = $1 where id = $2`, [B, ids.aliceGuest]);
    await refuse(`update public.connected_calendars set user_id = $1 where id = $2`, [B, ids.aliceCal]);
    expect(passed).toEqual([]);
  });

  it("F7 is closed since 0275: Alice cannot add herself to Bob's workspace, and a viewer cannot promote herself", async () => {
    expect(await as(A, `insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'viewer')`, [ids.bobWs, A]).then(() => "accepted", () => "refused")).toBe("refused");
    await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'viewer')`, [ids.bobWs, A]);
    const up = await as(A, `update public.workspace_members set role = 'owner' where workspace_id = $1 and user_id = $2`, [ids.bobWs, A]).then((r) => r.affectedRows, () => 0);
    expect(up).toBe(0);
    await db.query(`delete from public.workspace_members where workspace_id = $1 and user_id = $2`, [ids.bobWs, A]);
  });

  it("finding F9 is real: rout_resolve_account gives any signed-in member another member's e-mail address for a @handle", async () => {
    const r = await as<{ email: string }>(A, `select email from public.rout_resolve_account('bobrls')`);
    expect(r.rows[0]?.email).toBe(`${B_MARK}@example.test`);
  });

  it("vault_enclave cannot be reached or reopened from rout_app", async () => {
    const tables = (await db.query<{ t: string }>(`select c.relname as t from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'vault_enclave' and c.relkind = 'r' order by 1`)).rows.map((r) => r.t);
    expect(tables.length).toBe(32);
    for (const t of tables) {
      const priv = await db.query<{ any: boolean; rls: boolean }>(`select (has_table_privilege('rout_app', $1, 'select,insert,update,delete,truncate,references,trigger')
        or has_table_privilege('public', $1, 'select,insert,update,delete,truncate,references,trigger')) as any,
        (select relrowsecurity from pg_class where oid = $1::regclass) as rls`, [`vault_enclave.${t}`]);
      expect(priv.rows[0], t).toEqual({ any: false, rls: true });
      await expect(as(A, `select * from vault_enclave.${t} limit 1`)).rejects.toThrow(/permission denied/);
      await expect(as(A, `delete from vault_enclave.${t}`)).rejects.toThrow(/permission denied/);
    }
    for (const q of [
      "alter table vault_enclave.server_keys disable row level security",
      "grant select on vault_enclave.server_keys to rout_app",
      "create function vault_enclave.x() returns int language sql as 'select 1'",
      "create table vault_enclave.x (id int)",
    ]) {
      const r = await as(A, q).then(() => "accepted", () => "refused");
      expect(`${q} → ${r}`).toBe(`${q} → refused`);
    }
    const schema = await db.query<{ create: boolean; usage: boolean }>(`select has_schema_privilege('rout_app', 'vault_enclave', 'CREATE') as create, has_schema_privilege('rout_app', 'vault_enclave', 'USAGE') as usage`);
    expect(schema.rows[0]).toEqual({ create: false, usage: true });
    // (SET ROLE is not tried: PGlite's session user is a superuser; on Neon the session user is rout_app itself.)
    const acl = await db.query<{ n: number }>(`select count(*)::int as n from pg_default_acl d join pg_namespace n on n.oid = d.defaclnamespace where n.nspname = 'vault_enclave' and array_to_string(d.defaclacl, ',') like '%rout_app%'`);
    expect(acl.rows[0]!.n).toBe(0);
  });

  it("every rout_app-callable SECURITY DEFINER, fed injection payloads and Bob's id as Alice, leaves Bob's rows unchanged and returns none of his secrets", async () => {
    const fns = (await db.query<{ schema: string; name: string; types: string[] }>(`select n.nspname as schema, p.proname as name,
        array(select format_type(t, null) from unnest(p.proargtypes) t) as types
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where p.prosecdef and p.prokind = 'f' and n.nspname in ('public', 'vault_enclave', 'auth')
        and p.prorettype <> 'trigger'::regtype and has_function_privilege('rout_app', p.oid, 'EXECUTE') and p.pronargs <= 8
      order by 1, 2`)).rows;
    expect(fns.length).toBeGreaterThan(50);
    const before = await fingerprintB();
    const relations = (await db.query<{ n: number }>(`select count(*)::int as n from pg_class`)).rows[0]!.n;
    const payloads = ["'); drop table public.profiles; --", "' or '1'='1", B, `${B_MARK}@example.test`];
    const leaks: string[] = [];
    let calls = 0;
    for (const f of fns) {
      for (const pay of payloads) {
        const args = f.types.map((t) => {
          if (t === "uuid") return B;
          if (t === "text" || t === "character varying" || t === "citext") return pay;
          if (t === "jsonb" || t === "json") return JSON.stringify({ user_id: B, id: B, q: pay });
          if (t === "uuid[]") return [B];
          if (t === "text[]") return [pay];
          if (t === "boolean") return true;
          if (/^(integer|bigint|smallint|numeric)$/.test(t)) return 1;
          return null;
        });
        const sql = `select coalesce((select jsonb_agg(to_jsonb(r))::text from ${f.schema}.${JSON.stringify(f.name).slice(1, -1)}(${f.types.map((t, i) => `$${i + 1}::${t}`).join(", ")}) as r), '') as out`;
        calls++;
        const out = await as<{ out: string }>(A, `set local statement_timeout = '2s'; ${sql}`.split("; ")[1]!, args).catch(() => null);
        if (out?.rows[0]?.out.includes(B_MARK)) leaks.push(`${f.schema}.${f.name}`);
      }
    }
    expect(calls).toBeGreaterThan(200);
    // F9 (rout_resolve_account) is the one known leak; it is tracked in the HANDOVER appendix.
    expect(leaks).toEqual(["public.rout_resolve_account"]);
    expect(await fingerprintB()).toBe(before);
    expect((await db.query<{ n: number }>(`select count(*)::int as n from pg_class`)).rows[0]!.n).toBe(relations);
  }, 300_000);

  it("finding F6 is real: a duplicate-key error tells Alice that Bob's e-mail address exists", async () => {
    const e = await as(A, `update public.users set email = $1 where id = $2`, [`${B_MARK}@example.test`, A]).catch((x: Error & { code?: string }) => x);
    expect(e instanceof Error && /duplicate key|unique/i.test(e.message)).toBe(true);
  });

  it("0275 keeps F4, F5, F7 and F8a closed without breaking the legitimate flows; the held rollback reopens them, is idempotent, and 0275 re-applies", async () => {
    const attack = async () => ({
      rewrite: await as(A, `update public.public_profiles set bio = 'pwned' where id = $1`, [B]).then((r) => r.affectedRows ?? 0, () => 0),
      handle: await as(A, `update public.profile_handles set username = username where username = 'bobrls'`).then((r) => r.affectedRows ?? 0, () => 0),
      emails: await as<{ n: number }>(A, `select count(*)::int as n from auth.users where email like $1`, [`${B_MARK}%`]).then((r) => r.rows[0]!.n, () => 0),
      ownEmail: await as<{ n: number }>(A, `select count(*)::int as n from auth.users where id = $1`, [A]).then((r) => r.rows[0]!.n, () => -1),
      publicRead: await as<{ n: number }>(null, `select count(*)::int as n from public.public_profiles where username = 'bobrls'`).then((r) => r.rows[0]!.n, () => -1),
      selfJoin: await as(A, `insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner')`, [ids.bobWs, A]).then(() => 1, () => 0),
      plant: await as(A, `insert into public.tracked_qrs (user_id, workspace_id, slug, dashboard_token, target_type, target_url) values ($1, $2, 'plant-qr', 'plant-token-xxxxxxxxxxxxxxxx', 'url', 'https://rout.be')`, [A, ids.bobWs]).then(() => 1, () => 0),
    });
    const cleanup = async () => {
      await db.query(`update public.profiles set bio = null where id = $1`, [B]);
      await db.query(`delete from public.workspace_members where workspace_id = $1 and user_id = $2`, [ids.bobWs, A]);
      await db.query(`delete from public.tracked_qrs where slug = 'plant-qr'`);
    };
    let n = 0;
    const legit = async () => {
      n++;
      // Creating a workspace and becoming its owner in one transaction (workspaces.functions.ts).
      const ws = `00000000-0000-4000-a000-${String(n).padStart(12, "0")}`;
      await db.exec("begin");
      await db.exec("set local role rout_app");
      for (const st of contextStatements({ userId: A, workspaceId: null })) await db.query(st.query, st.params as unknown[]);
      await db.query(`insert into public.workspaces (id, name, slug) values ($1, 'Alice ws', $2)`, [ws, `alice-new-${n}`]);
      await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'admin')`, [ws, A]);
      await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner')`, [ws, B]); // conversion: the admin adds the owner
      await db.exec("commit");
      // A second statement later (admin-grant.server.ts) on a fresh workspace still works.
      const ws2 = `00000000-0000-4000-b000-${String(n).padStart(12, "0")}`;
      await as(A, `insert into public.workspaces (id, name, slug) values ($1, 'Alice ws 2', $2)`, [ws2, `alice-new2-${n}`]);
      await as(A, `insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner') on conflict do nothing`, [ws2, A]);
      // Rows go into a workspace the caller belongs to.
      await as(A, `insert into public.tracked_qrs (user_id, workspace_id, slug, dashboard_token, target_type, target_url) values ($1, $2, $3, $4, 'url', 'https://rout.be')`, [A, ws, `own-qr-${n}`, `own-token-${n}-xxxxxxxxxxxxxxxx`]);
      // The owner changes a role, the member sees the team, and a member can leave.
      const promoted = await as(B, `update public.workspace_members set role = 'editor' where workspace_id = $1 and user_id = $2`, [ws, A]);
      const team = await as<{ n: number }>(A, `select count(*)::int as n from public.workspace_members where workspace_id = $1`, [ws]);
      const left = await as(A, `delete from public.workspace_members where workspace_id = $1 and user_id = $2`, [ws, A]);
      return { promoted: promoted.affectedRows, team: team.rows[0]!.n, left: left.affectedRows };
    };
    const verify = async () => {
      const cat = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
      const opts = (await db.query<{ k: string; o: string[] | null }>(`select n.nspname || '.' || c.relname as k, c.reloptions as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v'`)).rows;
      return new Verifier(cat, Object.fromEntries(opts.map((r) => [r.k, r.o ?? []]))).run();
    };
    const CLOSED = { rewrite: 0, handle: 0, emails: 0, ownEmail: 1, publicRead: 1, selfJoin: 0, plant: 0 };
    expect(await attack()).toEqual(CLOSED);
    expect(await legit()).toEqual({ promoted: 1, team: 2, left: 1 });
    // An old workspace without members cannot be claimed.
    await db.query(`insert into public.workspaces (id, name, slug, created_at) values ('00000000-0000-4000-c000-000000000001', 'old', 'old-orphan-ws', now() - interval '1 day')`);
    expect(await as(A, `insert into public.workspace_members (workspace_id, user_id, role) values ('00000000-0000-4000-c000-000000000001', $1, 'owner')`, [A]).then(() => 1, () => 0)).toBe(0);
    const v1 = await verify();
    expect(v1.findings.map((f) => f.id).filter((id) => FIXED_BY_0275.includes(id))).toEqual([]);
    expect(v1.findings.map((f) => f.id).filter((id) => !known.has(id))).toEqual([]);
    expect(v1.unusedModelEntries).toEqual([]);
    const fn = await db.query<{ pub: boolean; app: boolean }>(`select has_function_privilege('public', 'public.rout_workspace_claimable(uuid)', 'execute') as pub, has_function_privilege('rout_app', 'public.rout_workspace_claimable(uuid)', 'execute') as app`);
    expect(fn.rows[0]).toEqual({ pub: false, app: true });

    // The held rollback (twice: idempotent) restores 0274, where every finding is open again.
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    await db.exec(`begin;\n${ROLLBACK}\n;commit;`);
    expect(await attack()).toEqual({ rewrite: 1, handle: 1, emails: 1, ownEmail: 1, publicRead: 1, selfJoin: 1, plant: 1 });
    await cleanup();
    const v0 = await verify();
    for (const id of FIXED_BY_0275) expect(v0.findings.map((f) => f.id)).toContain(id);
    expect(await legit()).toEqual({ promoted: 1, team: 2, left: 1 });

    await db.exec(`begin;\n${SQL}\n;\n${migrationDefinerGuardSql(FILE)};\ncommit;`);
    expect(await attack()).toEqual(CLOSED);
    expect((await verify()).findings.map((f) => f.id).sort()).toEqual(v1.findings.map((f) => f.id).sort());
    await cleanup();
  }, 180_000);

  it("the reviewed list of security_invoker views matches the database", async () => {
    const r = await db.query<{ k: string }>(`select n.nspname || '.' || c.relname as k from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where c.relkind = 'v' and 'security_invoker=true' = any(coalesce(c.reloptions, '{}')) order by 1`);
    expect(r.rows.map((x) => x.k)).toEqual([...INVOKER_VIEWS].sort());
  });
});
