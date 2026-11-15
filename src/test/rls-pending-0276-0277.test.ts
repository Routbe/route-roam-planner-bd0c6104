// @vitest-environment node
/**
 * Stap 10 part II: db/0276 (EXPAND, released 2026-11-15) and the held-back db-pending/0277 (CONTRACT).
 * Replays db/ (0275) on PGlite, shows F1, F2, F3, F8b and F9 are real there, then applies 0276 and
 * 0277 and shows each is closed while the legitimate flows keep working, that the Z3 verifier
 * proves the result (only the reviewed 0277 declassification of public profile columns is added),
 * and that both rollbacks are idempotent and re-applicable. Nothing touches Neon.
 */
import { PGlite } from "@electric-sql/pglite";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { readCatalog } from "../../scripts/schema-catalog";
import { migrationDefinerGuardSql, migrationDefinerViolations } from "../../scripts/security-definer-policy";
import { Verifier } from "../../scripts/formal-rls-verifier";
import { CLOSED_BY_0276, F8A, KNOWN_OPEN, PENDING_0277_DECLASSIFIED, PRIVATE_PROFILE_COLUMNS } from "../../scripts/formal-rls/tenant-model";
import { contextStatements } from "@/lib/db-context";

const ROOT = join(__dirname, "..", "..");
const read = (f: string) => readFileSync(join(ROOT, "db-pending", f), "utf8");
const F76 = "0276_tenant_column_expand.sql", F77 = "0277_private_columns_contract.sql";
const SQL76 = readFileSync(join(ROOT, "db", F76), "utf8"), SQL77 = read(F77);
const RB76 = read("0276_tenant_column_expand_rollback.sql"), RB77 = read("0277_private_columns_contract_rollback.sql");
const A = "00000000-0000-4000-8000-00000000000a";
const B = "00000000-0000-4000-8000-00000000000b";
const MARK = "bob-private-91d2";
/** KNOWN_OPEN entries 0276 + 0277 close: F1, F2, F3 and every F8b entry. */
const OPEN_UNTIL_0277 = KNOWN_OPEN.map((k) => k.id).filter((id) => !id.startsWith("oracle:"));
const CLOSED = [...CLOSED_BY_0276, ...OPEN_UNTIL_0277];

describe("db-pending/0276 + 0277 on a replay of db/ (PGlite)", () => {
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
  const ok = (user: string | null, q: string, p: unknown[] = []) => as(user, q, p).then((r) => r.affectedRows || r.rows.length, (e: Error) => `refused: ${e.message.slice(0, 60)}`);
  const apply = async (file: string, body: string) => db.exec(`begin;\n${body}\n;\n${migrationDefinerGuardSql(file)};\ncommit;`);
  const verify = async () => {
    const cat = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
    const opts = (await db.query<{ k: string; o: string[] | null }>(`select n.nspname || '.' || c.relname as k, c.reloptions as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v'`)).rows;
    return new Verifier(cat, Object.fromEntries(opts.map((r) => [r.k, r.o ?? []])), { declassified: PENDING_0277_DECLASSIFIED }).run();
  };

  /** Each attack returns whether it got through. */
  const attacks = async () => {
    const r: Record<string, boolean> = {};
    const n = Math.random().toString(36).slice(2, 8);
    r.F3_legacy = typeof (await ok(A, `insert into public.workspaces (name, slug, legacy_user_id) values ('x', $1, $2)`, [`f3-${n}`, B])) === "number";
    r.F8b_move_qr = (await ok(A, `update public.tracked_qrs set workspace_id = $1 where id = $2`, [ids.bobWs, ids.aliceQr])) === 1;
    r.F8b_move_user = (await ok(A, `update public.users set migrated_to_workspace_id = $1 where id = $2`, [ids.bobWs, A])) === 1;
    r.F8b_move_profile = (await ok(A, `update public.profiles set workspace_id = $1 where id = $2`, [ids.bobWs, A])) === 1;
    r.F2_code = ((await as<{ v: string }>(null, `select verification_code as v from public.social_links where profile_id = $1`, [B]).then((x) => x.rows, () => []))[0]?.v ?? "") === `${MARK}-code`;
    r.F1_email = ((await as<{ v: string }>(null, `select email as v from public.profiles where id = $1`, [B]).then((x) => x.rows, () => []))[0]?.v ?? "") === `${MARK}@example.test`;
    r.F1_legal = ((await as<{ v: string }>(A, `select legal_last_name as v from public.profiles where id = $1`, [B]).then((x) => x.rows, () => []))[0]?.v ?? "") === MARK;
    r.F9_handle = ((await as<{ v: string | null }>(A, `select email as v from public.rout_resolve_account('bobrls')`).then((x) => x.rows, () => []))[0]?.v ?? "").includes(MARK);
    // restore what a successful attack changed
    await db.query(`update public.tracked_qrs set workspace_id = null where id = $1`, [ids.aliceQr]);
    await db.query(`update public.users set migrated_to_workspace_id = null where id = $1`, [A]);
    await db.query(`update public.profiles set workspace_id = null where id = $1`, [A]);
    await db.query(`delete from public.workspaces where slug like 'f3-%'`);
    return r;
  };
  const ALL_OPEN = { F3_legacy: true, F8b_move_qr: true, F8b_move_user: true, F8b_move_profile: true, F2_code: true, F1_email: true, F1_legal: true, F9_handle: true };

  /** Flows the app relies on; each must keep working at every stage. */
  const legit = async (stage: string) => {
    const n = `${stage}-${Math.random().toString(36).slice(2, 8)}`;
    const ws = (await db.query<{ id: string }>(`select gen_random_uuid() as id`)).rows[0]!.id;
    // Conversion (asSource): workspace with the caller as legacy account, caller added, own rows moved in.
    await db.exec("begin");
    await db.exec("set local role rout_app");
    for (const st of contextStatements({ userId: A, workspaceId: null })) await db.query(st.query, st.params as unknown[]);
    await db.query(`insert into public.workspaces (id, name, slug, legacy_user_id) values ($1, 'conv', $2, $3)`, [ws, `conv-${n}`, A]);
    await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'admin')`, [ws, A]);
    await db.query(`update public.profiles set workspace_id = $1 where id = $2`, [ws, A]);
    await db.query(`update public.tracked_qrs set workspace_id = $1 where id = $2`, [ws, ids.aliceQr]);
    await db.query(`update public.users set migrated_to_workspace_id = $1 where id = $2`, [ws, A]);
    await db.exec("commit");
    // After leaving, Alice may still edit her own row that stays in that workspace (reference kept).
    await db.query(`delete from public.workspace_members where workspace_id = $1 and user_id = $2`, [ws, A]);
    const kept = await ok(A, `update public.tracked_qrs set target_url = 'https://rout.be/kept' where id = $1`, [ids.aliceQr]);
    const keptUser = await ok(A, `update public.users set last_sign_in_at = now() where id = $1`, [A]);
    // Public profile page and the owner's own row.
    const pub = await ok(null, `select username, display_name, verified from public.profiles where id = $1`, [B]);
    const view = await ok(null, `select username from public.public_profiles where username = 'bobrls'`);
    await db.query(`update public.tracked_qrs set workspace_id = null where id = $1`, [ids.aliceQr]);
    await db.query(`update public.users set migrated_to_workspace_id = null where id = $1`, [A]);
    await db.query(`update public.profiles set workspace_id = null where id = $1`, [A]);
    return { kept, keptUser, pub, view };
  };

  beforeAll(async () => {
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const dir = join(ROOT, "db");
    // db/ up to 0275: 0276 is released (db/) but applied by this test step by step.
    for (const s of planMigrations(listMigrationFiles(dir).filter((f) => f < F76), new Set())) if (s.action === "run") await db.exec(`begin;\n${readFileSync(join(dir, s.file), "utf8")}\n;commit;`);
    for (const [u, tag] of [[A, "alice"], [B, "bob"]] as const) {
      const mail = u === B ? `${MARK}@example.test` : "alice@example.test";
      await db.query(`insert into public.users (id, email, email_normalized, account_status) values ($1, $2, $2, 'active') on conflict (id) do nothing`, [u, mail]).catch(async () => db.query(`insert into public.users (id, email) values ($1, $2)`, [u, mail]));
      await db.query(`insert into public.profiles (id, username, email, legal_first_name, legal_last_name, last_city) values ($1, $2, $3, $4, $4, $4)
        on conflict (id) do update set username = excluded.username, email = excluded.email, legal_first_name = excluded.legal_first_name, legal_last_name = excluded.legal_last_name, last_city = excluded.last_city`, [u, `${tag}rls`, mail, u === B ? MARK : "Alice"]);
      await db.query(`insert into public.social_links (profile_id, platform, username, is_verified, verification_code, last_error) values ($1, 'github', $2, true, $3, $3)`, [u, `${tag}gh`, u === B ? `${MARK}-code` : "alice-code"]);
      const qr = await db.query<{ id: string }>(`insert into public.tracked_qrs (user_id, slug, dashboard_token, target_type, target_url) values ($1, $2, $3, 'url', 'https://rout.be') returning id`, [u, `${tag}-pq`, `${tag}-ptoken-${"x".repeat(20)}`]);
      ids[`${tag}Qr`] = qr.rows[0]!.id;
      const ws = await db.query<{ id: string }>(`insert into public.workspaces (name, slug) values ($1, $2) returning id`, [`${tag} ws`, `${tag}-ws-p`]);
      ids[`${tag}Ws`] = ws.rows[0]!.id;
      await db.query(`insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner')`, [ids[`${tag}Ws`], u]);
    }
    await db.query(`update public.users set email_normalized = lower(email), account_status = 'active' where id in ($1, $2)`, [A, B]).catch(() => undefined);
  }, 300_000);
  afterAll(async () => db?.close());

  it("both files pass the SECURITY DEFINER lint", () => {
    expect(migrationDefinerViolations(F76, SQL76)).toEqual([]);
    expect(migrationDefinerViolations(F77, SQL77)).toEqual([]);
  });

  it("on 0275 every finding is real; 0276 closes F3 and F8b and keeps the old code paths; 0277 closes F1, F2 and F9", async () => {
    expect(await attacks()).toEqual(ALL_OPEN);
    expect(await legit("0275")).toEqual({ kept: 1, keptUser: 1, pub: 1, view: 1 });

    await apply(F76, SQL76);
    expect(await attacks()).toEqual({ ...ALL_OPEN, F3_legacy: false, F8b_move_qr: false, F8b_move_user: false, F8b_move_profile: false });
    expect(await legit("0276")).toEqual({ kept: 1, keptUser: 1, pub: 1, view: 1 });
    // The 0275 code paths still work: direct reads of the own private columns, owner social-link writes.
    expect(await ok(A, `select email, legal_first_name from public.profiles where id = $1`, [A])).toBe(1);
    expect(await ok(A, `insert into public.social_links (profile_id, platform, username) values ($1, 'mastodon', 'alice@m.example')`, [A])).toBe(1);

    await apply(F77, SQL77);
    expect(await attacks()).toEqual(Object.fromEntries(Object.keys(ALL_OPEN).map((k) => [k, false])));
    expect(await legit("0277")).toEqual({ kept: 1, keptUser: 1, pub: 1, view: 1 });
    for (const c of PRIVATE_PROFILE_COLUMNS) expect(await ok(A, `select ${c} from public.profiles where id = $1`, [A]), c).toMatch(/^refused: permission denied/);
    expect(await ok(A, `select * from public.profiles where id = $1`, [A])).toMatch(/^refused: permission denied/);
  }, 240_000);

  it("the 0276 definers answer only what their purpose needs", async () => {
    const one = async <T,>(user: string | null, q: string, p: unknown[] = []) => (await as<T>(user, q, p)).rows;
    expect(await one(A, `select email, legal_last_name, last_city from public.rout_profile_private_mine()`)).toEqual([{ email: "alice@example.test", legal_last_name: "Alice", last_city: "Alice" }]);
    expect(await one(null, `select * from public.rout_profile_private_mine()`)).toEqual([]);
    expect((await one<{ j: Record<string, unknown> }>(A, `select public.rout_profile_export_mine() as j`))[0]!.j["email"]).toBe("alice@example.test");
    expect(await one(A, `select * from public.rout_admin_profiles_private()`)).toEqual([]);
    await db.query(`insert into public.user_roles (user_id, role) values ($1, 'admin')`, [A]);
    expect((await one<{ email: string }>(A, `select email from public.rout_admin_profiles_private() where id = $1`, [B]))[0]?.email).toBe(`${MARK}@example.test`);
    await db.query(`delete from public.user_roles where user_id = $1 and role = 'admin'`, [A]);
    // Notification address: only for a profile that publishes a visible booking/contact block.
    expect((await one<{ e: string | null }>(A, `select public.rout_profile_notify_address($1, 'booking_request') as e`, [B]))[0]!.e).toBeNull();
    await db.query(`update public.profiles set blocks = '[{"kind":"booking_request","value":"{}"},{"kind":"contact_form","hidden":true}]' where id = $1`, [B]);
    expect((await one<{ e: string | null }>(null, `select public.rout_profile_notify_address($1, 'booking_request') as e`, [B]))[0]!.e).toBe(`${MARK}@example.test`);
    expect((await one<{ e: string | null }>(null, `select public.rout_profile_notify_address($1, 'contact_form') as e`, [B]))[0]!.e).toBeNull();
    expect((await one<{ e: string | null }>(null, `select public.rout_profile_notify_address($1, 'email') as e`, [B]))[0]!.e).toBeNull();
    await db.query(`update public.profiles set blocks = '[]' where id = $1`, [B]);
    // Verification-link token: a short or wrong token finds nothing.
    await db.query(`update public.profiles set forwarding_email = 'fw@example.test', forwarding_email_token = $2 where id = $1`, [B, "t".repeat(32)]);
    expect(await one(null, `select id from public.rout_forwarding_token_lookup($1)`, ["t".repeat(32)])).toEqual([{ id: B }]);
    expect(await one(null, `select id from public.rout_forwarding_token_lookup($1)`, ["t".repeat(8)])).toEqual([]);
    expect(await one(null, `select id from public.rout_forwarding_token_lookup(null)`)).toEqual([]);
    // Member lookup without any address; resolve_account echoes an address only for an e-mail lookup.
    expect(await one(A, `select * from public.rout_resolve_member('@bobrls')`)).toEqual([{ user_id: B, username: "bobrls" }]);
    expect(await one(A, `select email from public.rout_resolve_account($1)`, [`${MARK}@example.test`])).toEqual([{ email: `${MARK}@example.test` }]);
    expect(await one(A, `select email from public.rout_resolve_account('bobrls')`)).toEqual([{ email: null }]);
    // Public social links: verified rows only, no code or error column.
    const links = await one<Record<string, unknown>>(null, `select * from public.rout_public_social_links($1)`, [B]);
    expect(links.map((l) => Object.keys(l).sort())).toEqual([["checked_at", "follower_count", "platform", "username"]]);
    expect(JSON.stringify(links)).not.toContain(MARK);
    expect(await one(B, `select verification_code from public.social_links where profile_id = $1`, [B])).toEqual([{ verification_code: `${MARK}-code` }]);
  }, 120_000);

  it("a handle invite stores no address and is still accepted by the invited member", async () => {
    const r = await as(A, `insert into public.workspace_invites (workspace_id, email, role, invited_by, invited_user_id) values ($1, null, 'editor', $2, $3)
      on conflict (workspace_id, invited_user_id) where status = 'pending' and invited_user_id is not null do update set role = excluded.role`, [ids.aliceWs, A, B]);
    expect(r.affectedRows).toBe(1);
    expect(await ok(A, `insert into public.workspace_invites (workspace_id, email, role, invited_by, invited_user_id) values ($1, null, 'editor', $2, null)`, [ids.aliceWs, A])).toMatch(/^refused/);
    const n = await as<{ n: number }>(B, `select public.rout_accept_workspace_invites(null) as n`);
    expect(n.rows[0]!.n).toBe(1);
    expect((await db.query(`select role::text as role from public.workspace_members where workspace_id = $1 and user_id = $2`, [ids.aliceWs, B])).rows).toEqual([{ role: "editor" }]);
    await db.query(`delete from public.workspace_members where workspace_id = $1 and user_id = $2`, [ids.aliceWs, B]);
    await db.query(`delete from public.workspace_invites where workspace_id = $1`, [ids.aliceWs]);
  });

  it("a @handle workspace transfer reveals the owner's address only to its source, after the source's own code", async () => {
    const t = (await db.query<{ id: string }>(`insert into public.workspace_transfers (source_user_id, target_user_id, target_email, workspace_name, token_hash)
      values ($1, $2, '@bobrls', 'conv', $3) returning id`, [A, B, "h".repeat(64)])).rows[0]!.id;
    const addr = async (user: string) => (await as<{ e: string | null }>(user, `select public.rout_transfer_owner_address($1::uuid) as e`, [t])).rows[0]!.e;
    expect(await addr(A)).toBeNull();
    await db.query(`update public.workspace_transfers set otp_verified_at = now(), status = 'otp_ok' where id = $1`, [t]);
    expect(await addr(A)).toBe(`${MARK}@example.test`);
    expect(await addr(B)).toBeNull();
    await db.query(`update public.workspace_transfers set status = 'cancelled' where id = $1`, [t]);
    expect(await addr(A)).toBeNull();
    await db.query(`delete from public.workspace_transfers where id = $1`, [t]);
  });

  it("Z3 proves 0276 + 0277: F1, F2, F3 and F8b are closed, nothing new opens, and every reviewed entry is used", async () => {
    const v = await verify();
    const known = new Set(KNOWN_OPEN.map((k) => k.id));
    expect(v.findings.map((f) => f.id).filter((id) => !known.has(id))).toEqual([]);
    expect(v.findings.map((f) => f.id).filter((id) => CLOSED.includes(id))).toEqual([]);
    // Since db/0276 both views are security_invoker, so they need no declassification.
    expect(v.unusedModelEntries.sort()).toEqual(OPEN_UNTIL_0277.map((id) => `known_open:${id}`).sort());
    for (const t of [...F8A, "users", "profiles"]) expect(v.obligations.find((o) => o.table === `public.${t}` && o.cmd === "UPDATE" && o.phase === "check")?.outcome.status, t).toBe("proven");
    expect(v.obligations.find((o) => o.table === "public.profiles" && o.cmd === "SELECT")?.outcome.status).toBe("declassified");
    expect(v.obligations.find((o) => o.table === "public.social_links" && o.cmd === "SELECT")?.outcome).toEqual({ status: "proven", via: "smt" });
    expect(v.searchPath.findings).toEqual([]);
  }, 180_000);

  it("every rout_app-callable SECURITY DEFINER after 0277, fed injection payloads and Bob's id as Alice, leaks none of Bob's private values", async () => {
    await db.query(`update public.profiles set forwarding_email = $2 where id = $1`, [B, `${MARK}-fw@example.test`]);
    const fns = (await db.query<{ schema: string; name: string; types: string[] }>(`select n.nspname as schema, p.proname as name,
        array(select format_type(t, null) from unnest(p.proargtypes) t) as types
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where p.prosecdef and p.prokind = 'f' and n.nspname in ('public', 'vault_enclave', 'auth')
        and p.prorettype <> 'trigger'::regtype and has_function_privilege('rout_app', p.oid, 'EXECUTE') and p.pronargs <= 8
      order by 1, 2`)).rows;
    const leaks: string[] = [];
    for (const f of fns) {
      for (const pay of ["'); drop table public.profiles; --", "' or '1'='1", B, "bobrls", "@bobrls"]) {
        const args = f.types.map((t) => (t === "uuid" ? B : /^(text|character varying|citext)$/.test(t) ? pay : t === "jsonb" || t === "json" ? JSON.stringify({ user_id: B, id: B, q: pay }) : t === "uuid[]" ? [B] : t === "text[]" ? [pay] : t === "boolean" ? true : /^(integer|bigint|smallint|numeric)$/.test(t) ? 1 : null));
        const q = `select coalesce((select jsonb_agg(to_jsonb(r))::text from ${f.schema}.${f.name}(${f.types.map((t, i) => `$${i + 1}::${t}`).join(", ")}) as r), '') as out`;
        const out = await as<{ out: string }>(A, q, args).catch(() => null);
        if (out?.rows[0]?.out.includes(MARK)) leaks.push(`${f.schema}.${f.name}`);
      }
    }
    expect(fns.length).toBeGreaterThan(50);
    expect([...new Set(leaks)]).toEqual([]);
  }, 300_000);

  it("both rollbacks are idempotent, restore the earlier stage and allow re-applying", async () => {
    await db.exec(`begin;\n${RB77}\n;commit;`);
    await db.exec(`begin;\n${RB77}\n;commit;`);
    expect((await attacks()).F1_email).toBe(true);
    await db.exec(`begin;\n${RB76}\n;commit;`);
    await db.exec(`begin;\n${RB76}\n;commit;`);
    expect(await attacks()).toEqual(ALL_OPEN);
    const v = await verify();
    for (const id of CLOSED) expect(v.findings.map((f) => f.id), id).toContain(id);
    await apply(F76, SQL76);
    await apply(F77, SQL77);
    expect(await attacks()).toEqual(Object.fromEntries(Object.keys(ALL_OPEN).map((k) => [k, false])));
  }, 240_000);
});
