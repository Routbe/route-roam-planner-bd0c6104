// @vitest-environment node
/**
 * scripts/migration-rollout.ts: the one-file gateway batch used for each GO
 * (0273, now 0274). Emulates the gateway batch (one transaction, every query
 * with its params) on PGlite over a replay of db/ before the file, recorded as
 * Neon has it.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checksumOf, listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { asciiJson, rolloutBatch, type RolloutQuery } from "../../scripts/migration-rollout";
import { catalogJson, readCatalog } from "../../scripts/schema-catalog";

const ROOT = join(__dirname, "..", "..");
const DIR = join(ROOT, "db");
const FILE = "0274_multi_device_host_keys.sql";
const AFTER = "0273_anonymous_booking_engine.sql";
const BODY = readFileSync(join(DIR, FILE), "utf8");

describe("one-file rollout batch (0274)", () => {
  let db: PGlite;
  const batch = async (queries: RolloutQuery[]) => {
    await db.exec("begin");
    try {
      const out: Record<string, unknown>[][] = [];
      for (const q of queries) out.push((await db.query<Record<string, unknown>>(q.query, q.params)).rows);
      await db.exec("commit");
      return out;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  const anonTables = async () =>
    (await db.query<{ n: number }>("select count(*)::int as n from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'vault_enclave' and c.relkind = 'r' and c.relname like 'anon%'")).rows[0]!.n;
  const recorded = async () => (await db.query<{ checksum: string }>("select checksum from public.schema_migrations where filename = $1", [FILE])).rows;

  beforeAll(async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    db = await PGlite.create({ extensions: { pgcrypto, btree_gist } });
    const files = listMigrationFiles(DIR).filter((f) => f !== FILE);
    for (const step of planMigrations(files, new Set())) {
      if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DIR, step.file), "utf8")}\n;commit;`);
    }
    await db.exec("create table if not exists public.schema_migrations (filename text primary key, checksum text not null, applied_at timestamptz not null default now())");
    for (const f of files) await db.query("insert into public.schema_migrations (filename, checksum) values ($1, $2)", [f, checksumOf(readFileSync(join(DIR, f), "utf8"))]);
  }, 300_000);
  afterAll(async () => db?.close());

  it("survives ASCII-only JSON transport byte-exact", () => {
    const queries = rolloutBatch(FILE, AFTER, BODY);
    const json = asciiJson({ queries });
    expect(/^[\x00-\x7e]*$/.test(json)).toBe(true);
    expect(JSON.parse(json)).toEqual({ queries });
  });

  it("refuses a text that differs by one byte, a missing predecessor, and changes nothing", async () => {
    const good = rolloutBatch(FILE, AFTER, BODY);
    const tampered = good.map((q) => (q.params.length === 4 ? { ...q, params: [FILE, AFTER, BODY.replace("deny_all", "deny_alx"), q.params[3]] } : q));
    await expect(batch(tampered)).rejects.toThrow(/does not match checksum/);
    await expect(batch(rolloutBatch(FILE, "0272_dynamic_recovery_v4.sql_missing", BODY))).rejects.toThrow(/predecessor/);
    expect(await anonTables()).toBe(9);
    expect(await recorded()).toEqual([]);
  });

  it("applies 0274 exactly like the snapshot replay, records the file checksum, and refuses a second run", async () => {
    const rows = await batch(rolloutBatch(FILE, AFTER, BODY));
    expect(rows[1]).toEqual([{ applied: checksumOf(BODY) }]);
    expect(await recorded()).toEqual([{ checksum: checksumOf(BODY) }]);
    expect(await anonTables()).toBe(11);
    const catalog = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
    expect(catalogJson(catalog)).toBe(readFileSync(join(DIR, "schema.snapshot.json"), "utf8"));
    expect((await db.query("select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace where p.proname = 'rout_rollout'")).rows).toEqual([]);
    await expect(batch(rolloutBatch(FILE, AFTER, BODY))).rejects.toThrow(/already applied/);
  });
});
