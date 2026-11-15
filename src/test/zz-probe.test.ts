// @vitest-environment node
import { PGlite } from "@electric-sql/pglite";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
it("probe", async () => {
  const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  const dir = join(__dirname, "..", "..", "db");
  for (const s of planMigrations(listMigrationFiles(dir), new Set())) if (s.action === "run") await db.exec(`begin;\n${readFileSync(join(dir, s.file), "utf8")}\n;commit;`);
  await db.exec(`create table if not exists _x(); select 1`);
  const out: unknown[] = [];
  const q = async (s: string) => { try { out.push([s, (await db.query(s)).rows]); } catch (e) { out.push([s, String(e)]); } };
  await q(`select c.relname, c.reloptions, pg_get_userbyid(c.relowner) owner from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='v' and n.nspname in ('public','auth')`);
  await q(`select rolname, rolsuper, rolbypassrls from pg_roles where rolname in ('rout_app','postgres')`);
  await q(`select c.relname, c.relrowsecurity, c.relforcerowsecurity from pg_class c where relname in ('profiles','users')`);
  await q(`select polname, pg_get_expr(polqual, polrelid) from pg_policy where polrelid='public.users'::regclass`);
  await q(`select is_updatable, is_insertable_into, table_name from information_schema.views where table_name in ('public_profiles','profile_handles','users')`);
  writeFileSync("/tmp/probe/out.json", JSON.stringify(out, null, 1));
  await db.dumpDataDir("none").then((b) => writeFileSync("/tmp/probe/db.tar", Buffer.from(new Uint8Array(b instanceof Blob ? [] : [])))).catch(() => undefined);
  await db.close();
}, 400_000);
