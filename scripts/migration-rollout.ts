/**
 * One-transaction rollout of a single db/ migration through the Neon gateway
 * batch endpoint (`{ queries: [...] }` = one transaction), for when the owner
 * gives a GO for exactly one file and the agent applies it from chat.
 *
 * Unlike migrate-gateway.ts the file is NOT split client-side: its exact text
 * travels as one parameter, is hashed inside the transaction and only executed
 * when the SHA-256 equals the checksum of the file in db/. A single changed
 * byte on the way therefore aborts the whole transaction before any statement
 * runs, and the schema_migrations row records exactly the text that ran. The
 * SECURITY DEFINER guard runs afterwards in the same transaction.
 *
 *   bun scripts/migration-rollout.ts <file> --after=<previous file> [--out=<json>]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checksumOf, listMigrationFiles } from "./migration-plan";
import { guardedMigration, migrationDefinerGuardSql, migrationDefinerViolations } from "./security-definer-policy";

export type RolloutQuery = { query: string; params: unknown[] };

const RUNNER = `create function pg_temp.rout_rollout(p_file text, p_after text, p_sql text, p_sum text) returns text
language plpgsql as $rollout$
begin
  if pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_sql, 'UTF8')), 'hex') <> p_sum then
    raise exception 'rollout %: text does not match checksum %', p_file, p_sum;
  end if;
  if not exists (select 1 from public.schema_migrations where filename = p_after) then
    raise exception 'rollout %: predecessor % is not applied', p_file, p_after;
  end if;
  if exists (select 1 from public.schema_migrations where filename = p_file) then
    raise exception 'rollout %: already applied', p_file;
  end if;
  execute p_sql;
  insert into public.schema_migrations (filename, checksum) values (p_file, p_sum);
  return p_sum;
end $rollout$`;

/** The gateway batch for one file: runner, guarded execution, definer guard, read-back, cleanup. */
export function rolloutBatch(file: string, after: string, body: string): RolloutQuery[] {
  const violations = guardedMigration(file) ? migrationDefinerViolations(file, body) : [];
  if (violations.length > 0) throw new Error(violations.join("; "));
  const sum = checksumOf(body);
  return [
    { query: RUNNER, params: [] },
    { query: "select pg_temp.rout_rollout($1, $2, $3, $4) as applied", params: [file, after, body, sum] },
    ...(guardedMigration(file) ? [{ query: migrationDefinerGuardSql(file), params: [] }] : []),
    { query: "select filename, checksum from public.schema_migrations where filename = $1", params: [file] },
    { query: "drop function pg_temp.rout_rollout(text, text, text, text)", params: [] },
  ];
}

/** JSON with every non-ASCII character escaped, so the body survives any transport byte-exact. */
export const asciiJson = (value: unknown) =>
  JSON.stringify(value).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

if (import.meta.main) {
  const file = process.argv[2];
  const after = process.argv.find((a) => a.startsWith("--after="))?.slice(8);
  const out = process.argv.find((a) => a.startsWith("--out="))?.slice(6);
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "db");
  if (!file || !after) throw new Error("usage: bun scripts/migration-rollout.ts <file> --after=<previous file> [--out=<json>]");
  const files = listMigrationFiles(dir);
  const at = files.indexOf(file);
  if (at < 0) throw new Error(`${file} is not in db/`);
  if (files[at - 1] !== after) throw new Error(`${after} is not the file right before ${file} in db/ (found ${files[at - 1]})`);
  const body = readFileSync(join(dir, file), "utf8");
  const json = asciiJson({ queries: rolloutBatch(file, after, body) });
  if (out) writeFileSync(out, json);
  console.log(`${file}: sha256 ${checksumOf(body)}, ${body.length} chars, batch ${json.length} bytes${out ? ` -> ${out}` : ""}`);
}
