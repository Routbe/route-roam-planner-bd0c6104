/**
 * Runtime detection of held-back EXPAND migrations, so code that already uses
 * them keeps working on a database that is one migration behind (deploy order
 * free). A positive answer is cached for the isolate; a negative one for a minute.
 * Remove a detector together with its legacy path once the CONTRACT is in db/.
 */
import { sql } from "@/lib/neon";

const MARKERS = {
  /** db-pending/0276_tenant_column_expand.sql */
  "0276": "public.rout_profile_private_mine()",
} as const;
export type SchemaFeature = keyof typeof MARKERS;

const cache = new Map<SchemaFeature, { ok: boolean; at: number }>();
const NEGATIVE_TTL_MS = 60_000;

export async function hasSchemaFeature(feature: SchemaFeature): Promise<boolean> {
  const hit = cache.get(feature);
  if (hit && (hit.ok || Date.now() - hit.at < NEGATIVE_TTL_MS)) return hit.ok;
  try {
    const rows = (await sql`select pg_catalog.to_regprocedure(${MARKERS[feature]}) is not null as ok`) as { ok: boolean }[];
    const ok = rows[0]?.ok === true;
    cache.set(feature, { ok, at: Date.now() });
    return ok;
  } catch {
    return false;
  }
}

/** Test hook: forget cached answers. */
export function resetSchemaFeatures() {
  cache.clear();
}
