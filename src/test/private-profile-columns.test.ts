// @vitest-environment node
/**
 * db-pending/0277 withholds the private profile columns from rout_app. Only
 * src/lib/profile-private.server.ts may read them; everywhere else they may
 * only be written (UPDATE ... SET col = $x WHERE id = ..., or an INSERT column list).
 * This scan keeps new code from selecting, filtering on or returning them.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { PRIVATE_PROFILE_COLUMNS } from "../../scripts/formal-rls/tenant-model";

const ROOT = join(__dirname, "..", "..");
const ALLOWED = new Set(["src/lib/profile-private.server.ts"]);
const files = (dir: string): string[] =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) return f === "test" ? [] : files(p);
    return /\.(ts|tsx)$/.test(f) && !f.includes(".gen.") && !f.endsWith(".test.ts") ? [p] : [];
  });
/** Every SQL text in a file: tagged templates and sql.query("...") strings, placeholders blanked. */
const statements = (src: string) => [
  ...[...src.matchAll(/sql`((?:[^`\\]|\\.)*)`/g)].map((m) => m[1]!),
  ...[...src.matchAll(/sql\.query\(\s*`((?:[^`\\]|\\.)*)`/g)].map((m) => m[1]!),
].map((q) => q.replace(/\$\{[^}]*\}/g, "$x"));

const COL = new RegExp(`(?<![\\w.])(?:p\\.|profiles\\.)?(${PRIVATE_PROFILE_COLUMNS.join("|")})\\b`, "gi");
/** Reads of a private column in a statement that touches public.profiles (writes excluded). */
export function privateReads(q: string): string[] {
  if (!/\bprofiles\b/i.test(q)) return [];
  const s = q.replace(/--[^\n]*/g, "").replace(/\s+/g, " ").trim();
  const hits = (part: string) => [...part.matchAll(COL)].map((m) => m[1]!.toLowerCase());
  const upd = /^update\s+(?:public\.)?profiles\s+set\s+(.*?)(?:\s+where\s+(.*))?$/i.exec(s);
  if (upd) {
    // Drop each assignment target ("col =" at the start or after a comma); what remains is read.
    const values = upd[1]!.replace(/(^|,)\s*[\w.]+\s*=(?!=)/g, "$1");
    return [...hits(values), ...hits(upd[2] ?? "")];
  }
  const ins = /^insert\s+into\s+(?:public\.)?profiles\s*\(([^)]*)\)\s*values\s*\((.*?)\)(.*)$/i.exec(s);
  if (ins) return hits(ins[3]!);
  if (/^(insert|update|delete)\b/i.test(s) && !/\bprofiles\b/i.test(s.split(/\b(?:from|join)\b/i).slice(1).join(" "))) return [];
  return hits(s);
}

describe("private profile columns stay behind the 0276 definers", () => {
  it("the scanner itself: reads are caught, writes are allowed", () => {
    expect(privateReads("select p.email from public.profiles p where p.id = $x")).toEqual(["email"]);
    expect(privateReads("select username from public.profiles where forwarding_email_token = $x")).toEqual(["forwarding_email_token"]);
    expect(privateReads("update public.profiles set legal_first_name = coalesce($x, legal_first_name) where id = $x")).toEqual(["legal_first_name"]);
    expect(privateReads("update public.profiles set legal_first_name = $x where id = $x")).toEqual([]);
    expect(privateReads("insert into public.profiles (id, email) values ($x, $x) on conflict (id) do nothing")).toEqual([]);
    expect(privateReads("insert into public.profiles (id, email) values ($x, $x) on conflict (id) do update set email = excluded.email")).toEqual(["email"]);
    expect(privateReads("select u.email from public.users u join public.profiles p on p.id = u.id")).toEqual([]);
  });

  it("no module outside profile-private.server.ts reads them", () => {
    const offenders: string[] = [];
    for (const f of files(join(ROOT, "src"))) {
      const rel = relative(ROOT, f);
      if (ALLOWED.has(rel)) continue;
      for (const q of statements(readFileSync(f, "utf8"))) {
        const r = privateReads(q);
        if (r.length) offenders.push(`${rel}: ${[...new Set(r)].join(",")} :: ${q.replace(/\s+/g, " ").slice(0, 120)}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
