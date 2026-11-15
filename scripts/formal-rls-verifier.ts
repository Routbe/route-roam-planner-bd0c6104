/**
 * Stap 9: formal RLS non-interference check over db/schema.snapshot.json.
 * The snapshot is the replay of every db/ migration (migration-replay.test.ts)
 * and equals Neon (`bun scripts/schema-snapshot.ts --check`). This script only
 * reads the file and never connects to a database.
 *
 * For every table, every command and every row-security phase (USING / WITH CHECK)
 * that the application role rout_app can reach, the effective policy
 * (permissive OR'ed, restrictive AND'ed) is translated to SMT and Z3 checks
 *
 *   H(u1, row) ∧ Eval(policy, u1, row) = TRUE
 *
 * for satisfiability. H says the row belongs to other tenants: it has at least
 * one tenant reference, none of its identity columns names the caller u1, the
 * caller is in none of the workspaces it names, its handle is not the caller's,
 * the caller is not a platform admin and no purge context is active. Rows reached
 * through a foreign key from such a row belong to the same tenant and get the same H.
 * UNSAT is the proof that Eval(policy, u1, Row(u2)) = FALSE for every u1 ≠ u2.
 * SQL NULL is modelled with three-valued logic: a policy only admits a row when
 * it is definitely TRUE.
 *
 *   bun scripts/formal-rls-verifier.ts [--smt-out <dir>] [--json <file>]
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Catalog, Policy, Table } from "./schema-catalog";
import { searchPathFromDef, isSecurityDefinerDef } from "./security-definer-policy";
import { parsePolicyExpr, UnsupportedSql, type Expr, type Sel } from "./formal-rls/sql-expr";
import * as M from "./formal-rls/tenant-model";

export type Cmd = "SELECT" | "INSERT" | "UPDATE" | "DELETE";
export type Phase = "using" | "check";
export type Outcome =
  | { status: "proven"; via: "grant" | "no_policy" | "smt" }
  | { status: "declassified"; reason: string }
  | { status: "service_boundary"; reason: string }
  | { status: "unproven"; why: "satisfiable" | "unsupported" | "rls_disabled"; detail: string };
export type Obligation = { table: string; cmd: Cmd; phase: Phase; outcome: Outcome; smt?: string };
export type Finding = { id: string; detail: string };
export type Report = {
  obligations: Obligation[];
  smtChecks: number;
  enclave: { tables: number; findings: Finding[] };
  searchPath: { definers: number; findings: Finding[] };
  views: Finding[];
  oracles: Finding[];
  findings: Finding[];
  unusedModelEntries: string[];
};

const CMDS: Cmd[] = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const APP = "rout_app";
const TRANSPARENT_CASTS = new Set(["text", "uuid", "character varying", "varchar", "name", "citext", "bpchar", "character"]);

type FK = { cols: string[]; table: string; refCols: string[] };
const fksOf = (t: Table): FK[] =>
  t.constraints.filter((c) => c.kind === "f").flatMap((c) => {
    const m = /^FOREIGN KEY \(([^)]+)\) REFERENCES (?:"?[\w]+"?\.)?"?(\w+)"?\(([^)]+)\)/.exec(c.def);
    if (!m) return [];
    const split = (s: string) => s.split(",").map((x) => x.trim().replace(/^"|"$/g, ""));
    return [{ cols: split(m[1]!), table: m[2]!, refCols: split(m[3]!) }];
  });

export function tenantColumns(t: Table) {
  const fks = fksOf(t);
  const refTo = (col: string, set: Set<string>) => fks.some((f) => f.cols.length === 1 && f.cols[0] === col && set.has(f.table));
  const names = t.columns.map((c) => c.name);
  const identity = names.filter((n) => M.IDENTITY_COLUMN.test(n) || refTo(n, M.USER_TABLES) || (M.USER_TABLES.has(t.name) && t.schema === "public" && n === "id"));
  const workspace = names.filter((n) => !identity.includes(n) && (n === "workspace_id" || refTo(n, M.WORKSPACE_TABLES) || (M.WORKSPACE_TABLES.has(t.name) && n === "id")));
  const handle = names.filter((n) => n === "handle");
  return { identity, workspace, handle };
}

// ---------------------------------------------------------------- Z3 encoding
type Z3 = any;
type V = { kind: "val"; v: any; n: any; exact: boolean };
type B = { kind: "bool"; t: any; f: any; exact: boolean };
type Row = { table: Table; alias: string; cols: Map<string, V | B>; tag: string };

const sorts = new WeakMap<object, any>();
const valSort = (Z: Z3) => { let v = sorts.get(Z); if (!v) { v = Z.Sort.declare("Val"); sorts.set(Z, v); } return v; };

class Encoder {
  private n = 0;
  readonly facts: any[] = [];
  readonly Val: any;
  readonly caller: any;
  readonly callerN: any;
  readonly admin: any;
  readonly purgeActive: any;
  readonly purgeTarget: any;
  private readonly lits = new Map<string, any>();
  private readonly fns = new Map<string, any>();
  constructor(readonly Z: Z3, readonly verifier: Verifier) {
    this.Val = valSort(Z);
    this.caller = Z.Const("caller", this.Val);
    this.callerN = Z.Bool.const("caller_authenticated");
    this.admin = Z.Bool.const("caller_is_admin");
    this.purgeActive = Z.Bool.const("purge_context_active");
    this.purgeTarget = Z.Const("purge_target", this.Val);
  }
  fresh(p: string) { return `${p}!${++this.n}`; }
  and(xs: any[]) { const Z = this.Z; return xs.length === 0 ? Z.Bool.val(true) : xs.length === 1 ? xs[0] : Z.And(...xs); }
  or(xs: any[]) { const Z = this.Z; return xs.length === 0 ? Z.Bool.val(false) : xs.length === 1 ? xs[0] : Z.Or(...xs); }
  lit(key: string) {
    let c = this.lits.get(key);
    if (!c) { c = this.Z.Const(`lit:${key}`, this.Val); this.lits.set(key, c); }
    return c;
  }
  fn(name: string, arity: number, boolArgs: boolean[], range: "val" | "bool") {
    const key = `${name}/${arity}/${boolArgs.map((b) => (b ? "b" : "v")).join("")}/${range}`;
    let f = this.fns.get(key);
    if (!f) {
      const dom = boolArgs.map((b) => (b ? this.Z.Bool.sort() : this.Val));
      f = this.Z.Function.declare(key, ...dom, range === "bool" ? this.Z.Bool.sort() : this.Val);
      this.fns.set(key, f);
    }
    return f;
  }
  member(w: any) { return this.fn("member_of_caller", 1, [false], "bool").call(w); }
  roleOf(w: any) { return this.fn("caller_role_in", 1, [false], "val").call(w); }
  uname(u: any) { return this.fn("username_of", 1, [false], "val").call(u); }
  unameN(u: any) { return this.fn("username_present", 1, [false], "bool").call(u); }
  lower(x: any) { return this.fn("lower", 1, [false], "val").call(x); }
  literalFacts() {
    const all = [...this.lits.values()];
    return all.length >= 2 ? [this.Z.Distinct(...all)] : [];
  }

  newRow(table: Table, alias: string): Row { return { table, alias, cols: new Map(), tag: this.fresh(`${table.name}.${alias}`) }; }
  column(row: Row, name: string): V | B {
    let c = row.cols.get(name);
    if (c) return c;
    const def = row.table.columns.find((x) => x.name === name);
    if (!def) throw new UnsupportedSql(`unknown column ${row.table.name}.${name}`);
    const Z = this.Z;
    const n = def.notNull ? Z.Bool.val(true) : Z.Bool.const(`${row.tag}.${name}.notnull`);
    if (def.type === "boolean") {
      const b = Z.Bool.const(`${row.tag}.${name}`);
      c = { kind: "bool", t: Z.And(n, b), f: Z.And(n, Z.Not(b)), exact: true };
    } else c = { kind: "val", v: Z.Const(`${row.tag}.${name}`, this.Val), n, exact: true };
    row.cols.set(name, c);
    return c;
  }
  hasMember(w: any) { return this.fn("workspace_has_member", 1, [false], "bool").call(w); }
  /**
   * H: this row belongs to another tenant. Read phases (SELECT, UPDATE/DELETE USING):
   * at least one tenant reference, no identity column names the caller, no named
   * workspace is the caller's, the handle is not the caller's. Write phases
   * (INSERT / UPDATE WITH CHECK) also count a row that names the caller but places
   * it in a workspace someone else holds: writing into a foreign workspace interferes too.
   */
  /** The row an UPDATE writes, while its WITH CHECK is encoded (rout_tenant_ref_kept reads its pre-image). */
  keptRow: Row | null = null;
  private readonly keptVars = new Map<string, any>();
  /** "The pre-image of this row holds the same value in tenant column c" (pinned rout_tenant_ref_kept). */
  kept(row: Row, c: string) {
    const k = `${row.tag}.${c}`;
    let x = this.keptVars.get(k);
    if (!x) { x = this.Z.Bool.const(`${k}.kept`); this.keptVars.set(k, x); }
    return x;
  }
  otherTenant(row: Row, requireReference: boolean, opts: { excludeOwnKey?: boolean; write?: boolean; update?: boolean } = {}) {
    const Z = this.Z;
    const { identity, workspace, handle } = tenantColumns(row.table);
    const refs: any[] = [], read: any[] = [], foreignWs: any[] = [];
    for (const c of identity) {
      const t = this.column(row, c) as V;
      if (t.kind !== "val") continue;
      read.push(Z.Not(Z.And(this.callerN, t.n, t.v.eq(this.caller))));
      refs.push(t.n);
    }
    for (const c of workspace) {
      const t = this.column(row, c) as V;
      read.push(Z.Not(Z.And(t.n, this.member(t.v))));
      // An UPDATE that keeps the reference creates no new cross-tenant link: only a move counts.
      if (!(opts.excludeOwnKey && c === "id")) { refs.push(t.n); foreignWs.push(Z.And(t.n, Z.Not(this.member(t.v)), this.hasMember(t.v), ...(opts.update ? [Z.Not(this.kept(row, c))] : []))); }
    }
    for (const c of handle) {
      const t = this.column(row, c) as V;
      read.push(Z.Not(Z.And(t.n, this.callerN, this.unameN(this.caller), this.lower(t.v).eq(this.uname(this.caller)))));
      refs.push(t.n);
    }
    const readH = this.and(requireReference ? [...read, this.or(refs)] : read);
    this.facts.push(opts.write && foreignWs.length ? Z.Or(readH, this.or(foreignWs)) : readH);
    return refs.length;
  }
  /** Facts that hold for any row of a table the policy functions are defined over. */
  definitional(row: Row) {
    const Z = this.Z;
    if (row.table.schema !== "public") return;
    if (row.table.name === "workspace_members") {
      const u = this.column(row, "user_id") as V, w = this.column(row, "workspace_id") as V;
      this.facts.push(Z.Implies(Z.And(this.callerN, u.n, u.v.eq(this.caller), w.n), this.member(w.v)));
    }
    if (row.table.name === "user_roles") {
      const u = this.column(row, "user_id") as V, r = this.column(row, "role") as V;
      this.facts.push(Z.Implies(Z.And(this.callerN, u.n, u.v.eq(this.caller), r.n, r.v.eq(this.lit("s:admin"))), this.admin));
    }
  }

  // ---- expressions
  kind(e: Expr, sc: Row[]): "bool" | "val" | "null" {
    switch (e.k) {
      case "and": case "or": case "not": case "cmp": case "isnull": case "any": case "in": case "exists": case "bool": return "bool";
      case "null": return "null";
      case "col": { const c = this.resolve(e, sc); return c.kind; }
      case "cast": return /^bool(ean)?$/.test(e.type) ? "bool" : "val";
      case "call": return this.verifier.returnsBoolean(e.name) ? "bool" : "val";
      case "case": return this.kind(e.whens[0]![1], sc) === "null" && e.els ? this.kind(e.els, sc) : this.kind(e.whens[0]![1], sc);
      case "scalar": return e.sub.from.length === 0 && e.sub.targets.length === 1 ? this.kind(e.sub.targets[0]!, sc) : "val";
      default: return "val";
    }
  }
  resolve(e: Extract<Expr, { k: "col" }>, sc: Row[]): V | B {
    for (let i = sc.length - 1; i >= 0; i--) {
      const r = sc[i]!;
      if (e.q && e.q !== r.alias && e.q !== r.table.name) continue;
      if (r.table.columns.some((c) => c.name === e.name)) return this.column(r, e.name);
    }
    throw new UnsupportedSql(`unresolved column ${e.q ? `${e.q}.` : ""}${e.name}`);
  }
  b(e: Expr, sc: Row[], depth: number): B {
    const Z = this.Z;
    const T = (t: any, f: any, exact = true): B => ({ kind: "bool", t, f, exact });
    switch (e.k) {
      case "bool": return T(Z.Bool.val(e.v), Z.Bool.val(!e.v));
      case "null": return T(Z.Bool.val(false), Z.Bool.val(false));
      case "and": { const a = e.a.map((x) => this.b(x, sc, depth)); return T(this.and(a.map((x) => x.t)), this.or(a.map((x) => x.f)), a.every((x) => x.exact)); }
      case "or": { const a = e.a.map((x) => this.b(x, sc, depth)); return T(this.or(a.map((x) => x.t)), this.and(a.map((x) => x.f)), a.every((x) => x.exact)); }
      case "not": { const x = this.b(e.e, sc, depth); return T(x.f, x.t, x.exact); }
      case "isnull": {
        const k = this.kind(e.e, sc);
        let isNull: any;
        let exact = true;
        if (k === "null") isNull = Z.Bool.val(true);
        else if (k === "bool") { const x = this.b(e.e, sc, depth); isNull = Z.And(Z.Not(x.t), Z.Not(x.f)); exact = x.exact; }
        else { const x = this.v(e.e, sc, depth); isNull = Z.Not(x.n); exact = x.exact; }
        return e.neg ? T(Z.Not(isNull), isNull, exact) : T(isNull, Z.Not(isNull), exact);
      }
      case "cmp": return this.cmp(e.op, e.l, e.r, sc, depth);
      case "any": {
        if (e.r.k !== "array") throw new UnsupportedSql("ANY over a non-literal array");
        const a = e.r.items.map((it) => this.cmp(e.op, e.l, it, sc, depth));
        return T(this.or(a.map((x) => x.t)), this.and(a.map((x) => x.f)), a.every((x) => x.exact));
      }
      case "in": {
        let r: B;
        if (e.list) { const a = e.list.map((it) => this.cmp("=", e.l, it, sc, depth)); r = T(this.or(a.map((x) => x.t)), this.and(a.map((x) => x.f)), a.every((x) => x.exact)); }
        else r = this.inSub(e.l, e.sub!, sc, depth);
        return e.neg ? T(r.f, r.t, r.exact) : r;
      }
      case "exists": { const t = this.existsSub(e.sub, sc, depth, null); return T(t, Z.Bool.const(this.fresh("not_exists")), false); }
      case "col": { const c = this.resolve(e, sc); if (c.kind !== "bool") throw new UnsupportedSql("non-boolean column used as condition"); return c; }
      case "cast": return this.b(e.e, sc, depth);
      case "scalar": {
        if (e.sub.from.length === 0 && e.sub.targets.length === 1 && !e.sub.where) return this.b(e.sub.targets[0]!, sc, depth);
        const x = Z.Bool.const(this.fresh("scalar_bool")); return T(x, Z.Not(x), false);
      }
      case "case": { const x = Z.Bool.const(this.fresh("case_bool")); return T(x, Z.Not(x), false); }
      case "call": return this.callB(e, sc, depth);
      default: throw new UnsupportedSql(`boolean ${e.k}`);
    }
  }
  cmp(op: string, l: Expr, r: Expr, sc: Row[], depth: number): B {
    const Z = this.Z;
    const kl = this.kind(l, sc), kr = this.kind(r, sc);
    if (kl === "null" || kr === "null") return { kind: "bool", t: Z.Bool.val(false), f: Z.Bool.val(false), exact: true };
    if (kl === "bool" || kr === "bool") {
      const a = this.b(l, sc, depth), c = this.b(r, sc, depth);
      const eq = Z.Or(Z.And(a.t, c.t), Z.And(a.f, c.f)), ne = Z.Or(Z.And(a.t, c.f), Z.And(a.f, c.t));
      if (op === "=") return { kind: "bool", t: eq, f: ne, exact: a.exact && c.exact };
      if (op === "<>" || op === "!=") return { kind: "bool", t: ne, f: eq, exact: a.exact && c.exact };
      throw new UnsupportedSql(`boolean ${op}`);
    }
    const a = this.v(l, sc, depth), c = this.v(r, sc, depth);
    const both = Z.And(a.n, c.n);
    if (op === "=" || op === "<>" || op === "!=") {
      const eq = a.v.eq(c.v);
      const t = op === "=" ? Z.And(both, eq) : Z.And(both, Z.Not(eq));
      const f = op === "=" ? Z.And(both, Z.Not(eq)) : Z.And(both, eq);
      return { kind: "bool", t, f, exact: a.exact && c.exact };
    }
    const rel = this.fn(`op${op}`, 2, [false, false], "bool").call(a.v, c.v);
    return { kind: "bool", t: Z.And(both, rel), f: Z.And(both, Z.Not(rel)), exact: a.exact && c.exact };
  }
  v(e: Expr, sc: Row[], depth: number): V {
    const Z = this.Z;
    const V_ = (v: any, n: any, exact = true): V => ({ kind: "val", v, n, exact });
    switch (e.k) {
      case "lit": return V_(this.lit(e.v), Z.Bool.val(true));
      case "null": return V_(Z.Const(this.fresh("null"), this.Val), Z.Bool.val(false));
      case "col": { const c = this.resolve(e, sc); if (c.kind !== "val") throw new UnsupportedSql("boolean column used as value"); return c; }
      case "cast": {
        const inner = this.kind(e.e, sc) === "null" ? V_(Z.Const(this.fresh("null"), this.Val), Z.Bool.val(false)) : this.v(e.e, sc, depth);
        if (TRANSPARENT_CASTS.has(e.type)) return inner;
        return V_(this.fn(`cast:${e.type}`, 1, [false], "val").call(inner.v), inner.n, inner.exact);
      }
      case "scalar": {
        if (e.sub.from.length === 0 && e.sub.targets.length === 1 && !e.sub.where) return this.v(e.sub.targets[0]!, sc, depth);
        return V_(Z.Const(this.fresh("scalar"), this.Val), Z.Bool.const(this.fresh("scalar_nn")), false);
      }
      case "case": {
        const conds = e.whens.map(([c]) => this.b(c, sc, depth));
        const vals = e.whens.map(([, x]) => (this.kind(x, sc) === "null" ? V_(Z.Const(this.fresh("null"), this.Val), Z.Bool.val(false)) : this.v(x, sc, depth)));
        const els = e.els && this.kind(e.els, sc) !== "null" ? this.v(e.els, sc, depth) : V_(Z.Const(this.fresh("null"), this.Val), Z.Bool.val(false));
        if (!conds.every((c) => c.exact)) return V_(Z.Const(this.fresh("case"), this.Val), Z.Bool.const(this.fresh("case_nn")), false);
        let v = els.v, n = els.n;
        for (let i = conds.length - 1; i >= 0; i--) { v = Z.If(conds[i]!.t, vals[i]!.v, v); n = Z.If(conds[i]!.t, vals[i]!.n, n); }
        return V_(v, n, vals.every((x) => x.exact) && els.exact);
      }
      case "binop": {
        const a = this.v(e.l, sc, depth), c = this.v(e.r, sc, depth);
        return V_(this.fn(`op${e.op}`, 2, [false, false], "val").call(a.v, c.v), Z.And(a.n, c.n), a.exact && c.exact);
      }
      case "call": return this.callV(e, sc, depth);
      default: throw new UnsupportedSql(`value ${e.k}`);
    }
  }
  private settingName(e: Extract<Expr, { k: "call" }>) {
    const a = e.args[0];
    const lit = a?.k === "cast" ? a.e : a;
    if (lit?.k !== "lit" || !lit.v.startsWith("s:")) throw new UnsupportedSql("current_setting with a computed name");
    return lit.v.slice(2);
  }
  callV(e: Extract<Expr, { k: "call" }>, sc: Row[], depth: number): V {
    const Z = this.Z;
    if (M.IDENTITY_FUNCTIONS.has(e.name) && e.args.length === 0) return { kind: "val", v: this.caller, n: this.callerN, exact: true };
    if (e.name === "current_setting") {
      const s = this.settingName(e);
      if (M.IDENTITY_SETTINGS.has(s)) return { kind: "val", v: this.caller, n: this.callerN, exact: true };
      if (s === "rout.purge_user_id") return { kind: "val", v: this.purgeTarget, n: this.purgeActive, exact: true };
      return { kind: "val", v: Z.Const(`setting:${s}`, this.Val), n: Z.Bool.const(`setting:${s}.set`), exact: true };
    }
    if (e.name === "rout_workspace_role" && e.args.length === 1) {
      const w = this.v(e.args[0]!, sc, depth);
      return { kind: "val", v: this.roleOf(w.v), n: Z.And(w.n, this.member(w.v)), exact: w.exact };
    }
    if (e.name === "rout_current_username" && e.args.length === 0)
      return { kind: "val", v: this.uname(this.caller), n: Z.And(this.callerN, this.unameN(this.caller)), exact: true };
    if (e.name === "nullif" && e.args.length === 2) {
      const a = this.v(e.args[0]!, sc, depth), c = this.v(e.args[1]!, sc, depth);
      return { kind: "val", v: a.v, n: Z.And(a.n, Z.Not(Z.And(c.n, a.v.eq(c.v)))), exact: a.exact && c.exact };
    }
    if (e.name === "coalesce" && e.args.length >= 1) {
      const xs = e.args.map((x) => this.v(x, sc, depth));
      let v = xs[xs.length - 1]!.v;
      for (let i = xs.length - 2; i >= 0; i--) v = Z.If(xs[i]!.n, xs[i]!.v, v);
      return { kind: "val", v, n: this.or(xs.map((x) => x.n)), exact: xs.every((x) => x.exact) };
    }
    if (e.name === "lower" && e.args.length === 1) {
      const a = this.v(e.args[0]!, sc, depth);
      return { kind: "val", v: this.lower(a.v), n: a.n, exact: a.exact };
    }
    // Any other function: an uninterpreted function of its arguments (and their nullness).
    const args = e.args.map((x) => (this.kind(x, sc) === "bool" ? this.b(x, sc, depth) : this.kind(x, sc) === "null" ? null : this.v(x, sc, depth)));
    const flat: any[] = [], kinds: boolean[] = [];
    for (const a of args) {
      if (!a) { flat.push(Z.Bool.val(false)); kinds.push(true); continue; }
      if (a.kind === "bool") { flat.push(a.t, a.f); kinds.push(true, true); }
      else { flat.push(a.v, a.n); kinds.push(false, true); }
    }
    const f = this.fn(`fn:${e.name}`, flat.length, kinds, "val"), fn = this.fn(`fn:${e.name}.notnull`, flat.length, kinds, "bool");
    return { kind: "val", v: flat.length ? f.call(...flat) : Z.Const(`fn:${e.name}()`, this.Val), n: flat.length ? fn.call(...flat) : Z.Bool.const(`fn:${e.name}().notnull`), exact: args.every((a) => !a || a.exact) };
  }
  callB(e: Extract<Expr, { k: "call" }>, sc: Row[], depth: number): B {
    const Z = this.Z;
    const T = (t: any, f: any, exact = true): B => ({ kind: "bool", t, f, exact });
    if (e.name === "rout_caller_is_admin" && e.args.length === 0) return T(this.admin, Z.Not(this.admin));
    if (e.name === "rout_is_workspace_member" && e.args.length === 1) {
      const w = this.v(e.args[0]!, sc, depth);
      const t = Z.And(w.n, this.member(w.v));
      return T(t, Z.Not(t), w.exact);
    }
    if (e.name === "rout_workspace_claimable" && e.args.length === 1 && this.verifier.pinned(e.name)) {
      // Pinned body: true only for a workspace with no member at all (and created minutes ago).
      const w = this.v(e.args[0]!, sc, depth);
      const c = this.fn("workspace_claimable", 1, [false], "bool").call(w.v);
      this.facts.push(this.Z.Implies(this.hasMember(w.v), this.Z.Not(c)));
      const t = Z.And(w.n, c);
      return T(t, Z.Not(t), w.exact);
    }
    if (e.name === "rout_tenant_ref_kept" && e.args.length === 3 && this.keptRow && this.verifier.pinned(e.name)) {
      // Pinned body: true iff the row with this id (the primary key) already holds this value in that
      // column. Inside an UPDATE's WITH CHECK the statement still reads the pre-image.
      const row = this.keptRow;
      const a0 = e.args[0]!.k === "cast" ? (e.args[0] as Extract<Expr, { k: "cast" }>).e : e.args[0]!;
      const [a1, a2] = [e.args[1]!, e.args[2]!];
      if (a0.k === "lit" && a0.v === `s:${row.table.name}` && a1.k === "col" && a2.k === "col") {
        const id = this.resolve(a1, sc), ref = this.resolve(a2, sc);
        const col = [...row.cols.entries()].find(([, v]) => v === ref)?.[0];
        if (id === this.column(row, "id") && col && col !== "id") { const k = this.kept(row, col); return T(k, Z.Not(k)); }
      }
    }
    if (e.name === "rout_purge_due" && e.args.length === 1) {
      const x = this.v(e.args[0]!, sc, depth);
      const t = Z.And(x.n, this.purgeActive, x.v.eq(this.purgeTarget), this.fn("deletion_due", 1, [false], "bool").call(x.v));
      return T(t, Z.Not(t), x.exact);
    }
    const r = this.callV({ ...e, name: `bool:${e.name}` }, sc, depth);
    const b = this.fn(`truth:${e.name}`, 1, [false], "bool").call(r.v);
    return T(Z.And(r.n, b), Z.And(r.n, Z.Not(b)), r.exact);
  }

  // ---- subqueries (positive occurrences only; negative ones are left free)
  private rowsFor(sub: Sel, depth: number, bypass: boolean) {
    const rows: Row[] = [];
    const vis: any[] = [];
    for (const f of sub.from) {
      const t = this.verifier.table(f.table);
      if (!t) throw new UnsupportedSql(`unknown table ${f.table}`);
      const row = this.newRow(t, f.alias);
      rows.push(row);
      this.definitional(row);
      if (!bypass) vis.push(this.verifier.visible(this, row, depth + 1));
    }
    return { rows, vis };
  }
  private link(rows: Row[], conj: Expr[], outer: Row[], extraEq: [Expr, Expr] | null) {
    const eqs: [Expr, Expr][] = conj.filter((c): c is Extract<Expr, { k: "cmp" }> => c.k === "cmp" && c.op === "=").map((c) => [c.l, c.r]);
    if (extraEq) eqs.push(extraEq);
    const strip = (x: Expr): Expr => (x.k === "cast" ? strip(x.e) : x);
    for (const row of rows) {
      const linked = eqs.some(([a0, b0]) => {
        for (const [a, b] of [[strip(a0), strip(b0)], [strip(b0), strip(a0)]] as const) {
          if (a.k !== "col" || b.k !== "col") continue;
          if (a.q !== row.alias && !(a.q === null && rows.length === 1)) continue;
          const o = outer.find((r) => (b.q === null || b.q === r.alias || b.q === r.table.name) && r.table.columns.some((c) => c.name === b.name));
          if (!o || !(o as Row & { tenant?: boolean }).tenant) continue;
          if (fksOf(o.table).some((fk) => fk.cols.length === 1 && fk.cols[0] === b.name && fk.table === row.table.name && fk.refCols[0] === a.name)) return true;
        }
        return false;
      });
      if (linked) { (row as Row & { tenant?: boolean }).tenant = true; this.otherTenant(row, false); }
    }
  }
  existsSub(sub: Sel, sc: Row[], depth: number, inLhs: Expr | null, bypass = false): any {
    const { rows, vis } = this.rowsFor(sub, depth, bypass);
    const scope = [...sc, ...rows];
    const conj = sub.where ? (sub.where.k === "and" ? sub.where.a : [sub.where]) : [];
    this.link(rows, conj, sc, inLhs && sub.targets[0] ? [sub.targets[0], inLhs] : null);
    const parts = [...vis];
    if (sub.where) parts.push(this.b(sub.where, scope, depth).t);
    if (inLhs) parts.push(this.cmp("=", inLhs, sub.targets[0]!, scope, depth).t);
    return this.and(parts);
  }
  inSub(l: Expr, sub: Sel, sc: Row[], depth: number): B {
    const Z = this.Z;
    const t0 = sub.targets[0];
    if (sub.from.length === 0 && sub.targets.length === 1 && t0?.k === "call" && t0.args.length === 0) {
      const lemma = this.verifier.srfLemma(t0.name);
      if (!lemma) { const x = Z.Bool.const(this.fresh(`srf:${t0.name}`)); return { kind: "bool", t: x, f: Z.Not(x), exact: false }; }
      return { kind: "bool", t: this.existsSub(lemma, sc, depth, l, true), f: Z.Bool.const(this.fresh("not_in")), exact: false };
    }
    return { kind: "bool", t: this.existsSub(sub, sc, depth, l), f: Z.Bool.const(this.fresh("not_in")), exact: false };
  }
}

// ---------------------------------------------------------------- verifier
const applies = (p: Policy, cmd: Cmd) => (p.roles.includes("public") || p.roles.includes(APP)) && (p.cmd === cmd || p.cmd === "ALL");
const phaseExpr = (p: Policy, phase: Phase): string | null => (phase === "using" ? p.using : p.check ?? (p.cmd === "INSERT" ? null : p.using));

export class Verifier {
  private readonly tables = new Map<string, Table>();
  private readonly fnReturns = new Map<string, string>();
  private readonly lemmaUse = new Set<string>();
  readonly pinUse = new Set<string>();
  private readonly lemmas = new Map<string, Sel | null>();
  private readonly parsed = new Map<string, Expr>();
  /** viewOptions: "schema.name" → pg_class.reloptions, when read from a live database; defaults to the reviewed list. */
  private readonly declassified: ReadonlyArray<M.Declassification>;
  /** extra.declassified: reviewed entries for a held-back migration, tested before they move into DECLASSIFIED. */
  constructor(readonly catalog: Catalog, private readonly viewOptions?: Record<string, string[]>, extra: { declassified?: ReadonlyArray<M.Declassification> } = {}) {
    this.declassified = [...M.DECLASSIFIED, ...(extra.declassified ?? [])];
    for (const t of catalog.tables) if (t.schema === "public" || t.schema === "vault_enclave") this.tables.set(t.schema === "public" ? t.name : `vault_enclave.${t.name}`, t);
    for (const f of catalog.functions) {
      const m = /RETURNS\s+(SETOF\s+)?([\w ."\[\]]+?)\n/.exec(f.def);
      if (m) this.fnReturns.set(f.name, (m[1] ? "setof " : "") + m[2]!.trim());
    }
    for (const [name, l] of Object.entries(M.SRF_LEMMAS)) {
      const fn = catalog.functions.find((f) => f.name === name);
      const body = fn ? /AS \$function\$\n?([\s\S]*?)\n?\$function\$/.exec(fn.def)?.[1] : undefined;
      this.lemmas.set(name, body?.trim() === l.body.trim() ? (parsePolicyExpr(`(${l.sql})`) as Extract<Expr, { k: "scalar" }>).sub : null);
    }
  }
  table(name: string) { return this.tables.get(name); }
  returnsBoolean(name: string) { if (["rout_caller_is_admin", "rout_is_workspace_member", "rout_purge_due", "rout_workspace_claimable", "rout_tenant_ref_kept"].includes(name)) return true; return this.fnReturns.get(name) === "boolean"; }
  /** A helper with a reviewed meaning (tenant-model PINNED_FUNCTIONS) counts only while its body is unchanged. */
  pinned(name: string) {
    const want = M.PINNED_FUNCTIONS[name];
    const fn = this.catalog.functions.find((f) => f.name === name);
    const body = fn ? /AS \$function\$\n?([\s\S]*?)\n?\$function\$/.exec(fn.def)?.[1] : undefined;
    const ok = !!want && body?.replace(/\s+/g, " ").trim() === want.replace(/\s+/g, " ").trim();
    if (ok) this.pinUse.add(name);
    return ok;
  }
  srfLemma(name: string) { const l = this.lemmas.get(name) ?? null; if (l) this.lemmaUse.add(name); return l; }
  parse(src: string) { let e = this.parsed.get(src); if (!e) { e = parsePolicyExpr(src); this.parsed.set(src, e); } return e; }
  /** Table-level privilege, or a column-level grant of that privilege on some columns. */
  grant(t: Table, cmd: Cmd) { return (t.grants[APP] ?? []).includes(cmd) || !!t.columnGrants?.[APP]?.[cmd]?.length; }
  /** Whether rout_app may write column c with cmd (table-level grant, or a column-level grant naming it). */
  writable(t: Table, cmd: "INSERT" | "UPDATE", c: string) { return (t.grants[APP] ?? []).includes(cmd) || !!t.columnGrants?.[APP]?.[cmd]?.includes(c); }
  /** Reviewed declassifications; an entry with columns applies only while rout_app reads exactly a subset of them. */
  declassification(t: Table, name: string, cmd: Cmd) {
    return this.declassified.find((x) => {
      if (x.table !== name || x.cmd !== cmd) return false;
      if (!x.columns) return true;
      if ((t.grants[APP] ?? []).includes("SELECT")) return false;
      const cols = t.columnGrants?.[APP]?.["SELECT"] ?? [];
      return cols.length > 0 && cols.every((c) => x.columns!.includes(c));
    });
  }

  /** A row of a subquery is visible to rout_app only through that table's own SELECT policy. */
  visible(enc: Encoder, row: Row, depth: number): any {
    const t = row.table;
    if (!this.grant(t, "SELECT")) return enc.Z.Bool.val(false);
    if (!t.rls) return enc.Z.Bool.val(true);
    if (depth > 4) return enc.Z.Bool.val(true);
    return this.effective(enc, t, "SELECT", "using", [row], depth) ?? enc.Z.Bool.val(false);
  }
  effective(enc: Encoder, t: Table, cmd: Cmd, phase: Phase, sc: Row[], depth: number): any | null {
    const ps = t.policies.filter((p) => applies(p, cmd));
    const perm = ps.filter((p) => p.permissive).map((p) => phaseExpr(p, phase)).filter((x): x is string => !!x);
    const restr = ps.filter((p) => !p.permissive).map((p) => phaseExpr(p, phase)).filter((x): x is string => !!x);
    if (!perm.length) return null;
    const permT = enc.or(perm.map((s) => enc.b(this.parse(s), sc, depth).t));
    return enc.and([permT, ...restr.map((s) => enc.b(this.parse(s), sc, depth).t)]);
  }

  async run(opts: { smtOut?: string } = {}): Promise<Report> {
    const { init } = await import("z3-solver");
    const { Context } = await init();
    const Z = Context("rls");
    const obligations: Obligation[] = [];
    let smtChecks = 0;
    const usedDecl = new Set<string>(), usedService = new Set<string>();
    const findings: Finding[] = [];
    if (opts.smtOut) mkdirSync(opts.smtOut, { recursive: true });

    for (const t of this.catalog.tables) {
      for (const cmd of CMDS) {
        const phases: Phase[] = cmd === "INSERT" ? ["check"] : cmd === "UPDATE" ? ["using", "check"] : ["using"];
        for (const phase of phases) {
          const name = `${t.schema}.${t.name}`;
          const push = (outcome: Outcome, smt?: string) => obligations.push({ table: name, cmd, phase, outcome, smt });
          if (!this.grant(t, cmd)) { push({ status: "proven", via: "grant" }); continue; }
          if (!t.rls) {
            const s = M.SERVICE_BOUNDARY.find((x) => x.schema === t.schema && x.table === t.name);
            if (s) { usedService.add(name); push({ status: "service_boundary", reason: s.reason }); }
            else push({ status: "unproven", why: "rls_disabled", detail: `${APP} holds ${cmd} on a table without row level security` });
            continue;
          }
          if (!t.policies.some((p) => applies(p, cmd) && p.permissive && phaseExpr(p, phase))) { push({ status: "proven", via: "no_policy" }); continue; }
          const enc = new Encoder(Z, this);
          let goal: any;
          try {
            const row = enc.newRow(t, t.name);
            (row as Row & { tenant?: boolean }).tenant = true;
            const update = cmd === "UPDATE" && phase === "check";
            if (update) enc.keptRow = row;
            const refs = enc.otherTenant(row, true, { excludeOwnKey: cmd === "INSERT" && M.WORKSPACE_TABLES.has(t.name), write: phase === "check", update });
            // A tenant column rout_app may not UPDATE (column-level grants only) keeps its pre-image value.
            if (update) for (const c of tenantColumns(t).workspace) if (!this.writable(t, "UPDATE", c)) enc.facts.push(enc.kept(row, c));
            if (phase === "using") enc.definitional(row); // a row being written does not exist yet
            if (refs === 0) enc.facts.pop(); // tenantless table: H keeps only the privilege facts below
            goal = this.effective(enc, t, cmd, phase, [row], 0);
          } catch (e) {
            if (!(e instanceof UnsupportedSql)) throw e;
            push({ status: "unproven", why: "unsupported", detail: e.message });
            continue;
          }
          const s = new Z.Solver();
          for (const f of enc.facts) s.add(f);
          for (const f of enc.literalFacts()) s.add(f);
          s.add(enc.Z.Not(enc.admin));
          s.add(enc.Z.Not(enc.purgeActive));
          // H must be satisfiable on its own, or UNSAT below would prove nothing.
          if ((await s.check()) !== "sat") { push({ status: "unproven", why: "unsupported", detail: "tenant hypothesis is unsatisfiable (vacuous)" }); continue; }
          s.add(goal);
          const smt = `; ${name} ${cmd} ${phase}: SAT means a stranger's row passes\n${s.toString()}\n(check-sat)\n`;
          smtChecks++;
          const r = await s.check();
          let detail = r === "unknown" ? "solver returned unknown" : "counterexample exists";
          if (r === "sat") detail = `caller authenticated=${s.model().eval(enc.callerN, true).toString()}`;
          (s as { release?: () => void }).release?.();
          if (opts.smtOut) writeFileSync(join(opts.smtOut, `${name}.${cmd}.${phase}.smt2`), smt);
          if (r === "unsat") { push({ status: "proven", via: "smt" }); continue; }
          const d = this.declassification(t, name, cmd);
          if (d) { usedDecl.add(`${name}:${cmd}`); push({ status: "declassified", reason: d.reason }); continue; }
          push({ status: "unproven", why: "satisfiable", detail }, smt);
        }
      }
    }
    for (const o of obligations) if (o.outcome.status === "unproven") findings.push({ id: `rls:${o.table}:${o.cmd}:${o.phase}`, detail: `${o.outcome.why}: ${o.outcome.detail}` });

    // Deny-all enclave.
    const enclaveFindings: Finding[] = [];
    const vt = this.catalog.tables.filter((t) => t.schema === "vault_enclave");
    for (const t of vt) {
      const id = `vault_enclave.${t.name}`;
      if (!t.rls) enclaveFindings.push({ id: `enclave:${id}:rls_off`, detail: "row level security is off" });
      const g = Object.entries(t.grants).filter(([, v]) => v.length);
      if (g.length) enclaveFindings.push({ id: `enclave:${id}:grants`, detail: JSON.stringify(Object.fromEntries(g)) });
      for (const p of t.policies) if (p.permissive && !(p.using === "false" && (p.check === "false" || p.check === null))) enclaveFindings.push({ id: `enclave:${id}:policy:${p.name}`, detail: `permissive policy ${p.using}` });
    }
    for (const s of this.catalog.sequences.filter((s) => s.schema === "vault_enclave")) if (Object.values(s.grants).some((v) => v.length)) enclaveFindings.push({ id: `enclave:${s.name}:sequence`, detail: JSON.stringify(s.grants) });
    for (const v of this.catalog.views.filter((v) => v.schema === "vault_enclave")) enclaveFindings.push({ id: `enclave:${v.name}:view`, detail: "view in vault_enclave" });
    const schemaGrant = this.catalog.schemaGrants[`vault_enclave:${APP}`] ?? [];
    if (schemaGrant.some((p) => p !== "USAGE")) enclaveFindings.push({ id: "enclave:schema", detail: `schema privileges ${schemaGrant.join(",")}` });
    findings.push(...enclaveFindings);

    // search_path on every SECURITY DEFINER function.
    const definers = this.catalog.functions.filter((f) => isSecurityDefinerDef(f.def));
    const spFindings: Finding[] = definers
      .filter((f) => (searchPathFromDef(f.def) ?? []).join(", ") !== "pg_catalog, pg_temp")
      .map((f) => ({ id: `search_path:${f.schema}.${f.name}(${f.args})`, detail: String(searchPathFromDef(f.def)) }));
    findings.push(...spFindings);

    // Views run with their owner's rights unless security_invoker is set: RLS of the base table does not apply.
    const views: Finding[] = [];
    for (const v of this.catalog.views) {
      const g = v.grants[APP] ?? [];
      if (!g.length) continue;
      const key = `${v.schema}.${v.name}`;
      const invoker = this.viewOptions ? (this.viewOptions[key] ?? []).includes("security_invoker=true") : M.INVOKER_VIEWS.has(key);
      if (invoker) continue;
      if (g.some((p) => p !== "SELECT")) views.push({ id: `view:${v.schema}.${v.name}:writable_definer_view`, detail: `${APP} holds ${g.join(",")} on a view that runs with its owner's rights` });
      const d = M.DECLASSIFIED.find((x) => x.table === key && x.cmd === "SELECT");
      if (d) usedDecl.add(`${key}:SELECT`);
      else if (g.includes("SELECT")) views.push({ id: `view:${v.schema}.${v.name}:definer_read`, detail: "reads the base table with the owner's rights, so RLS on it does not apply" });
    }
    findings.push(...views);
    // pushed after the oracle scan below

    // Unique keys on writable tenant tables are existence oracles across tenants
    // (a duplicate-key error answers "does a row with this value exist?").
    const oracles: Finding[] = [];
    const oracleSeen = new Set<string>();
    for (const t of this.catalog.tables.filter((x) => x.schema === "public" && (this.grant(x, "INSERT") || this.grant(x, "UPDATE")))) {
      const { identity, workspace } = tenantColumns(t);
      if (!identity.length && !workspace.length) continue;
      const keys: string[][] = [];
      for (const c of t.constraints) if (c.kind === "u" || c.kind === "p") { const m = /\(([^)]+)\)/.exec(c.def); if (m) keys.push(m[1]!.split(",").map((s) => s.trim().replace(/"/g, ""))); }
      for (const i of t.indexes) { const m = /^CREATE UNIQUE INDEX \S+ ON \S+ USING \w+ \((.+?)\)(?: WHERE .*)?$/.exec(i); if (m) keys.push(m[1]!.split(",").map((s) => s.trim())); }
      for (const k of keys) {
        if (k.some((c) => identity.includes(c) || workspace.includes(c))) continue;
        // A duplicate-key error needs a write that sets a key column.
        if (!k.some((c) => this.writable(t, "INSERT", c.replace(/^lower\((.+)\)$/, "$1")) || this.writable(t, "UPDATE", c.replace(/^lower\((.+)\)$/, "$1")))) continue;
        const random = k.length === 1 && /gen_random_uuid\(\)|nextval\(/.test(t.columns.find((c) => c.name === k[0])?.default ?? "");
        if (random) continue;
        if (k.length === 1 && M.IDENTITY_COLUMN.test(k[0]!)) continue;
        const key = `${t.name}(${k.join(",")})`;
        oracleSeen.add(key);
        oracles.push({ id: `oracle:${key}`, detail: M.ORACLE_REVIEW[key] ? `reviewed: ${M.ORACLE_REVIEW[key]}` : "unique key without a tenant column on a table rout_app can write" });
      }
    }

    findings.push(...oracles.filter((o) => !o.detail.startsWith("reviewed:")));
    const unusedModelEntries = [
      ...this.declassified.filter((d) => !usedDecl.has(`${d.table}:${d.cmd}`)).map((d) => `declassified:${d.table}:${d.cmd}`),
      ...Object.keys(M.ORACLE_REVIEW).filter((k) => !oracleSeen.has(k)).map((k) => `oracle_review:${k}`),
      ...M.SERVICE_BOUNDARY.filter((s) => !usedService.has(`${s.schema}.${s.table}`)).map((s) => `service:${s.schema}.${s.table}`),
      ...M.KNOWN_OPEN.filter((k) => !findings.some((f) => f.id === k.id)).map((k) => `known_open:${k.id}`),
      ...Object.keys(M.SRF_LEMMAS).filter((n) => !this.lemmaUse.has(n)).map((n) => `lemma:${n}`),
    ];
    return { obligations, smtChecks, enclave: { tables: vt.length, findings: enclaveFindings }, searchPath: { definers: definers.length, findings: spFindings }, views, oracles, findings, unusedModelEntries };
  }
}

export const loadSnapshot = (root = process.cwd()) => JSON.parse(readFileSync(join(root, "db", "schema.snapshot.json"), "utf8")) as Catalog;

if (import.meta.main) {
  const args = process.argv.slice(2);
  const at = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
  const report = await new Verifier(loadSnapshot()).run({ smtOut: at("--smt-out") });
  const count = (s: Outcome["status"]) => report.obligations.filter((o) => o.outcome.status === s).length;
  console.log(`${report.obligations.length} obligations, ${report.smtChecks} Z3 checks: ${count("proven")} proven, ${count("declassified")} declassified, ${count("service_boundary")} service boundary, ${count("unproven")} unproven.`);
  console.log(`vault_enclave: ${report.enclave.tables} tables, ${report.enclave.findings.length} findings. SECURITY DEFINER: ${report.searchPath.definers} functions, ${report.searchPath.findings.length} without pg_catalog, pg_temp.`);
  console.log(`Views: ${report.views.length} findings. Unique-key oracles: ${report.oracles.length}.`);
  const open = new Set(M.KNOWN_OPEN.map((k) => k.id));
  const fresh = report.findings.filter((f) => !open.has(f.id));
  for (const f of report.findings) console.log(`${open.has(f.id) ? "known" : "NEW  "} ${f.id} — ${f.detail}`);
  for (const u of report.unusedModelEntries) console.log(`UNUSED ${u}`);
  if (at("--json")) writeFileSync(at("--json")!, JSON.stringify(report, null, 2));
  process.exitCode = fresh.length || report.unusedModelEntries.length ? 1 : 0;
}
