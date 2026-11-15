/**
 * Parser for the policy expressions Postgres prints with pg_get_expr (the
 * `using` / `check` strings in db/schema.snapshot.json). It covers the
 * deparsed subset those policies use. Anything outside it throws
 * UnsupportedSql, and the verifier counts that policy as unproven rather
 * than guessing.
 */
export class UnsupportedSql extends Error {}

export type Sel = { targets: Expr[]; from: { table: string; alias: string }[]; where: Expr | null };
export type Expr =
  | { k: "bool"; v: boolean }
  | { k: "null" }
  | { k: "lit"; v: string }
  | { k: "col"; q: string | null; name: string }
  | { k: "call"; name: string; args: Expr[] }
  | { k: "cast"; e: Expr; type: string }
  | { k: "and" | "or"; a: Expr[] }
  | { k: "not"; e: Expr }
  | { k: "cmp"; op: string; l: Expr; r: Expr }
  | { k: "isnull"; e: Expr; neg: boolean }
  | { k: "any"; op: string; l: Expr; r: Expr }
  | { k: "array"; items: Expr[] }
  | { k: "in"; l: Expr; list: Expr[] | null; sub: Sel | null; neg: boolean }
  | { k: "exists"; sub: Sel }
  | { k: "scalar"; sub: Sel }
  | { k: "case"; whens: [Expr, Expr][]; els: Expr | null }
  | { k: "binop"; op: string; l: Expr; r: Expr };

type Tok = { t: "id" | "qid" | "str" | "num" | "op"; v: string };
const OPS = ["::", "<>", "!=", "<=", ">=", "!~*", "!~~", "~~*", "!~", "~*", "~~", "||", "=", "<", ">", "~", "+", "-", "*", "/", "(", ")", "[", "]", ",", "."];
const CMP = new Set(["=", "<>", "!=", "<", ">", "<=", ">=", "~", "~*", "!~", "!~*", "~~", "~~*", "!~~"]);
const RESERVED = new Set(["and", "or", "not", "is", "in", "then", "else", "end", "when", "as", "from", "where", "limit", "join", "on", "select", "case", "exists", "any", "all", "array", "null", "true", "false", "inner", "left", "right", "full", "cross", "order", "group", "having", "union", "like", "ilike", "between", "distinct"]);
const TYPE_WORDS = new Set(["with", "without", "time", "zone", "varying", "precision"]);

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) { i++; continue; }
    if (c === "'") {
      let v = ""; i++;
      for (;;) {
        if (i >= src.length) throw new UnsupportedSql("unterminated string");
        if (src[i] === "'" && src[i + 1] === "'") { v += "'"; i += 2; continue; }
        if (src[i] === "'") { i++; break; }
        v += src[i++];
      }
      out.push({ t: "str", v }); continue;
    }
    if (c === '"') {
      const j = src.indexOf('"', i + 1);
      if (j < 0) throw new UnsupportedSql("unterminated identifier");
      out.push({ t: "qid", v: src.slice(i + 1, j) }); i = j + 1; continue;
    }
    const num = /^\d+(\.\d+)?/.exec(src.slice(i));
    if (num) { out.push({ t: "num", v: num[0] }); i += num[0].length; continue; }
    const id = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(src.slice(i));
    if (id) { out.push({ t: "id", v: id[0].toLowerCase() }); i += id[0].length; continue; }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (!op) throw new UnsupportedSql(`unexpected character ${JSON.stringify(c)}`);
    out.push({ t: "op", v: op }); i += op.length;
  }
  return out;
}

class P {
  i = 0;
  constructor(private readonly toks: Tok[]) {}
  peek(o = 0) { return this.toks[this.i + o]; }
  isOp(v: string, o = 0) { const t = this.peek(o); return t?.t === "op" && t.v === v; }
  isKw(v: string, o = 0) { const t = this.peek(o); return t?.t === "id" && t.v === v; }
  eatOp(v: string) { if (!this.isOp(v)) throw new UnsupportedSql(`expected ${v} at ${this.where()}`); this.i++; }
  eatKw(v: string) { if (!this.isKw(v)) throw new UnsupportedSql(`expected ${v.toUpperCase()} at ${this.where()}`); this.i++; }
  where() { return this.toks.slice(this.i, this.i + 4).map((t) => t.v).join(" ") || "end"; }
  done() { return this.i >= this.toks.length; }

  expr(): Expr { return this.or(); }
  or(): Expr { const a = [this.and()]; while (this.isKw("or")) { this.i++; a.push(this.and()); } return a.length === 1 ? a[0]! : { k: "or", a }; }
  and(): Expr { const a = [this.not()]; while (this.isKw("and")) { this.i++; a.push(this.not()); } return a.length === 1 ? a[0]! : { k: "and", a }; }
  not(): Expr { if (this.isKw("not")) { this.i++; return { k: "not", e: this.not() }; } return this.pred(); }
  pred(): Expr {
    const l = this.add();
    if (this.isKw("is")) {
      this.i++;
      const neg = this.isKw("not") ? (this.i++, true) : false;
      if (this.isKw("null")) { this.i++; return { k: "isnull", e: l, neg }; }
      if (this.isKw("true") || this.isKw("false")) {
        const v = this.peek()!.v === "true"; this.i++;
        // x IS TRUE / IS FALSE never yields NULL.
        const base: Expr = { k: "and", a: [{ k: "isnull", e: l, neg: true }, v ? l : { k: "not", e: l }] };
        return neg ? { k: "not", e: base } : base;
      }
      throw new UnsupportedSql(`IS ${this.where()}`);
    }
    const negIn = this.isKw("not") && this.isKw("in", 1);
    if (negIn) this.i++;
    if (this.isKw("in")) {
      this.i++; this.eatOp("(");
      if (this.isKw("select")) { const sub = this.select(); this.eatOp(")"); return { k: "in", l, list: null, sub, neg: negIn }; }
      const list = [this.expr()]; while (this.isOp(",")) { this.i++; list.push(this.expr()); }
      this.eatOp(")"); return { k: "in", l, list, sub: null, neg: negIn };
    }
    const t = this.peek();
    if (t?.t === "op" && CMP.has(t.v)) {
      this.i++;
      if (this.isKw("any") || this.isKw("all")) {
        if (this.isKw("all")) throw new UnsupportedSql("ALL");
        this.i++; this.eatOp("("); const r = this.expr(); this.eatOp(")");
        return { k: "any", op: t.v, l, r };
      }
      return { k: "cmp", op: t.v, l, r: this.add() };
    }
    return l;
  }
  add(): Expr {
    let l = this.cast();
    for (;;) {
      const t = this.peek();
      if (t?.t === "op" && ["||", "+", "-", "*", "/"].includes(t.v)) { this.i++; l = { k: "binop", op: t.v, l, r: this.cast() }; continue; }
      return l;
    }
  }
  cast(): Expr {
    let e = this.primary();
    while (this.isOp("::")) {
      this.i++;
      const words: string[] = [];
      const first = this.peek();
      if (!first || (first.t !== "id" && first.t !== "qid")) throw new UnsupportedSql("cast type");
      words.push(first.v); this.i++;
      if (this.isOp(".")) { this.i++; words.push(this.peek()!.v); this.i++; }
      while (this.peek()?.t === "id" && TYPE_WORDS.has(this.peek()!.v)) { words.push(this.peek()!.v); this.i++; }
      if (this.isOp("(")) { this.i++; while (!this.isOp(")")) this.i++; this.i++; }
      while (this.isOp("[") && this.isOp("]", 1)) { this.i += 2; words.push("[]"); }
      e = { k: "cast", e, type: words.join(" ") };
    }
    return e;
  }
  primary(): Expr {
    const t = this.peek();
    if (!t) throw new UnsupportedSql("unexpected end");
    if (t.t === "str") { this.i++; return { k: "lit", v: `s:${t.v}` }; }
    if (t.t === "num") { this.i++; return { k: "lit", v: `n:${t.v}` }; }
    if (t.t === "op" && t.v === "-" && this.peek(1)?.t === "num") { this.i += 2; return { k: "lit", v: `n:-${this.peek(-1)!.v}` }; }
    if (t.t === "op" && t.v === "(") {
      this.i++;
      if (this.isKw("select")) { const sub = this.select(); this.eatOp(")"); return { k: "scalar", sub }; }
      const e = this.expr(); this.eatOp(")"); return e;
    }
    if (t.t === "id") {
      switch (t.v) {
        case "true": case "false": this.i++; return { k: "bool", v: t.v === "true" };
        case "null": this.i++; return { k: "null" };
        case "exists": { this.i++; this.eatOp("("); const sub = this.select(); this.eatOp(")"); return { k: "exists", sub }; }
        case "array": {
          this.i++; this.eatOp("[");
          const items: Expr[] = [];
          if (!this.isOp("]")) { items.push(this.expr()); while (this.isOp(",")) { this.i++; items.push(this.expr()); } }
          this.eatOp("]"); return { k: "array", items };
        }
        case "case": {
          this.i++;
          if (!this.isKw("when")) throw new UnsupportedSql("simple CASE");
          const whens: [Expr, Expr][] = [];
          while (this.isKw("when")) { this.i++; const c = this.expr(); this.eatKw("then"); whens.push([c, this.expr()]); }
          let els: Expr | null = null;
          if (this.isKw("else")) { this.i++; els = this.expr(); }
          this.eatKw("end"); return { k: "case", whens, els };
        }
      }
      if (RESERVED.has(t.v)) throw new UnsupportedSql(`keyword ${t.v.toUpperCase()}`);
    }
    if (t.t === "id" || t.t === "qid") {
      this.i++;
      const parts = [t.v];
      while (this.isOp(".") && (this.peek(1)?.t === "id" || this.peek(1)?.t === "qid")) { this.i++; parts.push(this.peek()!.v); this.i++; }
      if (this.isOp("(")) {
        this.i++;
        const args: Expr[] = [];
        if (!this.isOp(")")) { args.push(this.expr()); while (this.isOp(",")) { this.i++; args.push(this.expr()); } }
        this.eatOp(")");
        return { k: "call", name: parts[parts.length - 1]!, args };
      }
      if (parts.length === 1) return { k: "col", q: null, name: parts[0]! };
      return { k: "col", q: parts[parts.length - 2]!, name: parts[parts.length - 1]! };
    }
    throw new UnsupportedSql(`unexpected ${t.v}`);
  }
  select(): Sel {
    this.eatKw("select");
    if (this.isKw("distinct")) this.i++;
    const targets: Expr[] = [];
    const target = () => {
      targets.push(this.expr());
      if (this.isKw("as")) { this.i += 2; }
    };
    target(); while (this.isOp(",")) { this.i++; target(); }
    const from: Sel["from"] = [];
    let where: Expr | null = null;
    const extra: Expr[] = [];
    if (this.isKw("from")) {
      this.i++;
      const item = () => {
        const parts = [this.peek()!.v]; this.i++;
        while (this.isOp(".")) { this.i++; parts.push(this.peek()!.v); this.i++; }
        const table = parts[parts.length - 1]!;
        let alias = table;
        if (this.isKw("as")) this.i++;
        const a = this.peek();
        if ((a?.t === "id" && !RESERVED.has(a.v)) || a?.t === "qid") { alias = a.v; this.i++; }
        from.push({ table, alias });
      };
      item();
      for (;;) {
        if (this.isOp(",")) { this.i++; item(); continue; }
        if (this.isKw("join") || (this.isKw("inner") && this.isKw("join", 1))) {
          if (this.isKw("inner")) this.i++;
          this.i++; item(); this.eatKw("on"); extra.push(this.expr()); continue;
        }
        if (["left", "right", "full", "cross"].some((k) => this.isKw(k))) throw new UnsupportedSql("outer join");
        break;
      }
    }
    if (this.isKw("where")) { this.i++; where = this.expr(); }
    if (this.isKw("limit")) { this.i += 2; }
    if (["order", "group", "having", "union"].some((k) => this.isKw(k))) throw new UnsupportedSql(this.peek()!.v.toUpperCase());
    if (extra.length) where = { k: "and", a: where ? [...extra, where] : extra };
    return { targets, from, where };
  }
}

export function parsePolicyExpr(src: string): Expr {
  const p = new P(lex(src));
  const e = p.expr();
  if (!p.done()) throw new UnsupportedSql(`trailing input at ${p.where()}`);
  return e;
}
