// @vitest-environment node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { withZkFrame, ZK_ENGINE_ABI, ZK_ENGINE_PAGES, zkEngineModule } from "./zk-engine";
import { ROUT_ZK_WASM_BASE64 } from "./zk-wasm-bytes";
import { ROUT_ZK_WASM_SHA384 } from "./zk-wasm-pin";

describe("committed rout-zk engine", () => {
  it("the pin, the committed .wasm and its embedded base64 copy are the same bytes", () => {
    const file = readFileSync(join(__dirname, "wasm", "rout-zk.wasm"));
    expect(ROUT_ZK_WASM_SHA384).toMatch(/^[0-9a-f]{96}$/);
    expect(createHash("sha384").update(file).digest("hex")).toBe(ROUT_ZK_WASM_SHA384);
    expect(Buffer.from(ROUT_ZK_WASM_BASE64!, "base64").equals(file)).toBe(true);
  });

  it("compiles, has ABI 6, imports only fixed memory and the CSPRNG, and has no memory.grow", async () => {
    const module = await zkEngineModule();
    expect(WebAssembly.Module.imports(module).map((i) => `${i.module}.${i.name}:${i.kind}`).sort()).toEqual(["env.memory:memory", "env.rout_random:function"]);
    expect(ZK_ENGINE_ABI).toBe(6);
    expect(await withZkFrame((f) => f.ex.rout_zk_abi_version())).toBe(6);
    expect(WebAssembly.Module.exports(module).some((e) => e.kind === "memory")).toBe(false);
    const wabt = await (await import("wabt")).default();
    const text = wabt.readWasm(readFileSync(join(__dirname, "wasm", "rout-zk.wasm")), { readDebugNames: false }).toText({});
    expect(text).not.toMatch(/memory\.grow/);
    const limits = /\(import "env" "memory" \(memory \(;\d+;\) (\d+) (\d+)\)\)/.exec(text);
    expect(limits?.slice(1).map(Number)).toEqual([ZK_ENGINE_PAGES, ZK_ENGINE_PAGES]);
    expect(ZK_ENGINE_PAGES).toBe(32);
  });
});
