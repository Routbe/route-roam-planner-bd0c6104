// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// The committed engine is pinned (zk-wasm-pin.ts); these tests cover the refusal path without one.
vi.mock("./zk-wasm-pin", () => ({ ROUT_ZK_WASM_SHA384: null }));
vi.mock("./zk-wasm-bytes", () => ({ ROUT_ZK_WASM_BASE64: null }));
import { anonVerifyPresentation, capacityKeyMaterial, capacityOpen, GuestBookingStore, guestCommit, PRESENTATION_MIN_BYTES } from "./anon-booking";
import { HSK_ENVELOPE_BYTES, HSK_PLAINTEXT_BYTES, hskContext, hskPlaintext, parseHskPlaintext } from "./forward-secure";
import { EnvelopePolicyError, generateRecipientKeys, openEnvelope, sealEnvelope } from "./pqc-envelope";
import { ZkEngineError } from "./zk-engine";

describe("anonymous booking adapters without a pinned engine", () => {
  it("refuse before reading any bytes (zk-wasm-pin is null)", async () => {
    await expect(guestCommit(new Uint8Array(32).fill(1))).rejects.toMatchObject({ code: "zk_engine_unpinned" });
    await expect(capacityOpen(new Uint8Array(32).fill(1), "cp_x", 3)).rejects.toMatchObject({ code: "zk_engine_unpinned" });
  });

  it("reject malformed inputs before the engine", async () => {
    await expect(guestCommit(new Uint8Array(31))).rejects.toBeInstanceOf(ZkEngineError);
    await expect(capacityOpen(new Uint8Array(32), "", 1)).rejects.toMatchObject({ code: "zk_invalid_input" });
    await expect(capacityOpen(new Uint8Array(32), "cp_x", -1)).rejects.toMatchObject({ code: "zk_invalid_input" });
    // A presentation of the wrong size is simply not valid.
    const pk = new Uint8Array(96);
    expect(await anonVerifyPresentation({ publicKey: pk, keyId: "hk_a", epoch: 0, presentation: new Uint8Array(PRESENTATION_MIN_BYTES - 1), messages: [], nullifier: new Uint8Array(32), challenge: new Uint8Array(1), windowStart: 0, windowEnd: 1 })).toBe(false);
  });

  it("derives distinct, deterministic pool key material per device seed", () => {
    const a = capacityKeyMaterial(new Uint8Array(32).fill(7));
    expect(a).toEqual(capacityKeyMaterial(new Uint8Array(32).fill(7)));
    expect(a).not.toEqual(capacityKeyMaterial(new Uint8Array(32).fill(8)));
    expect(a).toHaveLength(32);
  });

  it("the guest store refuses without an engine and wipes nothing it never held", async () => {
    const s = new GuestBookingStore();
    await expect(s.begin("h1", "host", "hk_a")).rejects.toMatchObject({ code: "zk_engine_unpinned" });
    expect(s.get("h1")).toBeUndefined();
    expect(s.wipeAll()).toBe(0);
    await expect(s.begin("h2", "", "hk_a")).rejects.toMatchObject({ code: "zk_invalid_input" });
  });
});

describe("host state envelope (hsk): member device only", () => {
  it("never seals or opens for the server vault, and binds member and key id", () => {
    const device = generateRecipientKeys("member_device");
    const state = new Uint8Array(32).fill(9);
    const pt = hskPlaintext(state, 7);
    expect(pt).toHaveLength(HSK_PLAINTEXT_BYTES);
    expect(() => sealEnvelope({ kind: "hsk", holder: "server_vault", recipientPublicKey: device.publicKey, plaintext: pt, context: hskContext("u1", "hk_a") }))
      .toThrow(EnvelopePolicyError);
    const env = sealEnvelope({ kind: "hsk", holder: "member_device", recipientPublicKey: device.publicKey, plaintext: pt, context: hskContext("u1", "hk_a") });
    expect(env).toHaveLength(HSK_ENVELOPE_BYTES);
    expect([env[5], env[6]]).toEqual([9, 2]);
    expect(() => openEnvelope({ envelope: env, expectedKind: "hsk", holder: "member_device", secretKey: device.secretKey, context: hskContext("u2", "hk_a") })).toThrow();
    expect(() => openEnvelope({ envelope: env, expectedKind: "hsk", holder: "member_device", secretKey: device.secretKey, context: hskContext("u1", "hk_b") })).toThrow();
    expect(() => openEnvelope({ envelope: env, expectedKind: "vcc", holder: "member_device", secretKey: device.secretKey, context: hskContext("u1", "hk_a") })).toThrow();
    const opened = parseHskPlaintext(openEnvelope({ envelope: env, expectedKind: "hsk", holder: "member_device", secretKey: device.secretKey, context: hskContext("u1", "hk_a") }));
    expect(opened.epoch).toBe(7);
    expect(opened.state).toEqual(state);
  });

  it("parseHskPlaintext wipes its input and rejects other sizes", () => {
    const pt = hskPlaintext(new Uint8Array(32).fill(3), 1);
    const { state } = parseHskPlaintext(pt);
    expect(pt.every((b) => b === 0)).toBe(true);
    expect(state.every((b) => b === 3)).toBe(true);
    expect(() => parseHskPlaintext(new Uint8Array(39))).toThrow(ZkEngineError);
  });
});
