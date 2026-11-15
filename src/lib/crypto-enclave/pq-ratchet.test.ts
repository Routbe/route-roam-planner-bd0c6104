// @vitest-environment node
/**
 * Stap 8 worker adapters: pq_ratchet.init_session / ratchet_encrypt /
 * ratchet_decrypt / close_session over the committed, pinned rout-zk engine
 * (ABI 6). The protocol itself is covered by the native Rust tests in
 * wasm/rout-zk/tests/pq_ratchet.rs; here: the worker boundary, state held
 * only in the worker and replaced in place, unchanged state on rejection,
 * wiping, and the engine memory reading back as zeros.
 */
import { afterEach, describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { isRve2Message, pqSessions, PQR_BUNDLE_BYTES, PQR_ENVELOPE_OVERHEAD, PQR_MAX_PLAINTEXT, PQR_STATE_BYTES } from "./pq-ratchet";
import { lastZkMemoryForTest } from "./zk-engine";
import { RP, signedPrekey , useEnclave } from "@/test/prekey-test-helpers";

const A = "00000000-0000-4000-8000-00000000a008";
const B = "00000000-0000-4000-8000-00000000b008";
const CONTEXT = `rout.pqr.v1|${A}|${B}|conversation-8`;
const enc = new TextEncoder();
const dec = new TextDecoder();

async function op<T>(name: string, args: Record<string, unknown>): Promise<T> {
  const r = await runEnclaveOp(name as never, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as T;
}
const code = async (name: string, args: Record<string, unknown>) => {
  const r = await runEnclaveOp(name as never, args);
  return r.ok ? "ok" : r.code;
};

async function session() {
  const bob = await signedPrekey(B, "bob");
  const alice = await op<{ sessionId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document: bob.document, handle: "bob", ...RP });
  const send = async (from: string, id: string, text: string) =>
    (await op<{ envelope: Uint8Array }>("pq_ratchet.ratchet_encrypt", { userId: from, sessionId: id, plaintext: enc.encode(text) })).envelope;
  const recv = async (to: string, id: string, envelope: Uint8Array) =>
    dec.decode((await op<{ plaintext: Uint8Array }>("pq_ratchet.ratchet_decrypt", { userId: to, sessionId: id, envelope: envelope.slice() })).plaintext);
  return { bob, alice, send, recv };
}

useEnclave(runEnclaveOp);

afterEach(async () => {
  await runEnclaveOp("secure.wipe" as never, {});
});

describe("pq_ratchet worker ops (Stap 8, pinned rout-zk ABI 6)", () => {
  it("handshake + messages both ways, RVE2 envelopes, engine memory zero after every call", async () => {
    const { bob, alice, send, recv } = await session();
    expect(bob.bundle).toHaveLength(1646);
    expect(Array.from(bob.bundle.subarray(0, 6))).toEqual([0x52, 0x56, 0x45, 0x32, 1, 3]);
    const e1 = await send(A, alice.sessionId, "hallo Bob");
    expect(isRve2Message(e1)).toBe(true);
    expect(e1.length).toBe(PQR_ENVELOPE_OVERHEAD + 9);
    expect(lastZkMemoryForTest()!.every((b) => b === 0)).toBe(true);
    expect(await recv(B, bob.sessionId, e1)).toBe("hallo Bob");
    expect(lastZkMemoryForTest()!.every((b) => b === 0)).toBe(true);
    const e2 = await send(B, bob.sessionId, "status: beschikbaar");
    expect(await recv(A, alice.sessionId, e2)).toBe("status: beschikbaar");
    // Out of order across the worker boundary.
    const a = [await send(A, alice.sessionId, "a1"), await send(A, alice.sessionId, "a2"), await send(A, alice.sessionId, "a3")];
    expect(await recv(B, bob.sessionId, a[2]!)).toBe("a3");
    expect(await recv(B, bob.sessionId, a[0]!)).toBe("a1");
    expect(await recv(B, bob.sessionId, a[1]!)).toBe("a2");
  });

  it("the held state is replaced in place; a rejected envelope leaves it byte-for-byte unchanged", async () => {
    const { bob, alice, send, recv } = await session();
    const held = pqSessions.peek(A, alice.sessionId)!;
    expect(held).toHaveLength(PQR_STATE_BYTES);
    const before = held.slice();
    const e1 = await send(A, alice.sessionId, "eerste");
    expect(pqSessions.peek(A, alice.sessionId)).toBe(held);
    expect(Buffer.from(held).equals(Buffer.from(before))).toBe(false);
    await recv(B, bob.sessionId, e1);
    const bobHeld = pqSessions.peek(B, bob.sessionId)!;
    const e2 = await send(A, alice.sessionId, "tweede");
    const snapshot = bobHeld.slice();
    for (const at of [7, 40, 2000, 3180, e2.length - 20, e2.length - 1]) {
      const t = e2.slice();
      t[at]! ^= 0x01;
      expect(await code("pq_ratchet.ratchet_decrypt", { userId: B, sessionId: bob.sessionId, envelope: t })).toMatch(/^(decrypt_failed|invalid_input)$/);
      expect(Buffer.from(bobHeld).equals(Buffer.from(snapshot))).toBe(true);
    }
    expect(await recv(B, bob.sessionId, e2)).toBe("tweede");
    // A replay finds no key.
    expect(await code("pq_ratchet.ratchet_decrypt", { userId: B, sessionId: bob.sessionId, envelope: e2.slice() })).toBe("decrypt_failed");
  });

  it("sessions belong to one member; the plaintext input is wiped; bad input is refused", async () => {
    const { bob, alice, send } = await session();
    const pt = enc.encode("geheim");
    await op("pq_ratchet.ratchet_encrypt", { userId: A, sessionId: alice.sessionId, plaintext: pt });
    expect(pt.every((b) => b === 0)).toBe(true);
    expect(await code("pq_ratchet.ratchet_encrypt", { userId: B, sessionId: alice.sessionId, plaintext: enc.encode("x") })).toBe("invalid_input");
    expect(await code("pq_ratchet.ratchet_encrypt", { userId: B, sessionId: bob.sessionId, plaintext: enc.encode("x") })).toBe("invalid_input"); // responder sends after receiving
    expect(await code("pq_ratchet.ratchet_encrypt", { userId: A, sessionId: alice.sessionId, plaintext: new Uint8Array(PQR_MAX_PLAINTEXT + 1) })).toBe("invalid_input");
    expect(await code("pq_ratchet.init_session", { userId: A, role: "initiator", context: CONTEXT, peerBundle: new Uint8Array(PQR_BUNDLE_BYTES) })).toBe("invalid_input");
    expect(await code("pq_ratchet.init_session", { userId: A, role: "initiator", document: {}, handle: "bob", ...RP })).toBe("bundle_rejected");
    expect(await code("pq_ratchet.init_session", { userId: A, role: "responder", context: "" })).toBe("invalid_input");
    expect(await code("pq_ratchet.init_session", { userId: A, role: "other", context: CONTEXT })).toBe("invalid_input");
    expect(await code("pq_ratchet.ratchet_decrypt", { userId: B, sessionId: "pqs_nope", envelope: new Uint8Array(10) })).toBe("invalid_input");
    // A bundle published for another handle does not open this conversation.
    const other = await signedPrekey(B, "carol");
    expect(await code("pq_ratchet.init_session", { userId: A, role: "initiator", document: other.document, handle: "bob", ...RP })).toBe("bundle_rejected");
    void send;
  });

  it("close_session and secure.wipe zero-fill the held state", async () => {
    const { bob, alice } = await session();
    const a = pqSessions.peek(A, alice.sessionId)!;
    const b = pqSessions.peek(B, bob.sessionId)!;
    expect(await op("pq_ratchet.close_session", { userId: A, sessionId: alice.sessionId })).toEqual({ closed: true });
    expect(a.every((x) => x === 0)).toBe(true);
    expect(await op("pq_ratchet.close_session", { userId: A, sessionId: alice.sessionId })).toEqual({ closed: false });
    await runEnclaveOp("secure.wipe" as never, {});
    expect(b.every((x) => x === 0)).toBe(true);
    expect(pqSessions.size).toBe(0);
  });
});
