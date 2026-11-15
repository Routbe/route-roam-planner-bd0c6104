// @vitest-environment node
import "fake-indexeddb/auto";
import { afterEach, describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { pqSessions } from "./pq-ratchet";
import { pqSessionVault } from "./pq-session-vault";
import { fromB64u, b64u } from "@/lib/anon-booking/zkp-anchor";
import { assertOver } from "@/test/webauthn-test-authenticator";
import { enclaveCode as code, enclaveOp as op, MDS3_OK, RP, signedPrekey , useEnclave } from "@/test/prekey-test-helpers";
import { publishPrekey, readPrekeyDocument, prekeyObjectKey } from "@/lib/pq/prekey-publish.server";

const A = "00000000-0000-4000-8000-00000000a801";
const B = "00000000-0000-4000-8000-00000000b802";
const enc = new TextEncoder();
const dec = new TextDecoder();
const seed = (x: number) => new Uint8Array(32).fill(x);
const send = async (u: string, id: string, t: string) => (await op<{ envelope: Uint8Array }>("pq_ratchet.ratchet_encrypt", { userId: u, sessionId: id, plaintext: enc.encode(t) })).envelope;
const recv = async (u: string, id: string, e: Uint8Array) => dec.decode((await op<{ plaintext: Uint8Array }>("pq_ratchet.ratchet_decrypt", { userId: u, sessionId: id, envelope: e.slice() })).plaintext);

useEnclave(runEnclaveOp);

afterEach(async () => {
  await runEnclaveOp("secure.wipe" as never, {} as never);
});

describe("Stap 8 integration: verified prekeys, session vault, publication", () => {
  it("1. a PQ session starts from a verified prekey document", async () => {
    const bob = await signedPrekey(B, "bob");
    const alice = await op<{ sessionId: string; prekeyId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document: bob.document, handle: "bob", ...RP });
    expect(alice.prekeyId).toBe(bob.prekeyId);
    expect(await recv(B, bob.sessionId, await send(A, alice.sessionId, "hallo"))).toBe("hallo");
  });

  it("2. an active session is restored from vault_ratchet_sessions after a reload", async () => {
    await op("pq_ratchet.unlock_vault", { userId: A, prfSeed: seed(1), deviceSeed: seed(2) });
    const bob = await signedPrekey(B, "bob");
    const alice = await op<{ sessionId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document: bob.document, handle: "bob", ...RP });
    expect(await recv(B, bob.sessionId, await send(A, alice.sessionId, "een"))).toBe("een");
    const bobSession = pqSessions.peek(B, bob.sessionId)!.slice();
    // Reload: worker memory is gone, IndexedDB stays.
    await op("pq_ratchet.lock_vault", {});
    expect(pqSessions.size).toBe(0);
    const r = await op<{ sessionIds: string[] }>("pq_ratchet.unlock_vault", { userId: A, prfSeed: seed(1), deviceSeed: seed(2) })
      .then(() => op<{ sessionIds: string[]; dropped: number }>("pq_ratchet.load_session_vault", { userId: A }));
    expect(r.sessionIds).toContain(alice.sessionId);
    expect(pqSessions.restore(B, bob.sessionId, bobSession)).toBe(true);
    expect(await recv(B, bob.sessionId, await send(A, alice.sessionId, "twee"))).toBe("twee");
    await op("pq_ratchet.close_session", { userId: A, sessionId: alice.sessionId });
  });

  it("3. unsigned, altered, stale or non-attested prekeys are refused before any session exists", async () => {
    const bob = await signedPrekey(B, "bob");
    const before = pqSessions.size;
    const sig = fromB64u(bob.document.passkey.signature);
    sig[0]! ^= 1;
    const bundle = fromB64u(bob.document.bundle);
    bundle[50]! ^= 1;
    const bad = [
      { ...bob.document, passkey: { ...bob.document.passkey, signature: b64u(sig) } },
      { ...bob.document, bundle: b64u(bundle) },
      { ...bob.document, passkey: { ...bob.document.passkey, mds3: { ...MDS3_OK, statusSafe: false } } },
      (await signedPrekey(B, "bob", { mds3: { ...MDS3_OK, attested: false } })).document,
      { ...bob.document, passkey: { ...bob.document.passkey, publicKey: b64u((await signedPrekey(B, "bob")).auth.cose) } },
    ];
    const sizeBefore = pqSessions.size;
    for (const document of bad) {
      expect(await code("pq_ratchet.init_session", { userId: A, role: "initiator", document, handle: "bob", ...RP })).toBe("bundle_rejected");
    }
    expect(pqSessions.size).toBe(sizeBefore);
    expect(before).toBeGreaterThan(0);
  });

  it("4. close_session and secure.wipe destroy the session state in memory and IndexedDB", async () => {
    await op("pq_ratchet.unlock_vault", { userId: A, prfSeed: seed(3), deviceSeed: seed(4) });
    const bob = await signedPrekey(B, "bob");
    const s1 = await op<{ sessionId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document: bob.document, handle: "bob", ...RP });
    const bob2 = await signedPrekey(B, "bob");
    const s2 = await op<{ sessionId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document: bob2.document, handle: "bob", ...RP });
    const held1 = pqSessions.peek(A, s1.sessionId)!;
    const held2 = pqSessions.peek(A, s2.sessionId)!;
    expect((await pqSessionVault.sessionIds(A)).sort()).toEqual([s1.sessionId, s2.sessionId].sort());
    expect(await op("pq_ratchet.close_session", { userId: A, sessionId: s1.sessionId })).toEqual({ closed: true });
    expect(held1.every((b) => b === 0)).toBe(true);
    expect(await pqSessionVault.sessionIds(A)).toEqual([s2.sessionId]);
    await runEnclaveOp("secure.wipe" as never, {} as never);
    expect(held2.every((b) => b === 0)).toBe(true);
    expect(pqSessions.size).toBe(0);
    expect(pqSessionVault.isOpen).toBe(false);
    expect(await code("pq_ratchet.load_session_vault", { userId: A })).toBe("vault_locked");
    await pqSessionVault.erase(A, s2.sessionId);
  });

  it("E2E: create bundle → publish to (mocked) Scaleway → public read → handshake → messages", async () => {
    const store = new Map<string, Uint8Array>();
    const created = await op<{ sessionId: string; bundle: Uint8Array; challenge: Uint8Array }>("pq_ratchet.create_prekey_bundle", { userId: B, rpId: RP.rpId, handle: "bob" });
    const ref = await signedPrekey(B, "bob");
    const a = await assertOver(ref.auth, created.challenge);
    const deps = {
      ...RP,
      handleOf: async () => "bob",
      passkey: async () => ({ found: true as const, publicKey: ref.auth.cose, ...MDS3_OK }),
      put: async (k: string, b: Uint8Array) => void store.set(k, b),
    };
    const input = { bundle: b64u(created.bundle), credentialId: "c".repeat(22), algorithm: -7, authenticatorData: b64u(a.authenticatorData), clientDataJSON: b64u(a.clientDataJSON), signature: b64u(a.signature) };
    expect(await publishPrekey({ ...deps, passkey: async () => ({ found: true as const, publicKey: ref.auth.cose, ...MDS3_OK, statusSafe: false }) }, B, input)).toEqual({ ok: false, reason: "attestation" });
    expect(store.size).toBe(0);
    const pub = await publishPrekey(deps, B, input);
    expect(pub.ok).toBe(true);
    expect([...store.keys()]).toEqual([prekeyObjectKey(B)]);
    const read = await readPrekeyDocument({ userIdOf: async (h) => (h === "bob" ? B : null), get: async (k) => store.get(k) ?? null }, "@bob");
    expect(read.status).toBe("ok");
    const document = JSON.parse(dec.decode((read as { body: Uint8Array }).body));
    const alice = await op<{ sessionId: string }>("pq_ratchet.init_session", { userId: A, role: "initiator", document, handle: "bob", ...RP });
    expect(await recv(B, created.sessionId, await send(A, alice.sessionId, "post-quantum hallo"))).toBe("post-quantum hallo");
    expect(await recv(A, alice.sessionId, await send(B, created.sessionId, "terug"))).toBe("terug");
  });
});
