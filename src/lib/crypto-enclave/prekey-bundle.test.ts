// @vitest-environment node
import { afterEach, describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import { b64u, fromB64u } from "@/lib/anon-booking/zkp-anchor";
import { decodePrekeyBundle, prekeyChallenge, prekeyContext, prekeyStatement, verifyPrekeyDocument, PREKEY_BUNDLE_BYTES, PREKEY_MAX_AGE_EPOCHS } from "./prekey-bundle";
import { MDS3_OK, RP, signedPrekey , useEnclave } from "@/test/prekey-test-helpers";
import { sha256 } from "@noble/hashes/sha2.js";

const B = "00000000-0000-4000-8000-00000000b801";
const DAY = 86_400_000;
const expect_ = (now?: number) => ({ ...RP, handle: "bob", now });

useEnclave(runEnclaveOp);

afterEach(async () => {
  await runEnclaveOp("secure.wipe" as never, {} as never);
});

describe("prekey bundle (Stap 8): creation, signature, context, refusal", () => {
  it("worker creates a 1646-byte bundle whose challenge is SHA-256 of the statement", async () => {
    const p = await signedPrekey(B, "bob");
    expect(p.bundle).toHaveLength(PREKEY_BUNDLE_BYTES);
    expect(p.challenge).toEqual(sha256(prekeyStatement("rout.be", "bob", p.bundle)));
    expect(p.challenge).toEqual(prekeyChallenge("rout.be", "bob", p.bundle));
    const b = decodePrekeyBundle(p.bundle);
    const v = await verifyPrekeyDocument(p.document, expect_());
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.context).toBe(prekeyContext("rout.be", "bob", b.epoch, b.nonce));
    expect(p.document.handle).toBe("@bob");
  });

  it("refuses a bundle older than 30 UTC days", async () => {
    const p = await signedPrekey(B, "bob");
    const later = Date.now() + (PREKEY_MAX_AGE_EPOCHS + 1) * DAY;
    expect(await verifyPrekeyDocument(p.document, expect_(later))).toEqual({ ok: false, reason: "stale" });
    expect((await verifyPrekeyDocument(p.document, expect_(Date.now() + (PREKEY_MAX_AGE_EPOCHS - 1) * DAY))).ok).toBe(true);
  });

  it("refuses an altered bundle, a forged signature and a missing MDS3 pass", async () => {
    const p = await signedPrekey(B, "bob");
    const bytes = fromB64u(p.document.bundle);
    bytes[100]! ^= 1;
    expect((await verifyPrekeyDocument({ ...p.document, bundle: b64u(bytes) }, expect_())).ok).toBe(false);
    const sig = fromB64u(p.document.passkey.signature);
    sig[sig.length - 1]! ^= 1;
    expect((await verifyPrekeyDocument({ ...p.document, passkey: { ...p.document.passkey, signature: b64u(sig) } }, expect_())).ok).toBe(false);
    const unsigned = { ...p.document, passkey: { ...p.document.passkey, signature: "" } };
    expect((await verifyPrekeyDocument(unsigned, expect_())).ok).toBe(false);
    for (const mds3 of [{ ...MDS3_OK, attested: false }, { ...MDS3_OK, statusSafe: false }]) {
      expect(await verifyPrekeyDocument({ ...p.document, passkey: { ...p.document.passkey, mds3 } }, expect_())).toEqual({ ok: false, reason: "mds3" });
    }
    expect(await verifyPrekeyDocument(p.document, { ...expect_(), handle: "eve" })).toEqual({ ok: false, reason: "handle" });
    expect(await verifyPrekeyDocument(p.document, { ...expect_(), rpId: "evil.example" })).toEqual({ ok: false, reason: "rp_id" });
  });
});
