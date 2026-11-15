// @vitest-environment node
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { assertOver, makeAuthenticator } from "@/test/webauthn-test-authenticator";
import { anchorChallenge, anchorStatement, b64u, parseCoseKey, toHex, verifyAnchorEndorsement, verifyZkpAnchorDevice, type AnchorStatementInput, type ZkpAnchorDevice } from "./zkp-anchor";

const hex32 = () => toHex(randomBytes(32));
const statement = (): AnchorStatementInput => ({
  deviceId: `hd_${hex32()}`, keyId: `hk_${hex32()}`, treeId: `st_${hex32()}`,
  anchorPublicKey: randomBytes(96), anchorSignerPublicKey: randomBytes(96), rootSignerPublicKey: randomBytes(96),
});
const CHECK = { rpId: "rout.be", origins: ["https://rout.be"] };

describe("zkp-anchor.json: PK_0 signed by the host's MDS3-attested passkey", () => {
  it("statement bytes are fixed: header, length-prefixed ids, three 96-byte keys", () => {
    const s = statement();
    const b = anchorStatement(s);
    expect(b.byteLength).toBe(18 + 3 * (4 + 67) + 3 * 96);
    expect(new TextDecoder().decode(b.slice(0, 18))).toBe("ROUT-ZKP-ANCHOR-V1");
    expect(Array.from(b.slice(18, 22))).toEqual([0, 0, 0, 67]);
    expect(anchorChallenge(s)).toEqual(sha256(b));
    expect(() => anchorStatement({ ...s, keyId: "hk_x" })).toThrow();
    expect(() => anchorStatement({ ...s, anchorPublicKey: randomBytes(95) })).toThrow();
  });

  for (const alg of [-7, -8, -257] as const) {
    it(`accepts a valid ${alg} assertion and rejects every tampered field`, async () => {
      const s = statement();
      const auth = await makeAuthenticator(alg);
      expect(parseCoseKey(auth.cose).alg).toBe(alg);
      const a = await assertOver(auth, anchorChallenge(s));
      const e = { publicKey: auth.cose, algorithm: alg, ...a };
      expect(await verifyAnchorEndorsement(s, e, CHECK)).toEqual({ ok: true });
      // Another anchor (PK_0 swapped) does not match the challenge.
      expect(await verifyAnchorEndorsement({ ...s, anchorPublicKey: randomBytes(96) }, e, CHECK)).toEqual({ ok: false, reason: "challenge" });
      const badSig = a.signature.slice();
      badSig[badSig.length - 1] ^= 1;
      expect((await verifyAnchorEndorsement(s, { ...e, signature: badSig }, CHECK)).ok).toBe(false);
      expect(await verifyAnchorEndorsement(s, e, { rpId: "evil.example", origins: CHECK.origins })).toEqual({ ok: false, reason: "rp_id" });
      expect(await verifyAnchorEndorsement(s, e, { rpId: "rout.be", origins: ["https://evil.example"] })).toEqual({ ok: false, reason: "origin" });
      expect(await verifyAnchorEndorsement(s, { ...e, algorithm: alg === -7 ? -8 : -7 }, CHECK)).toEqual({ ok: false, reason: "algorithm" });
      const other = await makeAuthenticator(alg);
      expect(await verifyAnchorEndorsement(s, { ...e, publicKey: other.cose }, CHECK)).toEqual({ ok: false, reason: "signature" });
    });
  }

  it("accepts high-S ECDSA (authenticators do not normalise S)", async () => {
    const s = statement();
    const auth = await makeAuthenticator(-7, { highS: true });
    const a = await assertOver(auth, anchorChallenge(s));
    expect(await verifyAnchorEndorsement(s, { publicKey: auth.cose, algorithm: -7, ...a }, CHECK)).toEqual({ ok: true });
  });

  it("needs user presence and user verification, and a get (not create) ceremony", async () => {
    const s = statement();
    const auth = await makeAuthenticator(-7);
    const noUv = await assertOver(auth, anchorChallenge(s), { flags: 0x01 });
    expect(await verifyAnchorEndorsement(s, { publicKey: auth.cose, algorithm: -7, ...noUv }, CHECK)).toEqual({ ok: false, reason: "flags" });
    const create = await assertOver(auth, anchorChallenge(s), { type: "webauthn.create" });
    expect(await verifyAnchorEndorsement(s, { publicKey: auth.cose, algorithm: -7, ...create }, CHECK)).toEqual({ ok: false, reason: "type" });
  });

  it("a published device needs ROUT's MDS3 verdict (attested, not compromised) besides a valid signature", async () => {
    const s = statement();
    const auth = await makeAuthenticator(-8);
    const a = await assertOver(auth, anchorChallenge(s));
    const device: ZkpAnchorDevice = {
      deviceId: s.deviceId, keyId: s.keyId, treeId: s.treeId, anchorPublicKey: toHex(s.anchorPublicKey),
      enclaveAnchor: { signerPublicKey: toHex(s.anchorSignerPublicKey), signature: toHex(randomBytes(80)) },
      rootSignerPublicKey: toHex(s.rootSignerPublicKey), epoch: 0, currentPublicKey: toHex(s.anchorPublicKey), retired: false,
      registeredAt: "2026-11-15T08:00:00Z", links: [],
      passkey: { credentialId: "c".repeat(22), algorithm: -8, publicKey: b64u(auth.cose), authenticatorData: b64u(a.authenticatorData), clientDataJSON: b64u(a.clientDataJSON), signature: b64u(a.signature), mds3: { fmt: "packed", attested: true, statusSafe: true, certifiedL3: false } },
    };
    expect(await verifyZkpAnchorDevice(device, CHECK)).toEqual({ ok: true });
    expect(await verifyZkpAnchorDevice({ ...device, passkey: { ...device.passkey, mds3: { ...device.passkey.mds3, statusSafe: false } } }, CHECK)).toEqual({ ok: false, reason: "mds3" });
    expect(await verifyZkpAnchorDevice({ ...device, passkey: { ...device.passkey, mds3: { ...device.passkey.mds3, attested: false } } }, CHECK)).toEqual({ ok: false, reason: "mds3" });
    expect(await verifyZkpAnchorDevice({ ...device, anchorPublicKey: "zz" }, CHECK)).toEqual({ ok: false, reason: "encoding" });
  });
});
