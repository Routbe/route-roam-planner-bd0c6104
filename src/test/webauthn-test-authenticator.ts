/**
 * Test-only WebAuthn authenticators (ES256 / EdDSA / RS256) that sign a
 * WebAuthn assertion over a given challenge the way a real authenticator
 * does: authenticatorData = SHA-256(rpId) || flags || counter, signature over
 * authenticatorData || SHA-256(clientDataJSON). Never imported by app code.
 */
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u } from "@/lib/anon-booking/zkp-anchor";

const enc = new TextEncoder();

function cborHead(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  return [(major << 5) | 25, n >> 8, n & 0xff];
}
const cborInt = (v: number) => (v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v));
const cborBytes = (b: Uint8Array) => [...cborHead(2, b.byteLength), ...b];
export function coseMap(entries: [number, number | Uint8Array][]): Uint8Array {
  const out = [...cborHead(5, entries.length)];
  for (const [k, v] of entries) out.push(...cborInt(k), ...(typeof v === "number" ? cborInt(v) : cborBytes(v)));
  return Uint8Array.from(out);
}

export type TestAuthenticator = {
  alg: -7 | -8 | -257;
  cose: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
};

export async function makeAuthenticator(alg: -7 | -8 | -257, opts: { highS?: boolean } = {}): Promise<TestAuthenticator> {
  if (alg === -7) {
    const sk = p256.utils.randomSecretKey();
    const pub = p256.getPublicKey(sk, false);
    return {
      alg,
      cose: coseMap([[1, 2], [3, -7], [-1, 1], [-2, pub.slice(1, 33)], [-3, pub.slice(33, 65)]]),
      async sign(data) {
        const der = p256.sign(data, sk, { format: "der" });
        if (!opts.highS) return der;
        const s = p256.Signature.fromBytes(der, "der");
        const n = p256.Point.CURVE().n;
        return new p256.Signature(s.r, n - s.s).toBytes("der");
      },
    };
  }
  if (alg === -8) {
    const sk = ed25519.utils.randomSecretKey();
    return { alg, cose: coseMap([[1, 1], [3, -8], [-1, 6], [-2, ed25519.getPublicKey(sk)]]), async sign(data) { return ed25519.sign(data, sk); } };
  }
  const kp = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return {
    alg,
    cose: coseMap([[1, 3], [3, -257], [-1, fromB64u(jwk.n!)], [-2, fromB64u(jwk.e!)]]),
    async sign(data) { return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, data as BufferSource)); },
  };
}

export async function assertOver(a: TestAuthenticator, challenge: Uint8Array, o: { rpId?: string; origin?: string; flags?: number; type?: string } = {}) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(enc.encode(o.rpId ?? "rout.be")));
  authenticatorData[32] = o.flags ?? 0x05;
  const clientDataJSON = enc.encode(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: b64u(challenge), origin: o.origin ?? "https://rout.be", crossOrigin: false }));
  const data = new Uint8Array(37 + 32);
  data.set(authenticatorData);
  data.set(sha256(clientDataJSON), 37);
  return { authenticatorData, clientDataJSON, signature: await a.sign(data) };
}
