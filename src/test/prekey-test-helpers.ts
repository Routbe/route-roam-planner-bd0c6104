/**
 * Test helpers for Stap 8 prekey documents: a responder's worker creates the
 * bundle, a software WebAuthn authenticator signs its challenge, and the
 * document is built exactly as the server publishes it. The enclave runner is
 * injected by each test (only the worker may import the enclave core).
 */
type Runner = (op: never, args: never) => Promise<{ ok: true; result: unknown } | { ok: false; code: string }>;
let run: Runner | null = null;
export function useEnclave(r: unknown) {
  run = r as Runner;
}
const runner = (): Runner => {
  if (!run) throw new Error("call useEnclave(runEnclaveOp) first");
  return run;
};
import { buildPrekeyDocument, type PrekeyDocument } from "@/lib/crypto-enclave/prekey-bundle";
import { assertOver, makeAuthenticator, type TestAuthenticator } from "./webauthn-test-authenticator";

export const RP = { rpId: "rout.be", origins: ["https://rout.be"] };
export const MDS3_OK = { fmt: "packed", attested: true, statusSafe: true, certifiedL3: false };

export async function enclaveOp<T>(name: string, args: Record<string, unknown>): Promise<T> {
  const r = await runner()(name as never, args as never);
  if (!r.ok) throw new Error(r.code);
  return r.result as T;
}

export async function enclaveCode(name: string, args: Record<string, unknown>): Promise<string> {
  const r = await runner()(name as never, args as never);
  return r.ok ? "ok" : r.code;
}

export type SignedPrekey = { sessionId: string; prekeyId: string; bundle: Uint8Array; challenge: Uint8Array; document: PrekeyDocument; auth: TestAuthenticator };

export async function signedPrekey(owner: string, handle: string, opts: { auth?: TestAuthenticator; mds3?: typeof MDS3_OK; publishedAt?: string } = {}): Promise<SignedPrekey> {
  const created = await enclaveOp<{ sessionId: string; prekeyId: string; bundle: Uint8Array; challenge: Uint8Array }>(
    "pq_ratchet.create_prekey_bundle", { userId: owner, rpId: RP.rpId, handle });
  const auth = opts.auth ?? (await makeAuthenticator(-7));
  const a = await assertOver(auth, created.challenge);
  const document = buildPrekeyDocument({
    handle,
    rpId: RP.rpId,
    bundle: created.bundle,
    assertion: { credentialId: "c".repeat(22), algorithm: -7, ...a },
    passkeyPublicKey: auth.cose,
    mds3: opts.mds3 ?? MDS3_OK,
    publishedAt: opts.publishedAt ?? new Date().toISOString(),
  });
  return { ...created, document, auth };
}
