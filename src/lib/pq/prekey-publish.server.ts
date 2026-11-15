/**
 * Stap 8: publication of a member's PQ prekey document without SQL. The
 * signed document lives in Scaleway Object Storage (client bucket) under
 * `users/<uid>/prekey-bundle.json`; Neon is only read, through the existing
 * vault_enclave.anon_host_passkey entry point (db/0274) for the caller's own
 * passkey key and MDS3 verdict.
 *
 * The server builds the document from the stored passkey key (never a key
 * sent by the client) and runs the same verifyPrekeyDocument the worker runs
 * before a handshake: handle, RP id, bundle encoding, age ≤ 30 UTC days,
 * MDS3 attested + status safe, clientDataJSON / RP id hash / UP+UV /
 * signature. Anything else is refused and nothing is stored.
 */
import { buildPrekeyDocument, prekeyHandle, verifyPrekeyDocument, type PrekeyDocument, type PrekeyRejection } from "@/lib/crypto-enclave/prekey-bundle";
import { fromB64u } from "@/lib/anon-booking/zkp-anchor";
import type { HostPasskey } from "@/lib/anon-booking/host-chain-store.server";

export const prekeyObjectKey = (userId: string) => `users/${userId}/prekey-bundle.json`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type PrekeyPublishInput = {
  bundle: string;
  credentialId: string;
  algorithm: number;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
};

export type PrekeyPublishDeps = {
  rpId: string;
  origins: readonly string[];
  handleOf: (userId: string) => Promise<string | null>;
  passkey: (userId: string, credentialId: string) => Promise<HostPasskey>;
  put: (key: string, body: Uint8Array) => Promise<void>;
  now?: () => number;
};

export type PrekeyPublishResult =
  | { ok: true; prekeyId: string; handle: string }
  | { ok: false; reason: "no_handle" | "passkey" | "attestation" | "input" | PrekeyRejection["reason"] };

export async function publishPrekey(deps: PrekeyPublishDeps, userId: string, input: PrekeyPublishInput): Promise<PrekeyPublishResult> {
  if (!UUID.test(userId)) return { ok: false, reason: "input" };
  const handle = prekeyHandle(await deps.handleOf(userId));
  if (!handle) return { ok: false, reason: "no_handle" };
  const pk = await deps.passkey(userId, input.credentialId);
  if (!pk.found) return { ok: false, reason: "passkey" };
  if (!pk.attested || !pk.statusSafe) return { ok: false, reason: "attestation" };
  const now = deps.now?.() ?? Date.now();
  let doc: PrekeyDocument;
  try {
    doc = buildPrekeyDocument({
      handle,
      rpId: deps.rpId,
      bundle: fromB64u(input.bundle),
      assertion: {
        credentialId: input.credentialId,
        algorithm: input.algorithm,
        authenticatorData: fromB64u(input.authenticatorData),
        clientDataJSON: fromB64u(input.clientDataJSON),
        signature: fromB64u(input.signature),
      },
      passkeyPublicKey: pk.publicKey,
      mds3: { fmt: pk.fmt, attested: pk.attested, statusSafe: pk.statusSafe, certifiedL3: pk.certifiedL3 },
      publishedAt: new Date(now).toISOString(),
    });
  } catch {
    return { ok: false, reason: "input" };
  }
  const v = await verifyPrekeyDocument(doc, { rpId: deps.rpId, origins: deps.origins, handle, now });
  if (!v.ok) return { ok: false, reason: v.reason };
  await deps.put(prekeyObjectKey(userId), new TextEncoder().encode(JSON.stringify(doc)));
  return { ok: true, prekeyId: doc.prekeyId, handle };
}

export type PrekeyReadDeps = {
  userIdOf: (handle: string) => Promise<string | null>;
  get: (key: string) => Promise<Uint8Array | null>;
};

/** Public read: the stored document exactly as published, or null. */
export async function readPrekeyDocument(deps: PrekeyReadDeps, rawHandle: string): Promise<{ status: "ok"; body: Uint8Array } | { status: "not_found" | "invalid_handle" }> {
  const handle = prekeyHandle(rawHandle);
  if (!handle) return { status: "invalid_handle" };
  const uid = await deps.userIdOf(handle);
  if (!uid || !UUID.test(uid)) return { status: "not_found" };
  const body = await deps.get(prekeyObjectKey(uid));
  return body ? { status: "ok", body } : { status: "not_found" };
}

// ---- Production wiring ---------------------------------------------------------

export async function prekeyRp(): Promise<{ rpId: string; origins: string[] }> {
  const { canonicalAppUrl } = await import("@/lib/app-url");
  const u = new URL(canonicalAppUrl());
  return { rpId: u.hostname, origins: [u.origin] };
}

export async function productionPublishDeps(): Promise<PrekeyPublishDeps> {
  const rp = await prekeyRp();
  const { AnonHostChainStore } = await import("@/lib/anon-booking/host-chain-store.server");
  const { runQuery, withDbContext } = await import("@/lib/neon");
  const store = new AnonHostChainStore(
    async (userId, query, params) => (await withDbContext({ userId, workspaceId: null }, () => runQuery(query, [...params]))).rows,
    rp,
  );
  const { readMyHandle } = await import("@/lib/claim.server");
  const { putObject } = await import("@/lib/storage/s3.server");
  return {
    ...rp,
    handleOf: async (uid) => (await readMyHandle(uid)).handle,
    passkey: (uid, cred) => store.passkey(uid, cred),
    put: (key, body) => putObject("client", key, body, { contentType: "application/json", cacheControl: "no-store" }),
  };
}

export async function productionReadDeps(): Promise<PrekeyReadDeps> {
  const { dbAdmin } = await import("@/lib/db/admin.server");
  const { getObject } = await import("@/lib/storage/s3.server");
  return {
    userIdOf: async (handle) => {
      const { data } = await dbAdmin.from("profiles").select("id").eq("username", handle).maybeSingle();
      return (data?.id as string | undefined) ?? null;
    },
    get: async (key) => {
      const r = await getObject("client", key);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`prekey_storage_${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    },
  };
}
