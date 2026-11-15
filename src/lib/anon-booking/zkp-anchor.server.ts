/**
 * Public anchor document behind /@host/zkp-anchor.json (Stap 7g). Reads
 * vault_enclave.anon_host_anchor_public (db/0274) without a session:
 * only public keys, signatures, the host passkey's assertion and MDS3 flags.
 * Until 0274 is applied the document does not exist (status "unavailable").
 */
import { EPOCH_ORIGIN, EPOCH_SECONDS, utcEpochAt } from "./epoch-clock";
import { b64u, fromHex, ZKP_ANCHOR_TYPE, ZKP_ANCHOR_VERSION, type ZkpAnchorDevice, type ZkpAnchorDocument } from "./zkp-anchor";

export type AnchorQuery = (query: string, params: unknown[]) => Promise<readonly Record<string, unknown>[]>;
export type AnchorReadResult = { status: "ok"; document: ZkpAnchorDocument } | { status: "unavailable" | "not_found" | "no_anchor" };

const HANDLE_RE = /^[a-z0-9._-]{2,40}$/;

/** "@Host" / "host" → "host", or null when it is not a handle. */
export function anchorHandle(raw: string): string | null {
  const h = raw.trim().replace(/^@/, "").toLowerCase();
  return HANDLE_RE.test(h) ? h : null;
}

const b64uOfHex = (h: unknown) => b64u(fromHex(h));

export function documentFromRows(handle: string, rpId: string, devices: Record<string, unknown>[], now = Date.now()): ZkpAnchorDocument {
  return {
    type: ZKP_ANCHOR_TYPE,
    version: ZKP_ANCHOR_VERSION,
    host: `@${handle}`,
    rpId,
    epoch: { seconds: EPOCH_SECONDS, origin: EPOCH_ORIGIN, current: utcEpochAt(now) },
    devices: devices.map((d): ZkpAnchorDevice => {
      const p = d["passkey"] as Record<string, unknown>;
      return {
        deviceId: String(d["deviceId"]),
        keyId: String(d["keyId"]),
        treeId: String(d["treeId"]),
        anchorPublicKey: String(d["anchorPublicKey"]),
        enclaveAnchor: { signerPublicKey: String(d["anchorSignerPublicKey"]), signature: String(d["anchorSignature"]) },
        rootSignerPublicKey: String(d["rootSignerPublicKey"]),
        epoch: Number(d["epoch"]),
        currentPublicKey: String(d["currentPublicKey"]),
        retired: d["retired"] === true,
        registeredAt: String(d["registeredAt"]),
        links: ((d["links"] as Record<string, unknown>[]) ?? []).map((l) => ({
          from: Number(l["from"]), to: Number(l["to"]), publicKey: String(l["publicKey"]), signature: String(l["signature"]),
        })),
        passkey: {
          credentialId: String(p["credentialId"]),
          algorithm: Number(p["algorithm"]),
          publicKey: b64uOfHex(p["publicKey"]),
          authenticatorData: b64uOfHex(p["authenticatorData"]),
          clientDataJSON: b64uOfHex(p["clientDataJSON"]),
          signature: b64uOfHex(p["signature"]),
          mds3: { fmt: String(p["fmt"]), attested: p["attested"] === true, statusSafe: p["statusSafe"] === true, certifiedL3: p["certifiedL3"] === true },
        },
      };
    }),
  };
}

export async function readZkpAnchorDocument(query: AnchorQuery, handle: string, rpId: string, now = Date.now()): Promise<AnchorReadResult> {
  const available = await query("select pg_catalog.to_regprocedure('vault_enclave.anon_host_anchor_public(text)') is not null as ok", []);
  if (available[0]?.["ok"] !== true) return { status: "unavailable" };
  const rows = await query("select vault_enclave.anon_host_anchor_public($1) as a", [handle]);
  const a = rows[0]?.["a"] as { found?: boolean; devices?: Record<string, unknown>[] } | undefined;
  if (!a?.found) return { status: "not_found" };
  if (!Array.isArray(a.devices) || a.devices.length === 0) return { status: "no_anchor" };
  return { status: "ok", document: documentFromRows(handle, rpId, a.devices, now) };
}
