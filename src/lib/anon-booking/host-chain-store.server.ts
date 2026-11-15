/**
 * Server side of host key chains (Stap 7g): one call per vault_enclave entry
 * point of db/0273 (per chain) and db/0274 (per device). The caller is
 * always the signed-in member; the database takes it from the transaction
 * context. Nothing here holds or opens a key: SK_t exists only in the host's
 * crypto worker and reaches the database only as its RVE1 hsk envelope.
 *
 * registerDevice verifies the host passkey's assertion over the anchor
 * statement (zkp-anchor.ts) against the caller's own stored passkey key
 * before the database re-checks ownership, MDS3 verdict, challenge and flags.
 * Device calls need 0274; on a database without it they answer `unavailable`.
 */
import type { VaultSqlExecutor } from "@/lib/vault/vault-port.server";
import type { EpochLink } from "@/lib/crypto-enclave/forward-secure";
import type { PersistAnswer, RatchetStep } from "./epoch-ratchet";
import { verifyAnchorEndorsement, type AnchorStatementInput, type EndorsementCheck } from "./zkp-anchor";

export type AnonAnswer = { op: string; ok: boolean; why: string; epoch: number | null; ver: number | null };
export type HostKeyStateRow = { granted: boolean; epoch: number | null; ver: number | null; sealedState: Uint8Array | null };
export type HostPasskey = { found: false } | { found: true; publicKey: Uint8Array; fmt: string; attested: boolean; statusSafe: boolean; certifiedL3: boolean };
export type DeviceRegistration = AnchorStatementInput & {
  proofId: string | null;
  anchorSignature: Uint8Array;
  sealedState: Uint8Array;
  genesisSignature: Uint8Array;
  credentialId: string;
  algorithm: number;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  passkeySignature: Uint8Array;
};
export type HostDevice = { deviceId: string; createdAt: string; revokedAt: string | null; keyId: string | null; treeId: string | null; epoch: number | null; ver: number | null };

const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");
const bx = (h: unknown) => (typeof h === "string" ? new Uint8Array(Buffer.from(h.replace(/^\\x/, ""), "hex")) : h instanceof Uint8Array ? h : null);

function answer(rows: readonly Record<string, unknown>[]): AnonAnswer {
  const a = rows[0]?.["a"] as AnonAnswer | undefined;
  if (!a || typeof a.ok !== "boolean") throw new Error("anon_no_answer");
  return { ...a, epoch: a.epoch === null ? null : Number(a.epoch), ver: a.ver === null ? null : Number(a.ver) };
}

const unavailable = (op: string): AnonAnswer => ({ op, ok: false, why: "unavailable", epoch: null, ver: null });

export class AnonHostChainStore {
  constructor(private readonly exec: VaultSqlExecutor, private readonly rp: EndorsementCheck) {}

  /** Whether db/0274 is applied (runtime detection; code may deploy first). */
  async devicesAvailable(userId: string): Promise<boolean> {
    const rows = await this.exec(userId, "select pg_catalog.to_regprocedure('vault_enclave.anon_host_devices_mine()') is not null as ok", []);
    return rows[0]?.["ok"] === true;
  }

  async state(userId: string, keyId: string): Promise<HostKeyStateRow> {
    const rows = await this.exec(userId, "select granted, epoch, ver, state_envelope from vault_enclave.anon_host_key_state($1)", [keyId]);
    const r = rows[0] ?? {};
    return {
      granted: r["granted"] === true,
      epoch: r["epoch"] == null ? null : Number(r["epoch"]),
      ver: r["ver"] == null ? null : Number(r["ver"]),
      sealedState: bx(r["state_envelope"]),
    };
  }

  async advance(userId: string, s: { keyId: string; ver: number; from: number; to: number; link: EpochLink; sealedState: Uint8Array }): Promise<AnonAnswer> {
    return answer(await this.exec(userId,
      "select vault_enclave.anon_host_key_advance($1, $2::bigint, $3::bigint, $4::bigint, decode($5, 'hex'), decode($6, 'hex'), decode($7, 'hex')) as a",
      [s.keyId, String(s.ver), String(s.from), String(s.to), hx(s.link.publicKey), hx(s.link.signature), hx(s.sealedState)]));
  }

  /**
   * persist() of a DailyEpochRatchet for one device chain: reads the stored
   * ver, then writes the step with compare-and-swap. Transport errors throw
   * (the ratchet keeps the step and re-sends it).
   */
  persistFor(userId: string, keyId: string): (step: RatchetStep) => Promise<PersistAnswer> {
    return async (step) => {
      const st = await this.state(userId, keyId);
      if (!st.granted || st.ver === null) return "unknown";
      const a = await this.advance(userId, { keyId, ver: st.epoch === step.to ? st.ver - 1 : st.ver, from: step.from, to: step.to, link: step.link, sealedState: step.sealedState });
      return (a.ok ? (a.why === "replay" ? "replay" : "ok") : a.why) as PersistAnswer;
    };
  }

  async passkey(userId: string, credentialId: string): Promise<HostPasskey> {
    if (!(await this.devicesAvailable(userId))) return { found: false };
    const rows = await this.exec(userId, "select vault_enclave.anon_host_passkey($1) as a", [credentialId]);
    const a = rows[0]?.["a"] as Record<string, unknown> | undefined;
    if (!a || a["found"] !== true) return { found: false };
    return {
      found: true,
      publicKey: bx(a["publicKey"]) ?? new Uint8Array(0),
      fmt: String(a["fmt"]),
      attested: a["attested"] === true,
      statusSafe: a["statusSafe"] === true,
      certifiedL3: a["certifiedL3"] === true,
    };
  }

  /** Verifies the passkey assertion, then registers the device chain in one database transaction. */
  async registerDevice(userId: string, r: DeviceRegistration): Promise<AnonAnswer> {
    if (!(await this.devicesAvailable(userId))) return unavailable("device_register");
    const pk = await this.passkey(userId, r.credentialId);
    if (!pk.found) return { op: "device_register", ok: false, why: "passkey", epoch: null, ver: null };
    if (!pk.attested || !pk.statusSafe) return { op: "device_register", ok: false, why: "attestation", epoch: null, ver: null };
    const verdict = await verifyAnchorEndorsement(r, {
      publicKey: pk.publicKey, algorithm: r.algorithm, authenticatorData: r.authenticatorData, clientDataJSON: r.clientDataJSON, signature: r.passkeySignature,
    }, this.rp);
    if (!verdict.ok) return { op: "device_register", ok: false, why: `endorsement_${verdict.reason}`, epoch: null, ver: null };
    return answer(await this.exec(userId,
      `select vault_enclave.anon_host_device_register($1::uuid, $2, $3, decode($4, 'hex'), decode($5, 'hex'), decode($6, 'hex'),
         decode($7, 'hex'), $8, decode($9, 'hex'), decode($10, 'hex'), $11, $12::int, decode($13, 'hex'), decode($14, 'hex'), decode($15, 'hex')) as a`,
      [r.proofId, r.deviceId, r.keyId, hx(r.anchorPublicKey), hx(r.anchorSignerPublicKey), hx(r.anchorSignature), hx(r.sealedState), r.treeId,
        hx(r.rootSignerPublicKey), hx(r.genesisSignature), r.credentialId, r.algorithm, hx(r.authenticatorData), hx(r.clientDataJSON), hx(r.passkeySignature)]));
  }

  async revokeDevice(userId: string, proofId: string | null, deviceId: string): Promise<AnonAnswer> {
    if (!(await this.devicesAvailable(userId))) return unavailable("device_revoke");
    return answer(await this.exec(userId, "select vault_enclave.anon_host_device_revoke($1::uuid, $2) as a", [proofId, deviceId]));
  }

  async devices(userId: string): Promise<HostDevice[] | null> {
    if (!(await this.devicesAvailable(userId))) return null;
    const a = (await this.exec(userId, "select vault_enclave.anon_host_devices_mine() as a", []))[0]?.["a"] as { ok?: boolean; devices?: Record<string, unknown>[] } | undefined;
    if (!a?.ok || !Array.isArray(a.devices)) return null;
    return a.devices.map((d) => ({
      deviceId: String(d["deviceId"]),
      createdAt: String(d["createdAt"]),
      revokedAt: (d["revokedAt"] as string | null) ?? null,
      keyId: (d["keyId"] as string | null) ?? null,
      treeId: (d["treeId"] as string | null) ?? null,
      epoch: d["epoch"] == null ? null : Number(d["epoch"]),
      ver: d["ver"] == null ? null : Number(d["ver"]),
    }));
  }
}
