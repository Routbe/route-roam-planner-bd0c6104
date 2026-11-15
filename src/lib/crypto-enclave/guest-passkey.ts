/**
 * UI-thread WebAuthn for the guest vault (Stap 7g). WebAuthn is unavailable
 * in workers, so the passkey output is produced here and transferred straight
 * into the crypto worker ("guest_vault.unlock"), which derives the guest's
 * master seed and wipes the bytes. Nothing is sent to a server and nothing is
 * stored outside the worker's encrypted IndexedDB records.
 *
 * PRF first (extension "prf", eval.first = GUEST_PRF_SALT). Without PRF the
 * fallback asks for a second assertion over the same fixed challenge; the
 * worker accepts the signature as key material only when both are identical
 * (deterministic signer, unchanged counter) and otherwise refuses with
 * `no_stable_secret`.
 */
import { GUEST_FALLBACK_CHALLENGE, GUEST_PRF_SALT } from "./guest-vault-constants";

export type GuestPasskeyMaterial = { credentialId: string; prf?: Uint8Array; signatures?: Uint8Array[] };

const b64u = (bytes: Uint8Array) => btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

export class GuestPasskeyCancelled extends Error {
  constructor() {
    super("guest_passkey_cancelled");
  }
}

type PrfResults = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

async function assertion(credentialId?: string): Promise<PublicKeyCredential> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: GUEST_FALLBACK_CHALLENGE.slice(),
      userVerification: "required",
      timeout: 60_000,
      ...(credentialId ? { allowCredentials: [{ type: "public-key" as const, id: fromB64u(credentialId) }] } : {}),
      extensions: { prf: { eval: { first: GUEST_PRF_SALT.slice() } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new GuestPasskeyCancelled();
  return credential;
}

/** The passkey output for guest_vault.unlock; hand it to enclave.guestVault.unlock right away (it is transferred). */
export async function guestPasskeyMaterial(credentialId?: string): Promise<GuestPasskeyMaterial> {
  const first = await assertion(credentialId);
  const id = b64u(new Uint8Array(first.rawId));
  const prf = (first.getClientExtensionResults() as PrfResults).prf?.results?.first;
  if (prf) return { credentialId: id, prf: new Uint8Array(prf) };
  const sig1 = new Uint8Array((first.response as AuthenticatorAssertionResponse).signature);
  const second = await assertion(id);
  const sig2 = new Uint8Array((second.response as AuthenticatorAssertionResponse).signature);
  return { credentialId: id, signatures: [sig1, sig2] };
}

/**
 * A new discoverable passkey that only opens this device's guest vault: a
 * random user handle, no account, no name of the guest. Returns its id and
 * whether the authenticator reported PRF support at creation.
 */
export async function createGuestPasskey(rpName = "ROUT"): Promise<{ credentialId: string; prfEnabled: boolean }> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: rpName },
      user: { id: crypto.getRandomValues(new Uint8Array(32)), name: "ROUT gast", displayName: "ROUT gast" },
      pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      timeout: 60_000,
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new GuestPasskeyCancelled();
  const ext = credential.getClientExtensionResults() as PrfResults;
  return { credentialId: b64u(new Uint8Array(credential.rawId)), prfEnabled: ext.prf?.enabled === true };
}
