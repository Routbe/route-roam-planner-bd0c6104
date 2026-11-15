/**
 * Public constants of the guest vault (guest-vault.ts), shared by the worker
 * and the UI-thread WebAuthn helper (guest-passkey.ts). No secrets here.
 */
import { sha256 } from "@noble/hashes/sha2.js";

const enc = new TextEncoder();

/** IndexedDB database of the guest vault; holds only { v, iv, ct } records. */
export const GUEST_VAULT_DB = "vault_guest_storage";
export const GUEST_VAULT_STORE = "records";
/** WebAuthn PRF eval.first salt of the guest vault (own purpose, never shared with ledger/recovery salts). */
export const GUEST_PRF_SALT: Uint8Array = sha256(enc.encode("rout.v1.guest-vault.prf-salt"));
/** Fixed challenge of the local-only fallback assertion (no server relies on it). */
export const GUEST_FALLBACK_CHALLENGE: Uint8Array = sha256(enc.encode("rout.v1.guest-vault.fallback-challenge"));
