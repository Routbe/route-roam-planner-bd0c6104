-- 0274 — EXPAND: multi-device hosts for the anonymous booking engine (Stap 7g).
-- Moved into db/ after the owner's explicit GO of 2026-11-15 (CODE_SCHEMA_LEVEL
-- 0274); the rollback stays in db-pending/0274_multi_device_host_keys_rollback.sql.
--
-- Owner decisions (2026-11-15): every device of a host runs its own,
-- independent forward-secure key chain SK_t,dev, registered as an authorised
-- device under the Host Root Identity; PK_0 of each device chain is published
-- on the host's public profile (/@host/zkp-anchor.json), signed by a WebAuthn
-- assertion of the host's passkey whose hardware attestation passed FIDO MDS3
-- (0271: attested and not listed as compromised). The Host Root Identity is
-- that set of MDS3-attested passkeys of the host account.
--
-- What changes:
--   anon_host_devices          one row per authorised device of a host
--   anon_host_keys.device_id   the device a chain belongs to (NULL = a 0273
--                              single chain, still allowed as before)
--   anon_anchor_endorsements   per device chain: the passkey assertion over
--                              the anchor statement, the passkey's COSE key
--                              and MDS3 flags at registration (public material)
--   one live chain per device instead of one per host; a host has either one
--   0273 chain or up to 16 live devices, never both
--   anon_host_device_register  creates device (or reuses an own device without
--                              a live chain), chain, sealed SK_0, nullifier tree,
--                              genesis ledger and endorsement in one transaction
--   anon_host_device_revoke    retires the device's live chain, revokes it
--   anon_host_devices_mine     the caller's devices
--   anon_host_passkey          the caller's own passkey key + MDS3 flags, so
--                              the server can verify the assertion first
--   anon_host_anchor_public    public, read-only document behind zkp-anchor.json
--   anon_purge_host / anon_merge_host  also detach / move devices; the purge
--                              deletes endorsements (they name the passkey)
--
-- Existing per-chain entry points of 0273 (advance, state, booking record,
-- pools, ledger, check, invalidate, chain) work per key id and therefore per
-- device unchanged: each device advances, seals (RVE1 hsk, holder 2) and
-- stores its own SK_t,dev in its own anon_host_key_states row.
--
-- The database cannot verify WebAuthn signatures. It checks what it can: the
-- caller from the transaction context, ownership of the passkey (neon_auth),
-- its MDS3 verdict (vault_enclave.passkey_attestations), the clientDataJSON
-- type and challenge = base64url(SHA-256(anchor statement)), the UP+UV flags,
-- exact sizes, a fresh passkey step-up and an audit row for every call. The
-- signature itself is verified by the server before the call and by every
-- guest from the published document (src/lib/anon-booking/zkp-anchor.ts).
--
-- Every new table: no rights for PUBLIC or rout_app, RLS on with one
-- restrictive deny_all policy; rout_app reaches it only through the SECURITY
-- DEFINER entry points below (search_path = pg_catalog, pg_temp).

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login',
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share',
                    'anon_host_key_init', 'anon_host_key_advance', 'anon_host_key_retire',
                    'anon_host_state_read', 'anon_booking_record', 'anon_booking_check',
                    'anon_pseudonym_invalidate', 'anon_capacity_open', 'anon_ledger_read',
                    'anon_host_purge', 'anon_host_merge',
                    'anon_device_register', 'anon_device_revoke', 'anon_device_list'));

-- ---------------------------------------------------------------- shape helpers

-- "ROUT-ZKP-ANCHOR-V1" || lp(device) || lp(key) || lp(tree) || PK_0 || enclave
-- anchor signer PK || root signer PK; same bytes as zkp-anchor.ts anchorStatement.
create function vault_enclave.anon_anchor_statement(
  p_device text, p_key text, p_tree text, p_anchor_pk bytea, p_signer_pk bytea, p_root_pk bytea)
returns bytea language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.convert_to('ROUT-ZKP-ANCHOR-V1', 'UTF8')
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_device, 'UTF8'))
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_key, 'UTF8'))
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_tree, 'UTF8'))
    || p_anchor_pk || p_signer_pk || p_root_pk
$$;

-- base64url without padding (WebAuthn challenge encoding).
create function vault_enclave.anon_b64u(p bytea) returns text
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.rtrim(pg_catalog.translate(pg_catalog.encode(p, 'base64'), E'+/\n', '-_'), '=')
$$;

-- ---------------------------------------------------------------- tables

create table vault_enclave.anon_host_devices (
  device_id text primary key,
  host_user_id uuid references public.users(id) on delete restrict,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  revoked_at timestamptz,
  purged_at timestamptz,
  constraint anon_host_devices_id check (vault_enclave.anon_id_ok(device_id, 'hd')),
  -- Detached from an account only by the purge, and only once revoked.
  constraint anon_host_devices_owner check ((host_user_id is null) = (purged_at is not null)
                                            and (purged_at is null or revoked_at is not null))
);
create index anon_host_devices_live on vault_enclave.anon_host_devices (host_user_id) where revoked_at is null;

alter table vault_enclave.anon_host_keys
  add column device_id text references vault_enclave.anon_host_devices(device_id) on delete restrict;

-- 0273 allowed one live chain per host. Now: one live 0273 chain per host
-- (device_id null) and one live chain per device.
drop index vault_enclave.anon_host_keys_one_active;
create unique index anon_host_keys_one_active on vault_enclave.anon_host_keys (host_user_id)
  where retired_at is null and device_id is null;
create unique index anon_host_keys_one_active_device on vault_enclave.anon_host_keys (device_id)
  where retired_at is null and device_id is not null;

create table vault_enclave.anon_anchor_endorsements (
  key_id text primary key references vault_enclave.anon_host_keys(key_id) on delete restrict,
  device_id text not null references vault_enclave.anon_host_devices(device_id) on delete restrict,
  credential_id text not null,
  public_key bytea not null,
  algorithm integer not null,
  authenticator_data bytea not null,
  client_data_json bytea not null,
  signature bytea not null,
  fmt text not null,
  attested boolean not null,
  status_safe boolean not null,
  certified_l3 boolean not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_anchor_endorsements_credential check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 16 and 1366),
  constraint anon_anchor_endorsements_alg check (algorithm in (-7, -8, -257)),
  constraint anon_anchor_endorsements_len check (octet_length(public_key) between 32 and 1024
    and octet_length(authenticator_data) between 37 and 1024 and octet_length(client_data_json) between 32 and 4096
    and octet_length(signature) between 64 and 512),
  -- Only a passkey whose attestation passed MDS3 and is not listed as compromised.
  constraint anon_anchor_endorsements_mds3 check (attested and status_safe
    and fmt in ('packed', 'tpm', 'apple', 'android-key'))
);

-- Endorsements never change. Only the account purge (owner-only definer) may
-- delete them, so a purged chain keeps no reference to the host's passkey.
create trigger anon_anchor_endorsements_no_update before update on vault_enclave.anon_anchor_endorsements
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_anchor_endorsements_no_truncate before truncate on vault_enclave.anon_anchor_endorsements
  for each statement execute function vault_enclave.anon_append_only();
-- Devices are revoked or detached, never deleted.
create trigger anon_host_devices_no_delete before delete on vault_enclave.anon_host_devices
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_host_devices_no_truncate before truncate on vault_enclave.anon_host_devices
  for each statement execute function vault_enclave.anon_append_only();

revoke all on table vault_enclave.anon_host_devices from public, rout_app;
revoke all on table vault_enclave.anon_anchor_endorsements from public, rout_app;
alter table vault_enclave.anon_host_devices enable row level security;
alter table vault_enclave.anon_anchor_endorsements enable row level security;
create policy deny_all on vault_enclave.anon_host_devices as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_anchor_endorsements as restrictive for all to public using (false) with check (false);

-- ---------------------------------------------------------------- entry points

-- The caller's own passkey: COSE public key (hex) and the MDS3 flags of 0271,
-- so the server can verify an anchor assertion before registering it.
create function vault_enclave.anon_host_passkey(p_credential_id text) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_auth uuid;
  v_pk bytea;
  a vault_enclave.passkey_attestations%rowtype;
begin
  if v_caller is null or p_credential_id is null or p_credential_id !~ '^[A-Za-z0-9_-]+$' or length(p_credential_id) not between 16 and 1366 then
    return pg_catalog.jsonb_build_object('found', false);
  end if;
  v_auth := vault_enclave.passkey_attestation_identity(v_caller);
  begin
    select pg_catalog.decode(p."publicKey", 'base64') into v_pk from neon_auth.passkey p
     where p."credentialID" = p_credential_id and p."userId" = v_auth::text;
  exception when others then
    v_pk := null;
  end;
  if v_pk is null then return pg_catalog.jsonb_build_object('found', false); end if;
  select * into a from vault_enclave.passkey_attestations x where x.credential_id = p_credential_id and x.auth_user_id = v_auth;
  return pg_catalog.jsonb_build_object('found', true, 'publicKey', pg_catalog.encode(v_pk, 'hex'),
    'fmt', coalesce(a.fmt, 'none'), 'attested', coalesce(a.attested, false),
    'statusSafe', coalesce(a.status_safe, false), 'certifiedL3', coalesce(a.certified_l3, false));
end $$;

-- Registers one device chain of the caller. Order of refusals: no_caller,
-- malformed, legacy_chain (a live 0273 chain), taken (device of someone else,
-- revoked device, used key/tree id), busy (device already has a live chain),
-- device_limit (16 live devices), passkey (not the caller's), attestation (no
-- MDS3 pass), challenge (clientDataJSON not over this anchor), flags (no
-- UP+UV), stepup (no fresh passkey step-up; checked last so it is spent only
-- on an otherwise valid request).
create function vault_enclave.anon_host_device_register(
  p_proof uuid, p_device_id text, p_key_id text, p_anchor_pk bytea, p_anchor_signer_pk bytea, p_anchor_sig bytea,
  p_state bytea, p_tree_id text, p_root_signer_pk bytea, p_genesis_sig bytea,
  p_credential_id text, p_algorithm integer, p_authenticator_data bytea, p_client_data_json bytea, p_passkey_sig bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_auth uuid;
  v_why text := 'ok';
  v_cd jsonb;
  v_pk bytea;
  v_new_device boolean;
  d vault_enclave.anon_host_devices%rowtype;
  a vault_enclave.passkey_attestations%rowtype;
  v_genesis bytea;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_device_register', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('device_register', false, 'no_caller', null, null);
  end if;
  -- Same lock as 0273 anon_host_key_init: a 0273 init and a device registration serialize.
  perform pg_catalog.pg_advisory_xact_lock(273, pg_catalog.hashtext(v_caller::text));
  if not vault_enclave.anon_id_ok(p_device_id, 'hd') or not vault_enclave.anon_id_ok(p_key_id, 'hk')
     or not vault_enclave.anon_id_ok(p_tree_id, 'st')
     or not vault_enclave.anon_len(p_anchor_pk, 96) or not vault_enclave.anon_len(p_anchor_signer_pk, 96)
     or not vault_enclave.anon_len(p_anchor_sig, 80) or not vault_enclave.anon_len(p_root_signer_pk, 96)
     or not vault_enclave.anon_len(p_genesis_sig, 80) or not vault_enclave.anon_is_hsk(p_state)
     or p_credential_id is null or p_credential_id !~ '^[A-Za-z0-9_-]+$' or length(p_credential_id) not between 16 and 1366
     or p_algorithm is null or p_algorithm not in (-7, -8, -257)
     or p_authenticator_data is null or octet_length(p_authenticator_data) not between 37 and 1024
     or p_client_data_json is null or octet_length(p_client_data_json) not between 32 and 4096
     or p_passkey_sig is null or octet_length(p_passkey_sig) not between 64 and 512 then
    v_why := 'malformed';
  end if;
  if v_why = 'ok' then
    begin
      v_cd := pg_catalog.convert_from(p_client_data_json, 'UTF8')::jsonb;
      if pg_catalog.jsonb_typeof(v_cd) <> 'object' then v_why := 'malformed'; end if;
    exception when others then
      v_why := 'malformed';
    end;
  end if;
  if v_why = 'ok' then
    select * into d from vault_enclave.anon_host_devices x where x.device_id = p_device_id for update;
    v_new_device := d.device_id is null;
    if exists (select 1 from vault_enclave.anon_host_keys k
                where k.host_user_id = v_caller and k.retired_at is null and k.device_id is null) then
      v_why := 'legacy_chain';
    elsif not v_new_device and (d.host_user_id is distinct from v_caller or d.revoked_at is not null) then
      v_why := 'taken';
    elsif not v_new_device and exists (select 1 from vault_enclave.anon_host_keys k
                                        where k.device_id = p_device_id and k.retired_at is null) then
      v_why := 'busy';
    elsif v_new_device and (select pg_catalog.count(*) from vault_enclave.anon_host_devices x
                             where x.host_user_id = v_caller and x.revoked_at is null) >= 16 then
      v_why := 'device_limit';
    elsif exists (select 1 from vault_enclave.anon_host_keys k where k.key_id = p_key_id)
       or exists (select 1 from vault_enclave.anon_smt_trees t where t.tree_id = p_tree_id) then
      v_why := 'taken';
    end if;
  end if;
  if v_why = 'ok' then
    v_auth := vault_enclave.passkey_attestation_identity(v_caller);
    begin
      select pg_catalog.decode(p."publicKey", 'base64') into v_pk from neon_auth.passkey p
       where p."credentialID" = p_credential_id and p."userId" = v_auth::text;
    exception when others then
      v_pk := null;
    end;
    select * into a from vault_enclave.passkey_attestations x where x.credential_id = p_credential_id and x.auth_user_id = v_auth;
    if v_pk is null or octet_length(v_pk) not between 32 and 1024 then
      v_why := 'passkey';
    elsif a.credential_id is null or not a.attested or a.status_safe is not true
       or a.fmt not in ('packed', 'tpm', 'apple', 'android-key') then
      v_why := 'attestation';
    elsif v_cd->>'type' is distinct from 'webauthn.get'
       or v_cd->>'challenge' is distinct from vault_enclave.anon_b64u(pg_catalog.sha256(vault_enclave.anon_anchor_statement(
            p_device_id, p_key_id, p_tree_id, p_anchor_pk, p_anchor_signer_pk, p_root_signer_pk))) then
      v_why := 'challenge';
    elsif (pg_catalog.get_byte(p_authenticator_data, 32) & 5) <> 5 then
      v_why := 'flags';
    elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
      v_why := 'stepup';
    end if;
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_device_register', 'denied', v_why, null);
    return vault_enclave.anon_answer('device_register', false, v_why, null, null);
  end if;
  if v_new_device then
    insert into vault_enclave.anon_host_devices (device_id, host_user_id) values (p_device_id, v_caller);
  end if;
  insert into vault_enclave.anon_host_keys (key_id, host_user_id, anchor_pk, anchor_signer_pk, anchor_sig, current_pk, device_id)
  values (p_key_id, v_caller, p_anchor_pk, p_anchor_signer_pk, p_anchor_sig, p_anchor_pk, p_device_id);
  insert into vault_enclave.anon_host_key_states (key_id, state_envelope) values (p_key_id, p_state);
  insert into vault_enclave.anon_smt_trees (tree_id, key_id, root_signer_pk, ledger_head)
  values (p_tree_id, p_key_id, p_root_signer_pk, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
  insert into vault_enclave.anon_smt_roots (tree_id, epoch, root, root_sig)
  values (p_tree_id, 0, '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea, p_genesis_sig);
  v_genesis := vault_enclave.anon_ledger_hash(p_tree_id, 0, 'genesis', 0,
    '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea, null, null, null, null, null, null, null,
    '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);
  insert into vault_enclave.anon_ledger_events (tree_id, seq, kind, root_epoch, smt_root, prev_hash, event_hash)
  values (p_tree_id, 0, 'genesis', 0, '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea,
          '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea, v_genesis);
  update vault_enclave.anon_smt_trees set ledger_head = v_genesis where tree_id = p_tree_id;
  insert into vault_enclave.anon_anchor_endorsements (key_id, device_id, credential_id, public_key, algorithm,
      authenticator_data, client_data_json, signature, fmt, attested, status_safe, certified_l3)
  values (p_key_id, p_device_id, p_credential_id, v_pk, p_algorithm, p_authenticator_data, p_client_data_json,
          p_passkey_sig, a.fmt, a.attested, a.status_safe, a.certified_l3);
  perform vault_enclave.append_audit(v_caller, 'anon_device_register', 'granted', 'ok', null);
  return vault_enclave.anon_answer('device_register', true, 'ok', 0, 0);
end $$;

-- Revokes one of the caller's devices (fresh step-up): its live chain is
-- retired (sealed state deleted, ledger 'retire'); history stays.
create function vault_enclave.anon_host_device_revoke(p_proof uuid, p_device_id text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  d vault_enclave.anon_host_devices%rowtype;
  k record;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_device_revoke', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('device_revoke', false, 'no_caller', null, null);
  end if;
  select * into d from vault_enclave.anon_host_devices x where x.device_id = p_device_id and x.host_user_id = v_caller for update;
  if not found then
    v_why := 'unknown';
  elsif d.revoked_at is not null then
    v_why := 'revoked';
  elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
    v_why := 'stepup';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_device_revoke', 'denied', v_why, null);
    return vault_enclave.anon_answer('device_revoke', false, v_why, null, null);
  end if;
  for k in select h.key_id from vault_enclave.anon_host_keys h
            where h.device_id = d.device_id and h.retired_at is null order by h.key_id loop
    perform vault_enclave.anon_retire_chain(k.key_id);
  end loop;
  update vault_enclave.anon_host_devices set revoked_at = pg_catalog.clock_timestamp() where device_id = d.device_id;
  perform vault_enclave.append_audit(v_caller, 'anon_device_revoke', 'granted', 'ok', null);
  return vault_enclave.anon_answer('device_revoke', true, 'ok', null, null);
end $$;

-- The caller's devices with their live chain (if any).
create function vault_enclave.anon_host_devices_mine() returns jsonb
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_list jsonb;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_device_list', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('devices', false, 'no_caller', null, null);
  end if;
  select coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'deviceId', d.device_id, 'createdAt', d.created_at, 'revokedAt', d.revoked_at,
      'keyId', k.key_id, 'treeId', t.tree_id, 'epoch', k.epoch, 'ver', k.ver) order by d.created_at, d.device_id), '[]'::jsonb)
    into v_list
    from vault_enclave.anon_host_devices d
    left join vault_enclave.anon_host_keys k on k.device_id = d.device_id and k.retired_at is null
    left join vault_enclave.anon_smt_trees t on t.key_id = k.key_id
   where d.host_user_id = v_caller;
  perform vault_enclave.append_audit(v_caller, 'anon_device_list', 'granted', 'ok', null);
  return vault_enclave.anon_answer('devices', true, 'ok', null, null) || pg_catalog.jsonb_build_object('devices', v_list);
end $$;

-- Public, read-only: the anchor document of one public host profile (same
-- visibility rules as the profile page). Only public keys, signatures, the
-- passkey assertions and MDS3 flags; never the member id, a sealed state or
-- a booking. Not audited (public by design).
create function vault_enclave.anon_host_anchor_public(p_handle text) returns jsonb
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  with h as (
    select p.id from public.profiles p
     where p_handle is not null and p_handle ~ '^[a-z0-9._-]{2,40}$' and pg_catalog.lower(p.username) = p_handle
       and coalesce(p.is_banned, false) = false and coalesce(p.is_suspended, false) = false
       and coalesce(pg_catalog.to_jsonb(p)->>'status', 'active') not in ('frozen', 'banned', 'suspended')
       and coalesce(pg_catalog.to_jsonb(p)->'display_prefs'->'publicProfile', 'true'::jsonb)
           not in ('false'::jsonb, 'null'::jsonb, '0'::jsonb, '""'::jsonb)
     limit 1)
  select case when not exists (select 1 from h) then pg_catalog.jsonb_build_object('found', false)
  else pg_catalog.jsonb_build_object('found', true, 'devices', coalesce((
    select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'deviceId', d.device_id, 'keyId', k.key_id, 'treeId', t.tree_id,
        'anchorPublicKey', pg_catalog.encode(k.anchor_pk, 'hex'),
        'anchorSignerPublicKey', pg_catalog.encode(k.anchor_signer_pk, 'hex'),
        'anchorSignature', pg_catalog.encode(k.anchor_sig, 'hex'),
        'rootSignerPublicKey', pg_catalog.encode(t.root_signer_pk, 'hex'),
        'epoch', k.epoch, 'currentPublicKey', pg_catalog.encode(k.current_pk, 'hex'),
        'retired', k.retired_at is not null or d.revoked_at is not null,
        'registeredAt', e.created_at,
        'links', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'from', l.from_epoch, 'to', l.to_epoch,
            'publicKey', pg_catalog.encode(l.next_pk, 'hex'), 'signature', pg_catalog.encode(l.link_sig, 'hex'))
            order by l.from_epoch) from vault_enclave.anon_epoch_links l where l.key_id = k.key_id), '[]'::jsonb),
        'passkey', pg_catalog.jsonb_build_object(
            'credentialId', e.credential_id, 'algorithm', e.algorithm,
            'publicKey', pg_catalog.encode(e.public_key, 'hex'),
            'authenticatorData', pg_catalog.encode(e.authenticator_data, 'hex'),
            'clientDataJSON', pg_catalog.encode(e.client_data_json, 'hex'),
            'signature', pg_catalog.encode(e.signature, 'hex'),
            'fmt', e.fmt, 'attested', e.attested, 'statusSafe', e.status_safe, 'certifiedL3', e.certified_l3))
        order by d.created_at, d.device_id, k.created_at)
      from h join vault_enclave.anon_host_devices d on d.host_user_id = h.id
      join vault_enclave.anon_host_keys k on k.device_id = d.device_id
      join vault_enclave.anon_smt_trees t on t.key_id = k.key_id
      join vault_enclave.anon_anchor_endorsements e on e.key_id = k.key_id), '[]'::jsonb)) end
$$;

-- ---------------------------------------------------------------- account lifecycle

-- 0273 purge, now also: endorsements of the host's chains are deleted (they
-- name the host's passkey) and every device is revoked and detached.
create or replace function vault_enclave.anon_purge_host(p_user uuid) returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  k record;
  n integer := 0;
begin
  for k in select h.key_id from vault_enclave.anon_host_keys h where h.host_user_id = p_user order by h.key_id for update loop
    perform vault_enclave.anon_retire_chain(k.key_id);
    delete from vault_enclave.anon_host_key_states s where s.key_id = k.key_id;
    delete from vault_enclave.anon_anchor_endorsements e where e.key_id = k.key_id;
    update vault_enclave.anon_host_keys set host_user_id = null, purged_at = pg_catalog.clock_timestamp(),
           updated_at = pg_catalog.clock_timestamp() where key_id = k.key_id;
    n := n + 1;
  end loop;
  update vault_enclave.anon_host_devices set revoked_at = coalesce(revoked_at, pg_catalog.clock_timestamp()),
         host_user_id = null, purged_at = pg_catalog.clock_timestamp() where host_user_id = p_user;
  if n > 0 then
    perform vault_enclave.append_audit(null, 'anon_host_purge', 'granted', 'ok', null);
  end if;
  return n;
end $$;

-- 0273 merge, now also: the secondary's devices are revoked and move to the
-- primary (their chains are retired by the loop), so they never count
-- against the primary's live-device limit.
create or replace function vault_enclave.anon_merge_host(p_primary uuid, p_secondary uuid) returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  k record;
  n integer := 0;
begin
  for k in select h.key_id from vault_enclave.anon_host_keys h where h.host_user_id = p_secondary order by h.key_id for update loop
    perform vault_enclave.anon_retire_chain(k.key_id);
    update vault_enclave.anon_host_keys set host_user_id = p_primary, updated_at = pg_catalog.clock_timestamp()
     where key_id = k.key_id;
    n := n + 1;
  end loop;
  update vault_enclave.anon_host_devices set revoked_at = coalesce(revoked_at, pg_catalog.clock_timestamp()),
         host_user_id = p_primary where host_user_id = p_secondary;
  if n > 0 then
    perform vault_enclave.append_audit(p_primary, 'anon_host_merge', 'granted', 'ok', null);
  end if;
  return n;
end $$;

-- ---------------------------------------------------------------- rights

revoke all on function vault_enclave.anon_anchor_statement(text, text, text, bytea, bytea, bytea) from public, rout_app;
revoke all on function vault_enclave.anon_b64u(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_purge_host(uuid) from public, rout_app;
revoke all on function vault_enclave.anon_merge_host(uuid, uuid) from public, rout_app;
revoke all on function vault_enclave.anon_host_passkey(text) from public;
revoke all on function vault_enclave.anon_host_device_register(uuid, text, text, bytea, bytea, bytea, bytea, text, bytea, bytea, text, integer, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.anon_host_device_revoke(uuid, text) from public;
revoke all on function vault_enclave.anon_host_devices_mine() from public;
revoke all on function vault_enclave.anon_host_anchor_public(text) from public;
grant execute on function vault_enclave.anon_host_passkey(text) to rout_app;
grant execute on function vault_enclave.anon_host_device_register(uuid, text, text, bytea, bytea, bytea, bytea, text, bytea, bytea, text, integer, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_host_device_revoke(uuid, text) to rout_app;
grant execute on function vault_enclave.anon_host_devices_mine() to rout_app;
grant execute on function vault_enclave.anon_host_anchor_public(text) to rout_app;

-- In-transaction proof: the new tables are unreachable for rout_app and PUBLIC
-- with exactly one restrictive deny_all policy, every anon_* function is
-- pinned and closed to PUBLIC, internal helpers are closed to rout_app, no
-- foreign key of an anonymous table cascades, and the live-chain indexes are
-- per device.
do $$
declare v_bad text;
begin
  select string_agg(t, ', ') into v_bad from unnest(array['vault_enclave.anon_host_devices',
    'vault_enclave.anon_anchor_endorsements', 'vault_enclave.anon_host_keys']) t
   where pg_catalog.has_table_privilege('rout_app', t, 'select') or pg_catalog.has_table_privilege('rout_app', t, 'insert')
      or pg_catalog.has_table_privilege('rout_app', t, 'update') or pg_catalog.has_table_privilege('rout_app', t, 'delete')
      or pg_catalog.has_table_privilege('public', t, 'select') or pg_catalog.has_table_privilege('public', t, 'insert')
      or not (select c.relrowsecurity from pg_catalog.pg_class c where c.oid = t::regclass)
      or (select pg_catalog.count(*) from pg_catalog.pg_policy p where p.polrelid = t::regclass) <> 1
      or not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = t::regclass and p.polname = 'deny_all'
                       and not p.polpermissive and p.polcmd = '*'
                       and pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'false'
                       and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) = 'false');
  if v_bad is not null then raise exception '0274: reachable or wrongly guarded table %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname like 'anon\_%'
     and (not ('search_path=pg_catalog, pg_temp' = any (coalesce(p.proconfig, '{}')))
          or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0274: unpinned or public function %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname = any (array['anon_anchor_statement', 'anon_b64u',
     'anon_purge_host', 'anon_merge_host', 'anon_retire_chain', 'anon_ledger_append', 'anon_stepup', 'anon_caller'])
     and pg_catalog.has_function_privilege('rout_app', p.oid, 'execute');
  if v_bad is not null then raise exception '0274: rout_app can execute internal helper %', v_bad; end if;
  select string_agg(c.conname, ', ') into v_bad from pg_catalog.pg_constraint c
    join pg_catalog.pg_class r on r.oid = c.conrelid join pg_catalog.pg_namespace n on n.oid = r.relnamespace
   where n.nspname = 'vault_enclave' and r.relname like 'anon\_%' and c.contype = 'f' and c.confdeltype <> 'r';
  if v_bad is not null then raise exception '0274: cascading or non-restrict foreign key %', v_bad; end if;
  if pg_catalog.strpos(pg_catalog.pg_get_indexdef('vault_enclave.anon_host_keys_one_active'::regclass), 'device_id IS NULL') = 0
     or pg_catalog.to_regclass('vault_enclave.anon_host_keys_one_active_device') is null then
    raise exception '0274: live-chain indexes are not per device';
  end if;
end $$;
