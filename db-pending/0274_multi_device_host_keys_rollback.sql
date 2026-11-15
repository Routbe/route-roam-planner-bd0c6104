-- Rollback of 0274 (multi-device host keys). Separate GO required.
-- Idempotent: a second run, or a run on a database with 0273 but without
-- 0274, changes nothing. Refuses while any device or endorsement row exists,
-- while a chain belongs to a device, or once the audit log holds a 0274
-- action (audit entries are immutable, so their action values must stay
-- allowed). Restores 0273's anon_purge_host / anon_merge_host byte for byte,
-- its single-chain-per-host index and its audit action check.

do $$
declare
  v_has boolean;
begin
  -- Dynamic SQL: on a database without 0274 these tables do not exist (idempotent rerun).
  if pg_catalog.to_regclass('vault_enclave.anon_host_devices') is not null then
    execute 'select exists (select 1 from vault_enclave.anon_host_devices)' into v_has;
    if v_has then raise exception '0274 rollback: vault_enclave.anon_host_devices is not empty'; end if;
  end if;
  if pg_catalog.to_regclass('vault_enclave.anon_anchor_endorsements') is not null then
    execute 'select exists (select 1 from vault_enclave.anon_anchor_endorsements)' into v_has;
    if v_has then raise exception '0274 rollback: vault_enclave.anon_anchor_endorsements is not empty'; end if;
  end if;
  if exists (select 1 from pg_catalog.pg_attribute a where a.attrelid = pg_catalog.to_regclass('vault_enclave.anon_host_keys')
               and a.attname = 'device_id' and not a.attisdropped) then
    execute 'select exists (select 1 from vault_enclave.anon_host_keys where device_id is not null)' into v_has;
    if v_has then raise exception '0274 rollback: a chain still belongs to a device'; end if;
  end if;
  if exists (select 1 from vault_enclave.audit_logs
              where action in ('anon_device_register', 'anon_device_revoke', 'anon_device_list')) then
    raise exception '0274 rollback: audit log already holds 0274 entries (immutable)';
  end if;
end $$;

drop function if exists vault_enclave.anon_host_anchor_public(text);
drop function if exists vault_enclave.anon_host_devices_mine();
drop function if exists vault_enclave.anon_host_device_revoke(uuid, text);
drop function if exists vault_enclave.anon_host_device_register(uuid, text, text, bytea, bytea, bytea, bytea, text, bytea, bytea, text, integer, bytea, bytea, bytea);
drop function if exists vault_enclave.anon_host_passkey(text);
drop function if exists vault_enclave.anon_b64u(bytea);
drop function if exists vault_enclave.anon_anchor_statement(text, text, text, bytea, bytea, bytea);

-- 0273's lifecycle helpers, verbatim (they never touched devices).
do $rb$
begin
  if pg_catalog.to_regprocedure('vault_enclave.anon_purge_host(uuid)') is not null then
    execute $def$
create or replace function vault_enclave.anon_purge_host(p_user uuid) returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  k record;
  n integer := 0;
begin
  for k in select h.key_id from vault_enclave.anon_host_keys h where h.host_user_id = p_user order by h.key_id for update loop
    perform vault_enclave.anon_retire_chain(k.key_id);
    delete from vault_enclave.anon_host_key_states s where s.key_id = k.key_id;
    update vault_enclave.anon_host_keys set host_user_id = null, purged_at = pg_catalog.clock_timestamp(),
           updated_at = pg_catalog.clock_timestamp() where key_id = k.key_id;
    n := n + 1;
  end loop;
  if n > 0 then
    perform vault_enclave.append_audit(null, 'anon_host_purge', 'granted', 'ok', null);
  end if;
  return n;
end $$;
$def$;
  end if;
  if pg_catalog.to_regprocedure('vault_enclave.anon_merge_host(uuid, uuid)') is not null then
    execute $def$
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
  if n > 0 then
    perform vault_enclave.append_audit(p_primary, 'anon_host_merge', 'granted', 'ok', null);
  end if;
  return n;
end $$;
$def$;
  end if;
end $rb$;

drop table if exists vault_enclave.anon_anchor_endorsements;
-- Dropping the column also drops both per-device live-chain indexes (their predicates use it).
alter table if exists vault_enclave.anon_host_keys drop column if exists device_id;
drop table if exists vault_enclave.anon_host_devices;
do $ix$
begin
  if pg_catalog.to_regclass('vault_enclave.anon_host_keys') is not null
     and pg_catalog.to_regclass('vault_enclave.anon_host_keys_one_active') is null then
    create unique index anon_host_keys_one_active on vault_enclave.anon_host_keys (host_user_id) where retired_at is null;
  end if;
end $ix$;

alter table vault_enclave.audit_logs drop constraint if exists audit_logs_action_check;
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
                    'anon_host_purge', 'anon_host_merge'));
