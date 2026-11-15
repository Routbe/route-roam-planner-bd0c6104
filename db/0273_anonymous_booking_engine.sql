-- 0273 — EXPAND: anonymous booking engine (Stap 7e/7f), the SQL side of the
-- wasm/rout-zk engine from steps 7a-7d. Moved from db-pending/ into db/ with
-- CODE_SCHEMA_LEVEL 0273 after the owner's GO (2026-11-15); the rollback stays
-- in db-pending/0273_anonymous_booking_engine_rollback.sql.
--
-- What is stored (all of it public material or ciphertext; no guest identity):
--   anon_host_keys               one forward-secure chain per host: anchor PK_0
--                                (bound to the host row and signed by the
--                                enclave), current epoch and PK_t
--   anon_host_key_states         the current ratchet state SK_t, only as an
--                                RVE1 envelope (kind 9 hsk, holder 2 member
--                                device: sealed in the host's crypto worker to
--                                the host's own device key, owner decision 7f,
--                                superseding the server-vault holder of 7e);
--                                replaced in place on every advance, never
--                                kept twice; neither the database, the server
--                                vault nor ROUT_VAULT_KEK can open it
--   anon_epoch_links             PK_t -> PK_t' links signed by the old epoch key
--   anon_smt_trees / _roots      the nullifier tree of a chain and its signed
--                                root per tree epoch (one row per insertion)
--   anon_booking_tokens          a spent nullifier, the host-scoped pseudonym,
--                                the credential epoch and the BBS presentation
--   anon_pseudonym_invalidations pseudonyms a host has invalidated
--   anon_capacity_pools          a seat pool: Pedersen commitment to the
--                                capacity (with range proof) and the current
--                                remainder commitment; counts stay hidden
--   anon_ledger_events           one hash chain per tree over every mutation
--                                (genesis, pool_open, booking, invalidate,
--                                retire): root epoch and SMT root, pool step
--                                with take/remainder commitments and the
--                                1856-byte capacity proof, nullifier and
--                                pseudonym; kept apart from 0265's ledger
--
-- Account lifecycle (Stap 7f). No anon_* row is ever deleted by a cascade:
-- every foreign key is ON DELETE RESTRICT, so a purge or merge that forgot a
-- table fails instead of silently dropping spent nullifiers (which would let a
-- guest re-spend) or history. public.rout_anon_booking_purge (only inside the
-- due purge transaction) retires the host's live chain, deletes every sealed
-- state and detaches the chains from the account (host_user_id null,
-- purged_at set); chains, links, roots, tokens, pools and ledger stay, holding
-- no identity. public.rout_anon_booking_merge (only from
-- execute_account_merge) retires the secondary's live chain, deletes its
-- sealed state and moves its unchanged historic chains to the primary; the
-- primary keeps its own live chain.
--
-- The database cannot run pairings: it does NOT verify BBS signatures or
-- proofs. It enforces what it can prove itself: the caller from the
-- transaction context (vault_enclave.caller_user_id, never a parameter),
-- ownership, exact byte sizes, one linear history per chain and per tree
-- (compare-and-swap on ver / head epoch under FOR UPDATE), nullifier and
-- pseudonym uniqueness, credential epochs that have a published key, append-only
-- history rows, a fresh passkey step-up for creating or retiring a chain, and an
-- audit row for every call. Signature and proof checks happen in the crypto
-- worker (forward-secure.ts, smt.ts) before and after these calls.
--
-- Every new table: no rights for PUBLIC or rout_app, RLS on with one
-- restrictive deny_all policy. rout_app reaches the data only through the
-- SECURITY DEFINER entry points below (search_path = pg_catalog, pg_temp).
-- Denials return ok = false instead of raising, so their audit row commits.

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
                    'anon_host_purge', 'anon_host_merge'));

-- ---------------------------------------------------------------- shape helpers

-- RVE1 envelope of the ratchet state: magic, suite 1, kind 9 (hsk), holder 2
-- (member device); 1663 bytes of envelope overhead + 40 bytes of plaintext
-- (SK_t 32 || I2OSP(epoch, 8), forward-secure.ts HSK_PLAINTEXT_BYTES).
create function vault_enclave.anon_is_hsk(p_env bytea) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_env is not null and octet_length(p_env) = 1703
     and substring(p_env from 1 for 4) = '\x52564531'::bytea
     and pg_catalog.get_byte(p_env, 4) = 1 and pg_catalog.get_byte(p_env, 5) = 9 and pg_catalog.get_byte(p_env, 6) = 2
$$;

-- Anonymous presentation (wasm/rout-zk anon.rs): I2OSP(bbs_len, 8) || BBS
-- proof (272 + 32 per undisclosed message, at most 49) || one committed
-- disclosure (48 + 32) || two 928-byte range proofs. The length prefix must
-- match the encoding exactly.
create function vault_enclave.anon_is_proof(p bytea) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p is not null and octet_length(p) between 8 + 272 + 80 + 1856 and 8 + 1840 + 80 + 1856
     and (octet_length(p) - 8 - 80 - 1856 - 272) % 32 = 0
     and ('x' || pg_catalog.encode(substring(p from 1 for 8), 'hex'))::bit(64)::bigint = octet_length(p) - 8 - 80 - 1856
$$;

create function vault_enclave.anon_len(p bytea, n integer) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p is not null and octet_length(p) = n
$$;

-- Opaque random ids: hk_ (host chain), st_ (nullifier tree) and cp_ (capacity
-- pool), 256 bits hex.
create function vault_enclave.anon_id_ok(p_id text, p_prefix text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_id is not null and p_id ~ ('^' || p_prefix || '_[0-9a-f]{64}$')
$$;

create function vault_enclave.anon_answer(p_op text, p_ok boolean, p_why text, p_epoch bigint, p_ver bigint)
returns jsonb language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.jsonb_build_object('op', p_op, 'ok', p_ok, 'why', p_why, 'epoch', p_epoch, 'ver', p_ver)
$$;

-- ---------------------------------------------------------------- tables

create table vault_enclave.anon_host_keys (
  key_id text primary key,
  host_user_id uuid references public.users(id) on delete restrict,
  anchor_pk bytea not null,
  anchor_signer_pk bytea not null,
  anchor_sig bytea not null,
  epoch bigint not null default 0,
  current_pk bytea not null,
  ver bigint not null default 0,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  purged_at timestamptz,
  -- Detached from an account only by the purge, and only once retired.
  constraint anon_host_keys_owner check ((host_user_id is null) = (purged_at is not null)
                                         and (purged_at is null or retired_at is not null)),
  constraint anon_host_keys_id check (vault_enclave.anon_id_ok(key_id, 'hk')),
  constraint anon_host_keys_len check (octet_length(anchor_pk) = 96 and octet_length(anchor_signer_pk) = 96
                                       and octet_length(anchor_sig) = 80 and octet_length(current_pk) = 96),
  constraint anon_host_keys_epoch check (epoch between 0 and 9007199254740991 and ver >= 0
                                         and (epoch <> 0 or current_pk = anchor_pk))
);
-- One live chain per host.
create unique index anon_host_keys_one_active on vault_enclave.anon_host_keys (host_user_id) where retired_at is null;

create table vault_enclave.anon_host_key_states (
  key_id text primary key references vault_enclave.anon_host_keys(key_id) on delete restrict,
  state_envelope bytea not null,
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_host_key_states_env check (vault_enclave.anon_is_hsk(state_envelope))
);

create table vault_enclave.anon_epoch_links (
  key_id text not null references vault_enclave.anon_host_keys(key_id) on delete restrict,
  from_epoch bigint not null,
  to_epoch bigint not null,
  next_pk bytea not null,
  link_sig bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (key_id, to_epoch),
  constraint anon_epoch_links_from unique (key_id, from_epoch),
  -- forward_secure.rs MAX_ADVANCE = 65536; epochs stay exact in JavaScript.
  constraint anon_epoch_links_step check (from_epoch >= 0 and to_epoch > from_epoch
                                          and to_epoch - from_epoch <= 65536 and to_epoch <= 9007199254740991),
  constraint anon_epoch_links_len check (octet_length(next_pk) = 96 and octet_length(link_sig) = 80)
);

create table vault_enclave.anon_smt_trees (
  tree_id text primary key,
  key_id text not null unique references vault_enclave.anon_host_keys(key_id) on delete restrict,
  root_signer_pk bytea not null,
  head_epoch bigint not null default 0,
  ledger_seq bigint not null default 0,
  ledger_head bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_smt_trees_id check (vault_enclave.anon_id_ok(tree_id, 'st')),
  constraint anon_smt_trees_len check (octet_length(root_signer_pk) = 96 and octet_length(ledger_head) = 32 and ledger_seq >= 0),
  constraint anon_smt_trees_head check (head_epoch >= 0)
);

create table vault_enclave.anon_smt_roots (
  tree_id text not null references vault_enclave.anon_smt_trees(tree_id) on delete restrict,
  epoch bigint not null,
  root bytea not null,
  root_sig bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (tree_id, epoch),
  constraint anon_smt_roots_len check (octet_length(root) = 32 and octet_length(root_sig) = 80),
  -- Genesis is the empty 256-level Poseidon tree (smt.ts SMT_EMPTY_ROOT_HEX).
  constraint anon_smt_roots_genesis check (epoch >= 0 and (epoch <> 0
    or root = '\x46cb7f6a1a639693f80c2afddb77288ff88ff08ad19943a595c4c92633ec9505'::bytea))
);

create table vault_enclave.anon_booking_tokens (
  token_id uuid primary key default pg_catalog.gen_random_uuid(),
  tree_id text not null,
  root_epoch bigint not null,
  nullifier bytea not null,
  pseudonym bytea not null,
  credential_epoch bigint not null,
  presentation bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_booking_tokens_root foreign key (tree_id, root_epoch)
    references vault_enclave.anon_smt_roots(tree_id, epoch) on delete restrict,
  -- A nullifier is spent once per tree; each insertion is exactly one root step.
  constraint anon_booking_tokens_nullifier unique (tree_id, nullifier),
  constraint anon_booking_tokens_pseudonym unique (tree_id, pseudonym),
  constraint anon_booking_tokens_step unique (tree_id, root_epoch),
  constraint anon_booking_tokens_shape check (root_epoch >= 1 and octet_length(nullifier) = 32
    and octet_length(pseudonym) = 32 and credential_epoch >= 0 and vault_enclave.anon_is_proof(presentation))
);

create table vault_enclave.anon_pseudonym_invalidations (
  tree_id text not null,
  pseudonym bytea not null,
  reason text not null,
  invalidated_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (tree_id, pseudonym),
  constraint anon_pseudonym_invalidations_token foreign key (tree_id, pseudonym)
    references vault_enclave.anon_booking_tokens(tree_id, pseudonym) on delete restrict,
  constraint anon_pseudonym_invalidations_reason check (reason in ('cancelled', 'no_show', 'abuse', 'guest_request'))
);

-- A seat pool of one tree. The capacity and every count stay hidden in
-- Pedersen commitments; the database keeps the remainder commitment and the
-- step counter for compare-and-swap, the worker checks the proofs.
create table vault_enclave.anon_capacity_pools (
  pool_id text primary key,
  tree_id text not null references vault_enclave.anon_smt_trees(tree_id) on delete restrict,
  opened_commitment bytea not null,
  opened_proof bytea not null,
  remaining_commitment bytea not null,
  step bigint not null default 0,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint anon_capacity_pools_id check (vault_enclave.anon_id_ok(pool_id, 'cp')),
  -- anon.rs MAX_TAKES = 65536.
  constraint anon_capacity_pools_shape check (octet_length(opened_commitment) = 48 and octet_length(opened_proof) = 928
    and octet_length(remaining_commitment) = 48 and step between 0 and 65536)
);

-- One hash chain per tree over every mutation (anon_ledger_hash).
create table vault_enclave.anon_ledger_events (
  tree_id text not null references vault_enclave.anon_smt_trees(tree_id) on delete restrict,
  seq bigint not null,
  kind text not null,
  root_epoch bigint not null,
  smt_root bytea not null,
  pool_id text references vault_enclave.anon_capacity_pools(pool_id) on delete restrict,
  pool_step bigint,
  take_commitment bytea,
  remaining_commitment bytea,
  proof bytea,
  nullifier bytea,
  pseudonym bytea,
  prev_hash bytea not null,
  event_hash bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (tree_id, seq),
  constraint anon_ledger_events_hash unique (event_hash),
  constraint anon_ledger_events_kind check (kind in ('genesis', 'pool_open', 'booking', 'invalidate', 'retire')),
  constraint anon_ledger_events_len check (seq >= 0 and root_epoch >= 0 and octet_length(smt_root) = 32
    and octet_length(prev_hash) = 32 and octet_length(event_hash) = 32
    and (take_commitment is null or octet_length(take_commitment) = 48)
    and (remaining_commitment is null or octet_length(remaining_commitment) = 48)
    and (nullifier is null or octet_length(nullifier) = 32) and (pseudonym is null or octet_length(pseudonym) = 32)),
  constraint anon_ledger_events_shape check ((kind = 'genesis') = (seq = 0) and case kind
    when 'genesis' then seq = 0 and prev_hash = '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
      and pool_id is null and nullifier is null and pseudonym is null and proof is null
    when 'pool_open' then pool_id is not null and pool_step = 0 and take_commitment is null
      and remaining_commitment is not null and octet_length(proof) = 928 and nullifier is null and pseudonym is null
    when 'booking' then nullifier is not null and pseudonym is not null and ((pool_id is null and pool_step is null
      and take_commitment is null and remaining_commitment is null and proof is null)
      or (pool_id is not null and pool_step >= 1 and take_commitment is not null and remaining_commitment is not null
      and octet_length(proof) = 1856))
    when 'invalidate' then pseudonym is not null and pool_id is null and nullifier is null and proof is null
    else pool_id is null and nullifier is null and pseudonym is null and proof is null end)
);

-- History rows are append-only: no UPDATE, no DELETE, no TRUNCATE (there are
-- no cascades either, so nothing can remove them on the way).
create function vault_enclave.anon_append_only() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  raise exception 'anon_append_only' using errcode = '42501';
end $$;

create trigger anon_epoch_links_append_only before update or delete on vault_enclave.anon_epoch_links
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_epoch_links_no_truncate before truncate on vault_enclave.anon_epoch_links
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_smt_roots_append_only before update or delete on vault_enclave.anon_smt_roots
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_smt_roots_no_truncate before truncate on vault_enclave.anon_smt_roots
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_booking_tokens_append_only before update or delete on vault_enclave.anon_booking_tokens
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_booking_tokens_no_truncate before truncate on vault_enclave.anon_booking_tokens
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_pseudonym_invalidations_append_only before update or delete on vault_enclave.anon_pseudonym_invalidations
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_pseudonym_invalidations_no_truncate before truncate on vault_enclave.anon_pseudonym_invalidations
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_ledger_events_append_only before update or delete on vault_enclave.anon_ledger_events
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_ledger_events_no_truncate before truncate on vault_enclave.anon_ledger_events
  for each statement execute function vault_enclave.anon_append_only();
-- Pools move forward (remainder, step) but never disappear.
create trigger anon_capacity_pools_no_delete before delete on vault_enclave.anon_capacity_pools
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_capacity_pools_no_truncate before truncate on vault_enclave.anon_capacity_pools
  for each statement execute function vault_enclave.anon_append_only();
-- Chains are never deleted (the purge detaches them instead).
create trigger anon_host_keys_no_delete before delete on vault_enclave.anon_host_keys
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_host_keys_no_truncate before truncate on vault_enclave.anon_host_keys
  for each statement execute function vault_enclave.anon_append_only();
create trigger anon_smt_trees_no_delete before delete on vault_enclave.anon_smt_trees
  for each row execute function vault_enclave.anon_append_only();
create trigger anon_smt_trees_no_truncate before truncate on vault_enclave.anon_smt_trees
  for each statement execute function vault_enclave.anon_append_only();

-- No rights for anyone but the owner, on every table of the schema.
revoke all on all tables in schema vault_enclave from public, rout_app;
alter table vault_enclave.anon_host_keys enable row level security;
alter table vault_enclave.anon_host_key_states enable row level security;
alter table vault_enclave.anon_epoch_links enable row level security;
alter table vault_enclave.anon_smt_trees enable row level security;
alter table vault_enclave.anon_smt_roots enable row level security;
alter table vault_enclave.anon_booking_tokens enable row level security;
alter table vault_enclave.anon_pseudonym_invalidations enable row level security;
alter table vault_enclave.anon_capacity_pools enable row level security;
alter table vault_enclave.anon_ledger_events enable row level security;
create policy deny_all on vault_enclave.anon_host_keys as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_host_key_states as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_epoch_links as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_smt_trees as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_smt_roots as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_booking_tokens as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_pseudonym_invalidations as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_capacity_pools as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.anon_ledger_events as restrictive for all to public using (false) with check (false);

-- ---------------------------------------------------------------- internal helpers

-- The signed-in member from the transaction context, only if the member exists.
create function vault_enclave.anon_caller() returns uuid
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select u.id from public.users u where u.id = vault_enclave.caller_user_id()
$$;

-- Spends the caller's own passkey proof if it is unused and at most 300 s old
-- on the database clock; one statement, so a proof is spent at most once.
create function vault_enclave.anon_stepup(p_caller uuid, p_proof uuid) returns boolean
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if p_proof is null then return false; end if;
  update vault_enclave.step_up_proofs s set consumed_at = pg_catalog.clock_timestamp()
   where s.proof_id = p_proof and s.user_id = p_caller and s.method = 'passkey' and s.consumed_at is null
     and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
     and s.verified_at <= pg_catalog.clock_timestamp() + interval '5 seconds';
  return found;
end $$;

-- Length-prefixed field of the ledger encoding; NULL is 0xffffffff.
create function vault_enclave.anon_lp(p bytea) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case when p is null then '\xffffffff'::bytea else pg_catalog.int4send(pg_catalog.octet_length(p)) || p end
$$;

-- event_hash = SHA-256("rout.anon.ledger.v1" || lp(tree) || I2OSP(seq, 8) ||
-- lp(kind) || I2OSP(root_epoch, 8) || smt_root || lp(pool) || I2OSP(pool_step
-- or -1, 8) || lp(take) || lp(remaining) || lp(proof) || lp(nullifier) ||
-- lp(pseudonym) || prev_hash). Same rule as src/lib/crypto-enclave/anon-ledger.ts.
create function vault_enclave.anon_ledger_hash(
  p_tree text, p_seq bigint, p_kind text, p_root_epoch bigint, p_root bytea, p_pool text, p_pool_step bigint,
  p_take bytea, p_rem bytea, p_proof bytea, p_nf bytea, p_ps bytea, p_prev bytea)
returns bytea language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(pg_catalog.convert_to('rout.anon.ledger.v1', 'UTF8')
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_tree, 'UTF8')) || pg_catalog.int8send(p_seq)
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_kind, 'UTF8')) || pg_catalog.int8send(p_root_epoch) || p_root
    || vault_enclave.anon_lp(pg_catalog.convert_to(p_pool, 'UTF8')) || pg_catalog.int8send(coalesce(p_pool_step, -1))
    || vault_enclave.anon_lp(p_take) || vault_enclave.anon_lp(p_rem) || vault_enclave.anon_lp(p_proof)
    || vault_enclave.anon_lp(p_nf) || vault_enclave.anon_lp(p_ps) || p_prev)
$$;

-- Appends one event at ledger_seq + 1 over the tree's current signed root.
-- Callers hold the tree row (FOR UPDATE) in the same transaction.
create function vault_enclave.anon_ledger_append(
  p_tree text, p_kind text, p_pool text, p_pool_step bigint, p_take bytea, p_rem bytea, p_proof bytea, p_nf bytea, p_ps bytea)
returns bytea language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  t vault_enclave.anon_smt_trees%rowtype;
  v_root bytea;
  v_hash bytea;
begin
  select * into strict t from vault_enclave.anon_smt_trees tr where tr.tree_id = p_tree for update;
  select r.root into strict v_root from vault_enclave.anon_smt_roots r where r.tree_id = p_tree and r.epoch = t.head_epoch;
  v_hash := vault_enclave.anon_ledger_hash(p_tree, t.ledger_seq + 1, p_kind, t.head_epoch, v_root, p_pool, p_pool_step,
                                           p_take, p_rem, p_proof, p_nf, p_ps, t.ledger_head);
  insert into vault_enclave.anon_ledger_events (tree_id, seq, kind, root_epoch, smt_root, pool_id, pool_step,
      take_commitment, remaining_commitment, proof, nullifier, pseudonym, prev_hash, event_hash)
  values (p_tree, t.ledger_seq + 1, p_kind, t.head_epoch, v_root, p_pool, p_pool_step, p_take, p_rem, p_proof, p_nf, p_ps,
          t.ledger_head, v_hash);
  update vault_enclave.anon_smt_trees set ledger_seq = ledger_seq + 1, ledger_head = v_hash where tree_id = p_tree;
  return v_hash;
end $$;

-- Ends one live chain: deletes its sealed state, sets retired_at, and records
-- 'retire' on its tree's ledger. No-op on a chain that is already retired.
create function vault_enclave.anon_retire_chain(p_key_id text) returns boolean
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare v_tree text;
begin
  perform 1 from vault_enclave.anon_host_keys k where k.key_id = p_key_id and k.retired_at is null for update;
  if not found then return false; end if;
  delete from vault_enclave.anon_host_key_states s where s.key_id = p_key_id;
  update vault_enclave.anon_host_keys set retired_at = pg_catalog.clock_timestamp(), ver = ver + 1,
         updated_at = pg_catalog.clock_timestamp() where key_id = p_key_id;
  select t.tree_id into v_tree from vault_enclave.anon_smt_trees t where t.key_id = p_key_id;
  if v_tree is not null then
    perform vault_enclave.anon_ledger_append(v_tree, 'retire', null, null, null, null, null, null, null);
  end if;
  return true;
end $$;

-- ---------------------------------------------------------------- entry points

-- Creates the caller's chain: anchor PK_0 (epoch 0), the sealed SK_0 state,
-- the nullifier tree and its signed genesis root, in one transaction.
create function vault_enclave.anon_host_key_init(
  p_proof uuid, p_key_id text, p_anchor_pk bytea, p_anchor_signer_pk bytea, p_anchor_sig bytea,
  p_state bytea, p_tree_id text, p_root_signer_pk bytea, p_genesis_sig bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_why text := 'ok';
  v_genesis bytea;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_init', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('init', false, 'no_caller', null, null);
  end if;
  -- One init per host at a time (released at commit).
  perform pg_catalog.pg_advisory_xact_lock(273, pg_catalog.hashtext(v_caller::text));
  if not vault_enclave.anon_id_ok(p_key_id, 'hk') or not vault_enclave.anon_id_ok(p_tree_id, 'st')
     or not vault_enclave.anon_len(p_anchor_pk, 96) or not vault_enclave.anon_len(p_anchor_signer_pk, 96)
     or not vault_enclave.anon_len(p_anchor_sig, 80) or not vault_enclave.anon_len(p_root_signer_pk, 96)
     or not vault_enclave.anon_len(p_genesis_sig, 80) or not vault_enclave.anon_is_hsk(p_state) then
    v_why := 'malformed';
  elsif exists (select 1 from vault_enclave.anon_host_keys k where k.host_user_id = v_caller and k.retired_at is null) then
    v_why := 'busy';
  elsif exists (select 1 from vault_enclave.anon_host_keys k where k.key_id = p_key_id)
     or exists (select 1 from vault_enclave.anon_smt_trees t where t.tree_id = p_tree_id) then
    v_why := 'taken';
  elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
    v_why := 'stepup';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_init', 'denied', v_why, null);
    return vault_enclave.anon_answer('init', false, v_why, null, null);
  end if;
  insert into vault_enclave.anon_host_keys (key_id, host_user_id, anchor_pk, anchor_signer_pk, anchor_sig, current_pk)
  values (p_key_id, v_caller, p_anchor_pk, p_anchor_signer_pk, p_anchor_sig, p_anchor_pk);
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
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_init', 'granted', 'ok', null);
  return vault_enclave.anon_answer('init', true, 'ok', 0, 0);
end $$;

-- Epoch transition t -> t': CAS on ver and epoch, one signed link, the new
-- PK_t' and the new sealed state replace the old ones in the same row.
create function vault_enclave.anon_host_key_advance(
  p_key_id text, p_ver bigint, p_from bigint, p_to bigint, p_next_pk bytea, p_link_sig bytea, p_state bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  k vault_enclave.anon_host_keys%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_advance', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('advance', false, 'no_caller', null, null);
  end if;
  select * into k from vault_enclave.anon_host_keys h where h.key_id = p_key_id and h.host_user_id = v_caller for update;
  if not found then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif p_ver = k.ver - 1 and p_to = k.epoch and exists (select 1 from vault_enclave.anon_epoch_links l
          where l.key_id = k.key_id and l.from_epoch = p_from and l.to_epoch = p_to
            and l.next_pk = p_next_pk and l.link_sig = p_link_sig) then
    -- The same transition again (a retried request): its stored answer.
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'granted', 'replay', null);
    return vault_enclave.anon_answer('advance', true, 'replay', k.epoch, k.ver);
  elsif p_from is null or p_to is null or p_from < 0 or p_to <= p_from or p_to - p_from > 65536
     or p_to > 9007199254740991 or not vault_enclave.anon_len(p_next_pk, 96)
     or not vault_enclave.anon_len(p_link_sig, 80) or not vault_enclave.anon_is_hsk(p_state)
     or p_next_pk = k.current_pk then
    v_why := 'malformed';
  elsif p_ver is distinct from k.ver or p_from is distinct from k.epoch then
    v_why := 'conflict';
  elsif (select pg_catalog.count(*) from vault_enclave.anon_epoch_links l where l.key_id = k.key_id) >= 1024 then
    -- forward-secure.ts MAX_CHAIN_LINKS: a longer chain no guest could verify.
    v_why := 'chain_full';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'denied', v_why, null);
    return vault_enclave.anon_answer('advance', false, v_why, k.epoch, k.ver);
  end if;
  insert into vault_enclave.anon_epoch_links (key_id, from_epoch, to_epoch, next_pk, link_sig)
  values (k.key_id, p_from, p_to, p_next_pk, p_link_sig);
  update vault_enclave.anon_host_keys set epoch = p_to, current_pk = p_next_pk, ver = ver + 1,
         updated_at = pg_catalog.clock_timestamp() where key_id = k.key_id returning * into k;
  update vault_enclave.anon_host_key_states set state_envelope = p_state, updated_at = pg_catalog.clock_timestamp()
   where key_id = k.key_id;
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_advance', 'granted', 'ok', null);
  return vault_enclave.anon_answer('advance', true, 'ok', k.epoch, k.ver);
end $$;

-- The caller's own sealed SK_t (never another member's, never a retired chain's).
create function vault_enclave.anon_host_key_state(p_key_id text)
returns table (granted boolean, epoch bigint, ver bigint, state_envelope bytea)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  r record;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_state_read', 'denied', 'no_caller', null);
    return query select false, null::bigint, null::bigint, null::bytea; return;
  end if;
  select k.epoch as e, k.ver as v, s.state_envelope as env into r
    from vault_enclave.anon_host_keys k join vault_enclave.anon_host_key_states s on s.key_id = k.key_id
   where k.key_id = p_key_id and k.host_user_id = v_caller and k.retired_at is null;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_host_state_read', 'denied', 'unknown', null);
    return query select false, null::bigint, null::bigint, null::bytea; return;
  end if;
  perform vault_enclave.append_audit(v_caller, 'anon_host_state_read', 'granted', 'ok', null);
  return query select true, r.e, r.v, r.env;
end $$;

-- Ends the caller's chain (fresh step-up): the sealed state is deleted; the
-- public chain, tree, tokens and ledger stay for verification of earlier
-- bookings, and the ledger records the retirement.
create function vault_enclave.anon_host_key_retire(p_proof uuid, p_key_id text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  k vault_enclave.anon_host_keys%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_host_key_retire', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('retire', false, 'no_caller', null, null);
  end if;
  select * into k from vault_enclave.anon_host_keys h where h.key_id = p_key_id and h.host_user_id = v_caller for update;
  if not found then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif not vault_enclave.anon_stepup(v_caller, p_proof) then
    v_why := 'stepup';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_host_key_retire', 'denied', v_why, null);
    return vault_enclave.anon_answer('retire', false, v_why, k.epoch, k.ver);
  end if;
  perform vault_enclave.anon_retire_chain(k.key_id);
  select * into k from vault_enclave.anon_host_keys h where h.key_id = p_key_id;
  perform vault_enclave.append_audit(v_caller, 'anon_host_key_retire', 'granted', 'ok', null);
  return vault_enclave.anon_answer('retire', true, 'ok', k.epoch, k.ver);
end $$;

-- Records one anonymous booking on the caller's tree: the nullifier, the
-- per-booking pseudonym and the presentation, the new signed root at head + 1
-- and, for a pooled slot, the pool step (take and remainder commitments and
-- the 1856-byte capacity proof, anon.rs) — plus one ledger event, all in one
-- transaction. Order of refusals: unknown, retired, malformed, (replay),
-- spent, pseudonym_taken, epoch (credential epoch without a published key or
-- in the future), pool (unknown pool of this tree), conflict (stale head),
-- pool_conflict (stale pool step).
create function vault_enclave.anon_booking_record(
  p_tree_id text, p_head bigint, p_root bytea, p_root_sig bytea, p_nullifier bytea, p_pseudonym bytea,
  p_credential_epoch bigint, p_presentation bytea,
  p_pool_id text, p_pool_step bigint, p_take_commitment bytea, p_remaining_commitment bytea, p_capacity_proof bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  t vault_enclave.anon_smt_trees%rowtype;
  k vault_enclave.anon_host_keys%rowtype;
  cp vault_enclave.anon_capacity_pools%rowtype;
  v_pooled boolean := p_pool_id is not null;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_booking_record', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('record', false, 'no_caller', null, null);
  end if;
  select tr.* into t from vault_enclave.anon_smt_trees tr join vault_enclave.anon_host_keys h on h.key_id = tr.key_id
   where tr.tree_id = p_tree_id and h.host_user_id = v_caller for update of tr;
  if found then
    select * into k from vault_enclave.anon_host_keys h where h.key_id = t.key_id;
    if v_pooled then
      select * into cp from vault_enclave.anon_capacity_pools c where c.pool_id = p_pool_id and c.tree_id = t.tree_id for update;
    end if;
  end if;
  if t.tree_id is null then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif p_head is null or p_head < 0 or not vault_enclave.anon_len(p_root, 32) or not vault_enclave.anon_len(p_root_sig, 80)
     or not vault_enclave.anon_len(p_nullifier, 32) or not vault_enclave.anon_len(p_pseudonym, 32)
     or p_credential_epoch is null or p_credential_epoch < 0 or not vault_enclave.anon_is_proof(p_presentation)
     or (v_pooled and (not vault_enclave.anon_id_ok(p_pool_id, 'cp') or p_pool_step is null or p_pool_step < 1
          or p_pool_step > 65536 or not vault_enclave.anon_len(p_take_commitment, 48)
          or not vault_enclave.anon_len(p_remaining_commitment, 48) or not vault_enclave.anon_len(p_capacity_proof, 1856)))
     or (not v_pooled and (p_pool_step is not null or p_take_commitment is not null or p_remaining_commitment is not null
          or p_capacity_proof is not null)) then
    v_why := 'malformed';
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b join vault_enclave.anon_smt_roots r
                  on r.tree_id = b.tree_id and r.epoch = b.root_epoch
                 where b.tree_id = t.tree_id and b.nullifier = p_nullifier and b.root_epoch = p_head + 1
                   and b.pseudonym = p_pseudonym and b.credential_epoch = p_credential_epoch
                   and b.presentation = p_presentation and r.root = p_root and r.root_sig = p_root_sig) then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'granted', 'replay', null);
    return vault_enclave.anon_answer('record', true, 'replay', p_head + 1, null);
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = t.tree_id and b.nullifier = p_nullifier) then
    v_why := 'spent';
  elsif exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = t.tree_id and b.pseudonym = p_pseudonym) then
    v_why := 'pseudonym_taken';
  elsif p_credential_epoch > k.epoch or (p_credential_epoch <> 0 and not exists (
          select 1 from vault_enclave.anon_epoch_links l where l.key_id = k.key_id and l.to_epoch = p_credential_epoch)) then
    v_why := 'epoch';
  elsif v_pooled and cp.pool_id is null then
    v_why := 'pool';
  elsif p_head <> t.head_epoch then
    v_why := 'conflict';
  elsif v_pooled and p_pool_step <> cp.step + 1 then
    v_why := 'pool_conflict';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'denied', v_why, null);
    return vault_enclave.anon_answer('record', false, v_why, t.head_epoch, case when v_pooled then cp.step end);
  end if;
  insert into vault_enclave.anon_smt_roots (tree_id, epoch, root, root_sig) values (t.tree_id, p_head + 1, p_root, p_root_sig);
  insert into vault_enclave.anon_booking_tokens (tree_id, root_epoch, nullifier, pseudonym, credential_epoch, presentation)
  values (t.tree_id, p_head + 1, p_nullifier, p_pseudonym, p_credential_epoch, p_presentation);
  update vault_enclave.anon_smt_trees set head_epoch = p_head + 1 where tree_id = t.tree_id;
  if v_pooled then
    update vault_enclave.anon_capacity_pools set remaining_commitment = p_remaining_commitment, step = p_pool_step,
           updated_at = pg_catalog.clock_timestamp() where pool_id = cp.pool_id;
  end if;
  perform vault_enclave.anon_ledger_append(t.tree_id, 'booking', p_pool_id, p_pool_step, p_take_commitment,
                                           p_remaining_commitment, p_capacity_proof, p_nullifier, p_pseudonym);
  perform vault_enclave.append_audit(v_caller, 'anon_booking_record', 'granted', 'ok', null);
  return vault_enclave.anon_answer('record', true, 'ok', p_head + 1, case when v_pooled then p_pool_step end);
end $$;

-- Opens a seat pool on the caller's live tree: the capacity commitment and its
-- 928-byte range proof (checked by the worker, anon.rs capacity_open), which
-- is also the first remainder. Idempotent for the identical request.
create function vault_enclave.anon_capacity_open(p_tree_id text, p_pool_id text, p_commitment bytea, p_proof bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  t vault_enclave.anon_smt_trees%rowtype;
  k vault_enclave.anon_host_keys%rowtype;
  cp vault_enclave.anon_capacity_pools%rowtype;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_capacity_open', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('pool_open', false, 'no_caller', null, null);
  end if;
  select tr.* into t from vault_enclave.anon_smt_trees tr join vault_enclave.anon_host_keys h on h.key_id = tr.key_id
   where tr.tree_id = p_tree_id and h.host_user_id = v_caller for update of tr;
  if found then
    select * into k from vault_enclave.anon_host_keys h where h.key_id = t.key_id;
  end if;
  select * into cp from vault_enclave.anon_capacity_pools c where c.pool_id = p_pool_id;
  if t.tree_id is null then
    v_why := 'unknown';
  elsif k.retired_at is not null then
    v_why := 'retired';
  elsif not vault_enclave.anon_id_ok(p_pool_id, 'cp') or not vault_enclave.anon_len(p_commitment, 48)
     or not vault_enclave.anon_len(p_proof, 928) then
    v_why := 'malformed';
  elsif cp.pool_id is not null and cp.tree_id = t.tree_id and cp.opened_commitment = p_commitment and cp.opened_proof = p_proof then
    perform vault_enclave.append_audit(v_caller, 'anon_capacity_open', 'granted', 'replay', null);
    return vault_enclave.anon_answer('pool_open', true, 'replay', t.head_epoch, cp.step);
  elsif cp.pool_id is not null then
    v_why := 'taken';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_capacity_open', 'denied', v_why, null);
    return vault_enclave.anon_answer('pool_open', false, v_why, t.head_epoch, null);
  end if;
  insert into vault_enclave.anon_capacity_pools (pool_id, tree_id, opened_commitment, opened_proof, remaining_commitment)
  values (p_pool_id, t.tree_id, p_commitment, p_proof, p_commitment);
  perform vault_enclave.anon_ledger_append(t.tree_id, 'pool_open', p_pool_id, 0, null, p_commitment, p_proof, null, null);
  perform vault_enclave.append_audit(v_caller, 'anon_capacity_open', 'granted', 'ok', null);
  return vault_enclave.anon_answer('pool_open', true, 'ok', t.head_epoch, 0);
end $$;

-- The caller's own ledger (also of a retired chain), after seq p_after, at most
-- p_limit (1..500) events, hex encoded, with the current head. Never another
-- member's tree; a purged chain has no owner and is readable by nobody.
create function vault_enclave.anon_ledger(p_tree_id text, p_after bigint, p_limit integer)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  t vault_enclave.anon_smt_trees%rowtype;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_ledger_read', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('ledger', false, 'no_caller', null, null);
  end if;
  select tr.* into t from vault_enclave.anon_smt_trees tr join vault_enclave.anon_host_keys h on h.key_id = tr.key_id
   where tr.tree_id = p_tree_id and h.host_user_id = v_caller;
  if not found or p_after is null or p_after < -1 or p_limit is null or p_limit < 1 or p_limit > 500 then
    perform vault_enclave.append_audit(v_caller, 'anon_ledger_read', 'denied', case when t.tree_id is null then 'unknown' else 'malformed' end, null);
    return vault_enclave.anon_answer('ledger', false, case when t.tree_id is null then 'unknown' else 'malformed' end, null, null);
  end if;
  perform vault_enclave.append_audit(v_caller, 'anon_ledger_read', 'granted', 'ok', null);
  return vault_enclave.anon_answer('ledger', true, 'ok', t.head_epoch, null) || pg_catalog.jsonb_build_object(
    'treeId', t.tree_id, 'headSeq', t.ledger_seq, 'headHash', pg_catalog.encode(t.ledger_head, 'hex'),
    'events', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'seq', e.seq, 'kind', e.kind, 'rootEpoch', e.root_epoch, 'smtRoot', pg_catalog.encode(e.smt_root, 'hex'),
        'poolId', e.pool_id, 'poolStep', e.pool_step,
        'takeCommitment', pg_catalog.encode(e.take_commitment, 'hex'),
        'remainingCommitment', pg_catalog.encode(e.remaining_commitment, 'hex'),
        'proof', pg_catalog.encode(e.proof, 'hex'), 'nullifier', pg_catalog.encode(e.nullifier, 'hex'),
        'pseudonym', pg_catalog.encode(e.pseudonym, 'hex'),
        'prevHash', pg_catalog.encode(e.prev_hash, 'hex'), 'eventHash', pg_catalog.encode(e.event_hash, 'hex')) order by e.seq)
      from (select * from vault_enclave.anon_ledger_events x where x.tree_id = t.tree_id and x.seq > p_after
            order by x.seq limit p_limit) e), '[]'::jsonb));
end $$;

-- Whether a nullifier is spent on the caller's tree, and whether its
-- pseudonym was invalidated; also returns the head epoch.
create function vault_enclave.anon_booking_check(p_tree_id text, p_nullifier bytea)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_head bigint;
  v_spent boolean;
  v_invalid boolean;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_booking_check', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('check', false, 'no_caller', null, null);
  end if;
  select tr.head_epoch into v_head from vault_enclave.anon_smt_trees tr
    join vault_enclave.anon_host_keys h on h.key_id = tr.key_id where tr.tree_id = p_tree_id and h.host_user_id = v_caller;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'denied', 'unknown', null);
    return vault_enclave.anon_answer('check', false, 'unknown', null, null);
  end if;
  if not vault_enclave.anon_len(p_nullifier, 32) then
    perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'denied', 'malformed', null);
    return vault_enclave.anon_answer('check', false, 'malformed', v_head, null);
  end if;
  select true, exists (select 1 from vault_enclave.anon_pseudonym_invalidations i
                        where i.tree_id = b.tree_id and i.pseudonym = b.pseudonym)
    into v_spent, v_invalid
    from vault_enclave.anon_booking_tokens b where b.tree_id = p_tree_id and b.nullifier = p_nullifier;
  perform vault_enclave.append_audit(v_caller, 'anon_booking_check', 'granted', 'ok', null);
  return vault_enclave.anon_answer('check', true, 'ok', v_head, null)
    || pg_catalog.jsonb_build_object('spent', coalesce(v_spent, false), 'invalidated', coalesce(v_invalid, false));
end $$;

-- Invalidates a pseudonym recorded on the caller's tree (idempotent).
create function vault_enclave.anon_pseudonym_invalidate(p_tree_id text, p_pseudonym bytea, p_reason text)
returns jsonb language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.anon_caller();
  v_tree text;
  v_why text := 'ok';
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'anon_pseudonym_invalidate', 'denied', 'no_caller', null);
    return vault_enclave.anon_answer('invalidate', false, 'no_caller', null, null);
  end if;
  select tr.tree_id into v_tree from vault_enclave.anon_smt_trees tr
    join vault_enclave.anon_host_keys h on h.key_id = tr.key_id where tr.tree_id = p_tree_id and h.host_user_id = v_caller
    for update of tr;
  if v_tree is null then
    v_why := 'unknown';
  elsif not vault_enclave.anon_len(p_pseudonym, 32) or p_reason is null
     or p_reason not in ('cancelled', 'no_show', 'abuse', 'guest_request') then
    v_why := 'malformed';
  elsif not exists (select 1 from vault_enclave.anon_booking_tokens b where b.tree_id = v_tree and b.pseudonym = p_pseudonym) then
    v_why := 'unknown';
  end if;
  if v_why <> 'ok' then
    perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'denied', v_why, null);
    return vault_enclave.anon_answer('invalidate', false, v_why, null, null);
  end if;
  insert into vault_enclave.anon_pseudonym_invalidations (tree_id, pseudonym, reason)
  values (v_tree, p_pseudonym, p_reason) on conflict (tree_id, pseudonym) do nothing;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'granted', 'already', null);
    return vault_enclave.anon_answer('invalidate', true, 'already', null, null);
  end if;
  perform vault_enclave.anon_ledger_append(v_tree, 'invalidate', null, null, null, null, null, null, p_pseudonym);
  perform vault_enclave.append_audit(v_caller, 'anon_pseudonym_invalidate', 'granted', 'ok', null);
  return vault_enclave.anon_answer('invalidate', true, 'ok', null, null);
end $$;

-- Public, read-only: the anchor and every signed link of one chain, so an
-- anonymous guest can verify an epoch key without signing in. Only public
-- keys and signatures (hex); never the host id, the state or any token.
-- Not audited: it reads nothing private and would flood the audit chain.
create function vault_enclave.anon_host_chain(p_key_id text) returns jsonb
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select case when k.key_id is null then pg_catalog.jsonb_build_object('found', false)
  else pg_catalog.jsonb_build_object(
    'found', true, 'keyId', k.key_id, 'epoch', k.epoch, 'retired', k.retired_at is not null,
    'anchorPublicKey', pg_catalog.encode(k.anchor_pk, 'hex'),
    'anchorSignerPublicKey', pg_catalog.encode(k.anchor_signer_pk, 'hex'),
    'anchorSignature', pg_catalog.encode(k.anchor_sig, 'hex'),
    'currentPublicKey', pg_catalog.encode(k.current_pk, 'hex'),
    'links', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'from', l.from_epoch, 'to', l.to_epoch,
        'publicKey', pg_catalog.encode(l.next_pk, 'hex'), 'signature', pg_catalog.encode(l.link_sig, 'hex'))
        order by l.from_epoch)
      from vault_enclave.anon_epoch_links l where l.key_id = k.key_id), '[]'::jsonb)) end
  from (select 1) d left join vault_enclave.anon_host_keys k on k.key_id = p_key_id
$$;

-- ---------------------------------------------------------------- account lifecycle

-- Purge of a host account (after the 30-day cooling-off period): retires the
-- live chain (ledger 'retire'), deletes every sealed state and detaches every
-- chain from the account. Spent nullifiers, roots, links, pools and ledger
-- stay: without them a guest could spend a credential again. The audit row
-- carries no member id. Returns the number of chains detached.
create function vault_enclave.anon_purge_host(p_user uuid) returns integer
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

-- Merge of a secondary account into a primary: the secondary's live chain is
-- retired (its sealed state deleted) and all its chains, unchanged, move to
-- the primary, which keeps its own live chain. Two ratchet chains cannot be
-- joined (every link is signed by the previous key), so history stays as it
-- was signed.
create function vault_enclave.anon_merge_host(p_primary uuid, p_secondary uuid) returns integer
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

-- Called by the account purge (src/lib/account-purge.ts) as rout_app inside
-- the purge transaction; refuses (and so rolls the whole purge back) unless
-- this account's deletion is due and being purged right now.
create function public.rout_anon_booking_purge(p_user uuid) returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if not public.rout_purge_due(p_user) then
    raise exception 'anon_purge_not_due' using errcode = '42501';
  end if;
  return vault_enclave.anon_purge_host(p_user);
end $$;

-- Called only by execute_account_merge (owner rout_merge_executor), whose
-- secondary is the signed-in member of the transaction.
create function public.rout_anon_booking_merge(p_primary uuid, p_secondary uuid) returns integer
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
begin
  if p_primary is null or p_secondary is null or p_primary = p_secondary
     or vault_enclave.caller_user_id() is distinct from p_secondary
     or not exists (select 1 from public.users u where u.id = p_primary) then
    raise exception 'anon_merge_invalid' using errcode = '42501';
  end if;
  return vault_enclave.anon_merge_host(p_primary, p_secondary);
end $$;

-- ---------------------------------------------------------------- rights

revoke all on function vault_enclave.anon_is_hsk(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_is_proof(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_len(bytea, integer) from public, rout_app;
revoke all on function vault_enclave.anon_id_ok(text, text) from public, rout_app;
revoke all on function vault_enclave.anon_answer(text, boolean, text, bigint, bigint) from public, rout_app;
revoke all on function vault_enclave.anon_append_only() from public, rout_app;
revoke all on function vault_enclave.anon_caller() from public, rout_app;
revoke all on function vault_enclave.anon_stepup(uuid, uuid) from public, rout_app;
revoke all on function vault_enclave.anon_lp(bytea) from public, rout_app;
revoke all on function vault_enclave.anon_ledger_hash(text, bigint, text, bigint, bytea, text, bigint, bytea, bytea, bytea, bytea, bytea, bytea) from public, rout_app;
revoke all on function vault_enclave.anon_ledger_append(text, text, text, bigint, bytea, bytea, bytea, bytea, bytea) from public, rout_app;
revoke all on function vault_enclave.anon_retire_chain(text) from public, rout_app;
revoke all on function vault_enclave.anon_purge_host(uuid) from public, rout_app;
revoke all on function vault_enclave.anon_merge_host(uuid, uuid) from public, rout_app;

revoke all on function vault_enclave.anon_host_key_init(uuid, text, bytea, bytea, bytea, bytea, text, bytea, bytea) from public;
revoke all on function vault_enclave.anon_host_key_advance(text, bigint, bigint, bigint, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.anon_host_key_state(text) from public;
revoke all on function vault_enclave.anon_host_key_retire(uuid, text) from public;
revoke all on function vault_enclave.anon_booking_record(text, bigint, bytea, bytea, bytea, bytea, bigint, bytea, text, bigint, bytea, bytea, bytea) from public;
revoke all on function vault_enclave.anon_capacity_open(text, text, bytea, bytea) from public;
revoke all on function vault_enclave.anon_ledger(text, bigint, integer) from public;
revoke all on function vault_enclave.anon_booking_check(text, bytea) from public;
revoke all on function vault_enclave.anon_pseudonym_invalidate(text, bytea, text) from public;
revoke all on function vault_enclave.anon_host_chain(text) from public;
grant execute on function vault_enclave.anon_host_key_init(uuid, text, bytea, bytea, bytea, bytea, text, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_host_key_advance(text, bigint, bigint, bigint, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_host_key_state(text) to rout_app;
grant execute on function vault_enclave.anon_host_key_retire(uuid, text) to rout_app;
grant execute on function vault_enclave.anon_booking_record(text, bigint, bytea, bytea, bytea, bytea, bigint, bytea, text, bigint, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_capacity_open(text, text, bytea, bytea) to rout_app;
grant execute on function vault_enclave.anon_ledger(text, bigint, integer) to rout_app;
grant execute on function vault_enclave.anon_booking_check(text, bytea) to rout_app;
grant execute on function vault_enclave.anon_pseudonym_invalidate(text, bytea, text) to rout_app;
grant execute on function vault_enclave.anon_host_chain(text) to rout_app;
revoke all on function public.rout_anon_booking_purge(uuid) from public;
grant execute on function public.rout_anon_booking_purge(uuid) to rout_app;
revoke all on function public.rout_anon_booking_merge(uuid, uuid) from public, rout_app;
grant execute on function public.rout_anon_booking_merge(uuid, uuid) to rout_merge_executor;

-- execute_account_merge: move the secondary's booking chains right before the
-- secondary user row is deleted (the RESTRICT keys would otherwise stop it).
do $own$ begin execute pg_catalog.format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;
do $m$
declare
  v_def text;
  v_new text;
begin
  select pg_catalog.pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  if pg_catalog.strpos(v_def, 'rout_anon_booking_merge') > 0 then return; end if;
  v_new := pg_catalog.regexp_replace(v_def, E'(\\n)([ \\t]*delete from public\\.users where id=v_secondary;)',
    E'\\1 perform public.rout_anon_booking_merge(v_primary, v_secondary);\n\\2');
  if v_new = v_def then
    raise exception 'execute_account_merge: anchor "delete from public.users where id=v_secondary;" not found';
  end if;
  execute v_new;
end $m$;
revoke create on schema public from rout_merge_executor;
do $own$ begin execute pg_catalog.format('revoke rout_merge_executor from %I', current_user); end $own$;

-- In-transaction proof: no new table is reachable by rout_app or PUBLIC, each
-- has RLS on with exactly the restrictive deny_all policy, every new function
-- is pinned and closed to PUBLIC, and internal helpers are closed to rout_app.
do $$
declare v_bad text;
begin
  select string_agg(t, ', ') into v_bad from unnest(array['vault_enclave.anon_host_keys',
    'vault_enclave.anon_host_key_states', 'vault_enclave.anon_epoch_links', 'vault_enclave.anon_smt_trees',
    'vault_enclave.anon_smt_roots', 'vault_enclave.anon_booking_tokens', 'vault_enclave.anon_pseudonym_invalidations',
    'vault_enclave.anon_capacity_pools', 'vault_enclave.anon_ledger_events']) t
   where pg_catalog.has_table_privilege('rout_app', t, 'select') or pg_catalog.has_table_privilege('rout_app', t, 'insert')
      or pg_catalog.has_table_privilege('rout_app', t, 'update') or pg_catalog.has_table_privilege('rout_app', t, 'delete')
      or pg_catalog.has_table_privilege('public', t, 'select') or pg_catalog.has_table_privilege('public', t, 'insert')
      or not (select c.relrowsecurity from pg_catalog.pg_class c where c.oid = t::regclass)
      or (select pg_catalog.count(*) from pg_catalog.pg_policy p where p.polrelid = t::regclass) <> 1
      or not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = t::regclass and p.polname = 'deny_all'
                       and not p.polpermissive and p.polcmd = '*'
                       and pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'false'
                       and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) = 'false');
  if v_bad is not null then raise exception '0273: reachable or wrongly guarded table %', v_bad; end if;
  select string_agg(c.relname, ', ') into v_bad from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'vault_enclave' and c.relkind in ('r', 'p', 'v', 'm')
     and (pg_catalog.has_table_privilege('rout_app', c.oid, 'select') or pg_catalog.has_table_privilege('public', c.oid, 'select'));
  if v_bad is not null then raise exception '0273: vault_enclave table readable by rout_app or PUBLIC: %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname like 'anon\_%'
     and (not ('search_path=pg_catalog, pg_temp' = any (coalesce(p.proconfig, '{}')))
          or pg_catalog.has_function_privilege('public', p.oid, 'execute'));
  if v_bad is not null then raise exception '0273: unpinned or public function %', v_bad; end if;
  select string_agg(p.proname, ', ') into v_bad from pg_catalog.pg_proc p
   join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'vault_enclave' and p.proname = any (array['anon_is_hsk', 'anon_is_proof', 'anon_len', 'anon_id_ok',
     'anon_answer', 'anon_append_only', 'anon_caller', 'anon_stepup', 'anon_lp', 'anon_ledger_hash', 'anon_ledger_append',
     'anon_retire_chain', 'anon_purge_host', 'anon_merge_host'])
     and pg_catalog.has_function_privilege('rout_app', p.oid, 'execute');
  if v_bad is not null then raise exception '0273: rout_app can execute internal helper %', v_bad; end if;
  -- No foreign key into or between the anonymous tables may cascade.
  select string_agg(c.conname, ', ') into v_bad from pg_catalog.pg_constraint c
    join pg_catalog.pg_class r on r.oid = c.conrelid join pg_catalog.pg_namespace n on n.oid = r.relnamespace
   where n.nspname = 'vault_enclave' and r.relname like 'anon\_%' and c.contype = 'f' and c.confdeltype <> 'r';
  if v_bad is not null then raise exception '0273: cascading or non-restrict foreign key %', v_bad; end if;
  if pg_catalog.has_function_privilege('rout_app', 'public.rout_anon_booking_merge(uuid, uuid)', 'execute')
     or pg_catalog.has_function_privilege('public', 'public.rout_anon_booking_purge(uuid)', 'execute')
     or pg_catalog.strpos(pg_catalog.pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure),
          'rout_anon_booking_merge(v_primary, v_secondary)') = 0 then
    raise exception '0273: lifecycle functions wrongly granted or merge hook missing';
  end if;
end $$;
