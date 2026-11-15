-- 0276_tenant_column_expand.sql — Stap 10 part II (EXPAND, held in db-pending/ until the owner's GO).
--
-- Closes, or prepares the CONTRACT (db-pending/0277) for, the findings 0275 left open
-- (scripts/formal-rls/tenant-model.ts KNOWN_OPEN; HANDOVER appendix Stap 9):
--
--   F3   workspaces.rout_create let a new workspace name another member in legacy_user_id.
--   F8b  an own row could be moved into a foreign workspace by UPDATE (ten tables), and users/profiles
--        rows could name a foreign workspace on INSERT.
--   F2   (EXPAND) the social_links owner policies keyed on app.current_user_id, which the app never
--        sets; public reads get a definer that returns only the public columns of verified links.
--   F1   (EXPAND) owner, admin, notification and token definers for the private profile columns.
--   F9   (EXPAND) rout_resolve_member answers without an e-mail address; a pending invite may name a
--        member by id alone (email null), so a handle invite never stores that member's address.
--   Drift: on Neon public_profiles and profile_handles already run with security_invoker (seen
--        2026-11-15 after 0275); the replay of db/ now matches.
--
-- Compatibility with the code that runs at 0275 (checked against src/ and the 0275 snapshot):
--   * Workspace conversion inserts legacy_user_id = the converted account while acting as that
--     account (asSource), and moves profiles/QR/OAuth/users rows only after that account was added
--     as a member in the same transaction; no other path writes legacy_user_id.
--   * The UPDATE guards refuse only a changed tenant column that names a workspace the caller is
--     not a member of. rout_tenant_ref_kept is SECURITY INVOKER: inside WITH CHECK it sees the
--     pre-image through the caller's own RLS, so it reveals nothing the caller cannot already read.
--   * Nothing is revoked here; the old code keeps working unchanged. Rollback:
--     db-pending/0276_tenant_column_expand_rollback.sql.

-- Drift with Neon
alter view public.public_profiles set (security_invoker = true);
alter view public.profile_handles set (security_invoker = true);

-- F3: a new workspace may name only the caller as its legacy account.
alter policy rout_create on public.workspaces
  with check (public.rout_current_user_id() is not null
              and (legacy_user_id is null or legacy_user_id = public.rout_current_user_id()));

-- F8b / F3: an UPDATE may keep a tenant reference or point it at the caller's own workspace (account).
create function public.rout_tenant_ref_kept(p_table text, p_id uuid, p_ref uuid)
 returns boolean
 language sql
 stable
 set search_path = pg_catalog, pg_temp
as $function$
  select case p_table
    when 'booking_event_types' then exists (select 1 from public.booking_event_types t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'bookings' then exists (select 1 from public.bookings t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'oauth_clients' then exists (select 1 from public.oauth_clients t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'rout_calendars' then exists (select 1 from public.rout_calendars t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'tracked_qrs' then exists (select 1 from public.tracked_qrs t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'user_assets' then exists (select 1 from public.user_assets t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'webhook_endpoints' then exists (select 1 from public.webhook_endpoints t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'workspace_transfers' then exists (select 1 from public.workspace_transfers t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'profiles' then exists (select 1 from public.profiles t where t.id = p_id and t.workspace_id is not distinct from p_ref)
    when 'users' then exists (select 1 from public.users t where t.id = p_id and t.migrated_to_workspace_id is not distinct from p_ref)
    when 'workspaces' then exists (select 1 from public.workspaces t where t.id = p_id and t.legacy_user_id is not distinct from p_ref)
    else false end
$function$;
revoke all on function public.rout_tenant_ref_kept(text, uuid, uuid) from public, rout_app;
grant execute on function public.rout_tenant_ref_kept(text, uuid, uuid) to rout_app;

create policy rout_ws_update_guard on public.booking_event_types as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('booking_event_types', id, workspace_id));
create policy rout_ws_update_guard on public.bookings as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('bookings', id, workspace_id));
create policy rout_ws_update_guard on public.oauth_clients as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('oauth_clients', id, workspace_id));
create policy rout_ws_update_guard on public.rout_calendars as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('rout_calendars', id, workspace_id));
create policy rout_ws_update_guard on public.tracked_qrs as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('tracked_qrs', id, workspace_id));
create policy rout_ws_update_guard on public.user_assets as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('user_assets', id, workspace_id));
create policy rout_ws_update_guard on public.webhook_endpoints as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('webhook_endpoints', id, workspace_id));
create policy rout_ws_update_guard on public.workspace_transfers as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('workspace_transfers', id, workspace_id));
create policy rout_ws_update_guard on public.profiles as restrictive for update
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id) or public.rout_tenant_ref_kept('profiles', id, workspace_id));
create policy rout_ws_update_guard on public.users as restrictive for update
  with check (migrated_to_workspace_id is null or public.rout_is_workspace_member(migrated_to_workspace_id)
              or public.rout_tenant_ref_kept('users', id, migrated_to_workspace_id));
create policy rout_legacy_update_guard on public.workspaces as restrictive for update
  with check (legacy_user_id is null or legacy_user_id = public.rout_current_user_id()
              or public.rout_tenant_ref_kept('workspaces', id, legacy_user_id));
create policy rout_ws_insert_guard on public.users as restrictive for insert
  with check (migrated_to_workspace_id is null or public.rout_is_workspace_member(migrated_to_workspace_id));
create policy rout_ws_insert_guard on public.profiles as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));

-- F2 (EXPAND): owner policies on the setting the app sets; public reads through a narrow definer.
drop policy social_links_owner_delete on public.social_links;
drop policy social_links_owner_insert on public.social_links;
drop policy social_links_owner_update on public.social_links;
create policy social_links_owner_delete on public.social_links for delete
  using (profile_id = public.rout_current_user_id());
create policy social_links_owner_insert on public.social_links for insert
  with check (profile_id = public.rout_current_user_id());
create policy social_links_owner_update on public.social_links for update
  using (profile_id = public.rout_current_user_id()) with check (profile_id = public.rout_current_user_id());

create function public.rout_public_social_links(p_profile uuid)
 returns table(platform text, username text, follower_count integer, checked_at timestamp with time zone)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select s.platform, s.username, s.follower_count, coalesce(s.last_synced_at, s.verified_at)
    from public.social_links s
   where s.profile_id = p_profile and s.is_verified = true
   order by s.position, s.created_at
   limit 50
$function$;
revoke all on function public.rout_public_social_links(uuid) from public, rout_app;
grant execute on function public.rout_public_social_links(uuid) to rout_app;

-- F1 (EXPAND): the private profile columns, each read path narrowed to its purpose.
create function public.rout_profile_private_mine()
 returns table(email text, forwarding_email text, forwarding_email_verified boolean, forwarding_email_token text,
               forwarding_email_token_expires_at timestamp with time zone, legal_first_name text, legal_last_name text,
               last_city text, last_country text, last_location_at timestamp with time zone)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select p.email, p.forwarding_email, p.forwarding_email_verified, p.forwarding_email_token,
         p.forwarding_email_token_expires_at, p.legal_first_name, p.legal_last_name,
         p.last_city, p.last_country, p.last_location_at
    from public.profiles p
   where p.id = public.rout_current_user_id()
$function$;

create function public.rout_profile_export_mine()
 returns jsonb
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.to_jsonb(p) from public.profiles p where p.id = public.rout_current_user_id()
$function$;

create function public.rout_admin_profiles_private()
 returns table(id uuid, email text, forwarding_email text, legal_first_name text, legal_last_name text,
               last_city text, last_country text, last_location_at timestamp with time zone)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select p.id, p.email, p.forwarding_email, p.legal_first_name, p.legal_last_name,
         p.last_city, p.last_country, p.last_location_at
    from public.profiles p
   where public.rout_caller_is_admin()
$function$;

-- The address a visitor's booking request or contact form is sent to: only for a profile that
-- publishes that visible block, so it is never a general e-mail lookup.
create function public.rout_profile_notify_address(p_profile uuid, p_purpose text)
 returns text
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select coalesce(p.forwarding_email, p.email)
    from public.profiles p
   where p.id = p_profile
     and p_purpose in ('booking_request', 'contact_form')
     and pg_catalog.jsonb_typeof(p.blocks) = 'array'
     and exists (select 1 from pg_catalog.jsonb_array_elements(p.blocks) b
                  where b.value ->> 'kind' = p_purpose and coalesce(b.value ->> 'hidden', 'false') <> 'true')
$function$;

-- Verification links carry the token; only a well-formed token finds its own row.
create function public.rout_forwarding_token_lookup(p_token text)
 returns table(id uuid, forwarding_email text, forwarding_email_token_expires_at timestamp with time zone)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select p.id, p.forwarding_email, p.forwarding_email_token_expires_at
    from public.profiles p
   where pg_catalog.length(coalesce(p_token, '')) >= 16 and p.forwarding_email_token = p_token
   limit 1
$function$;

-- F9 (EXPAND): resolve a member by @handle or e-mail without returning any address.
create function public.rout_resolve_member(p_identifier text)
 returns table(user_id uuid, username text)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select u.id, p.username from public.users u left join public.profiles p on p.id = u.id
  where public.rout_current_user_id() is not null and u.account_status = 'active'
    and (pg_catalog.lower(p.username) = pg_catalog.lower(pg_catalog.ltrim(p_identifier, '@'))
         or u.email_normalized = pg_catalog.lower(p_identifier))
  limit 1
$function$;

alter table public.workspace_invites alter column email drop not null;
alter table public.workspace_invites add constraint workspace_invites_target_check
  check (email is not null or invited_user_id is not null);
create unique index workspace_invites_open_member_idx on public.workspace_invites (workspace_id, invited_user_id)
  where status = 'pending' and invited_user_id is not null;

-- F9 (EXPAND): a workspace transfer addressed by @handle stores that label, not the address; the
-- owner invitation is mailed to the account's address, which only the transfer's own source gets,
-- and only after confirming its own e-mail code, while the transfer is open.
create function public.rout_transfer_owner_address(p_transfer uuid)
 returns text
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select u.email
    from public.workspace_transfers t
    join public.users u on u.id = t.target_user_id
   where t.id = p_transfer
     and t.source_user_id = public.rout_current_user_id()
     and t.otp_verified_at is not null
     and t.status in ('pending', 'otp_ok')
     and t.expires_at > pg_catalog.now()
$function$;

revoke all on function public.rout_profile_private_mine() from public, rout_app;
revoke all on function public.rout_profile_export_mine() from public, rout_app;
revoke all on function public.rout_admin_profiles_private() from public, rout_app;
revoke all on function public.rout_profile_notify_address(uuid, text) from public, rout_app;
revoke all on function public.rout_forwarding_token_lookup(text) from public, rout_app;
revoke all on function public.rout_resolve_member(text) from public, rout_app;
revoke all on function public.rout_transfer_owner_address(uuid) from public, rout_app;
grant execute on function public.rout_profile_private_mine() to rout_app;
grant execute on function public.rout_profile_export_mine() to rout_app;
grant execute on function public.rout_admin_profiles_private() to rout_app;
grant execute on function public.rout_profile_notify_address(uuid, text) to rout_app;
grant execute on function public.rout_forwarding_token_lookup(text) to rout_app;
grant execute on function public.rout_resolve_member(text) to rout_app;
grant execute on function public.rout_transfer_owner_address(uuid) to rout_app;
