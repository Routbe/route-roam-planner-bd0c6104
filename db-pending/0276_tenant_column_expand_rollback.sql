-- Rollback of db-pending/0276_tenant_column_expand.sql: restores 0275, except that public_profiles and
-- profile_handles keep security_invoker (Neon already ran them that way before 0276). Idempotent.
-- Refuses while a pending invite names a member by id alone (its address was never stored).
do $rb$
begin
  if to_regclass('public.workspace_invites') is not null and exists (select 1 from public.workspace_invites where email is null) then
    raise exception '0276 rollback: % invite(s) without an e-mail address; revoke them first', (select count(*) from public.workspace_invites where email is null);
  end if;
end $rb$;

drop index if exists public.workspace_invites_open_member_idx;
alter table public.workspace_invites drop constraint if exists workspace_invites_target_check;
alter table public.workspace_invites alter column email set not null;

drop function if exists public.rout_transfer_owner_address(uuid);
drop function if exists public.rout_resolve_member(text);
drop function if exists public.rout_forwarding_token_lookup(text);
drop function if exists public.rout_profile_notify_address(uuid, text);
drop function if exists public.rout_admin_profiles_private();
drop function if exists public.rout_profile_export_mine();
drop function if exists public.rout_profile_private_mine();
drop function if exists public.rout_public_social_links(uuid);

drop policy if exists social_links_owner_delete on public.social_links;
drop policy if exists social_links_owner_insert on public.social_links;
drop policy if exists social_links_owner_update on public.social_links;
create policy social_links_owner_delete on public.social_links for delete using (profile_id = public.current_app_user_id());
create policy social_links_owner_insert on public.social_links for insert with check (profile_id = public.current_app_user_id());
create policy social_links_owner_update on public.social_links for update using (profile_id = public.current_app_user_id());

drop policy if exists rout_ws_update_guard on public.booking_event_types;
drop policy if exists rout_ws_update_guard on public.bookings;
drop policy if exists rout_ws_update_guard on public.oauth_clients;
drop policy if exists rout_ws_update_guard on public.rout_calendars;
drop policy if exists rout_ws_update_guard on public.tracked_qrs;
drop policy if exists rout_ws_update_guard on public.user_assets;
drop policy if exists rout_ws_update_guard on public.webhook_endpoints;
drop policy if exists rout_ws_update_guard on public.workspace_transfers;
drop policy if exists rout_ws_update_guard on public.profiles;
drop policy if exists rout_ws_update_guard on public.users;
drop policy if exists rout_legacy_update_guard on public.workspaces;
drop policy if exists rout_ws_insert_guard on public.users;
drop policy if exists rout_ws_insert_guard on public.profiles;
drop function if exists public.rout_tenant_ref_kept(text, uuid, uuid);

alter policy rout_create on public.workspaces with check (public.rout_current_user_id() is not null);
