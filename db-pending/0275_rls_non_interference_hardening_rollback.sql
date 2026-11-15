-- Rollback of 0275_rls_non_interference_hardening.sql: restores the 0274 rights and policies exactly.
-- Idempotent. It reopens findings F4, F5, F7 and F8a of the Stap 9 verifier; use it only to undo a failed rollout.

drop policy if exists rout_ws_insert_guard on public.booking_event_types;
drop policy if exists rout_ws_insert_guard on public.bookings;
drop policy if exists rout_ws_insert_guard on public.oauth_clients;
drop policy if exists rout_ws_insert_guard on public.rout_calendars;
drop policy if exists rout_ws_insert_guard on public.tracked_qrs;
drop policy if exists rout_ws_insert_guard on public.user_assets;
drop policy if exists rout_ws_insert_guard on public.webhook_endpoints;
drop policy if exists rout_ws_insert_guard on public.workspace_transfers;

drop policy if exists rout_first_member on public.workspace_members;
drop policy if exists rout_self_leave on public.workspace_members;
drop policy if exists rout_self_read on public.workspace_members;
drop policy if exists rout_scope on public.workspace_members;
create policy rout_scope on public.workspace_members
  using (user_id = rout_current_user_id()) with check (user_id = rout_current_user_id());
drop function if exists public.rout_workspace_claimable(uuid);

grant insert, update, delete on public.public_profiles to rout_app;
grant insert, update, delete on public.profile_handles to rout_app;
alter view auth.users reset (security_invoker);
