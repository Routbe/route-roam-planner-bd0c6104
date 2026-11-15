-- 0275_rls_non_interference_hardening.sql — Stap 9 (CONTRACT, held in db-pending/ until the owner's GO).
--
-- Found by scripts/formal-rls-verifier.ts (Z3) on the 0274 schema and reproduced on a PGlite replay
-- (src/test/rls-non-interference.test.ts):
--
--   F4  public.public_profiles and public.profile_handles run with their owner's rights and rout_app
--       holds INSERT/UPDATE/DELETE on them. A write through them is checked as the owner, so RLS on
--       profiles does not apply: any rout_app session could rewrite or delete another member's profile.
--   F5  auth.users reads public.users with its owner's rights: every member's e-mail address and
--       metadata are readable through it, although public.users only shows the caller's own row.
--   F7  workspace_members.rout_scope (ALL, user_id = caller) lets any member insert themselves into any
--       workspace with any role, and raise their own role to 'owner'.
--   F8a A member could insert their own row into a workspace they do not belong to (bookings, event
--       types, OAuth clients, webhooks, QR codes, calendars, assets, transfers), planting it in another
--       tenant's workspace.
--
-- Compatibility (checked against src/ and every function in the 0274 snapshot):
--   * Neither view is written by app code or a function; nothing reads auth.users.
--   * Members are added only by the workspace creator in the creating flow (workspaces.functions.ts,
--     admin-grant.server.ts, workspace-conversion.server.ts: first member right after the workspace is
--     created), by owners/admins (rout_team_add), or by SECURITY DEFINER functions (invites, agent claims).
--     rout_first_member keeps the first case; nobody updates their own membership; leaving stays possible.
--   * Rows are written into a workspace only for the active workspace, whose membership the server checks.
-- UPDATE of existing rows is unchanged (finding F8b stays open). Rollback:
-- db-pending/0275_rls_non_interference_hardening_rollback.sql.

-- F4 / F5
revoke insert, update, delete, truncate, references, trigger on public.public_profiles from rout_app, public;
revoke insert, update, delete, truncate, references, trigger on public.profile_handles from rout_app, public;
alter view auth.users set (security_invoker = true);

-- F7: a workspace without any member, created in the last ten minutes, may get its first member: the caller.
create function public.rout_workspace_claimable(ws uuid)
 returns boolean
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select exists (select 1 from public.workspaces w where w.id = ws and w.created_at >= pg_catalog.now() - interval '10 minutes')
     and not exists (select 1 from public.workspace_members m where m.workspace_id = ws)
$function$;
revoke all on function public.rout_workspace_claimable(uuid) from public, rout_app;
-- Called from a policy expression, which runs with the querying role's rights.
grant execute on function public.rout_workspace_claimable(uuid) to rout_app;

drop policy rout_scope on public.workspace_members;
create policy rout_self_read on public.workspace_members for select
  using (user_id = public.rout_current_user_id());
create policy rout_self_leave on public.workspace_members for delete
  using (user_id = public.rout_current_user_id());
create policy rout_first_member on public.workspace_members for insert
  with check (user_id = public.rout_current_user_id() and public.rout_workspace_claimable(workspace_id));

-- F8a: a new row may name a workspace only when the caller is a member of it.
create policy rout_ws_insert_guard on public.booking_event_types as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.bookings as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.oauth_clients as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.rout_calendars as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.tracked_qrs as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.user_assets as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.webhook_endpoints as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
create policy rout_ws_insert_guard on public.workspace_transfers as restrictive for insert
  with check (workspace_id is null or public.rout_is_workspace_member(workspace_id));
