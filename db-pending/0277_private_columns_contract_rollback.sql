-- Rollback of db-pending/0277_private_columns_contract.sql: restores 0276. Idempotent.
-- Pending handle invites get the member's address back, so the 0276 rollback can run afterwards.

grant select on public.profiles to rout_app;

drop policy if exists social_links_owner_select on public.social_links;
drop policy if exists social_links_public_select on public.social_links;
create policy social_links_public_select on public.social_links for select using (true);

create or replace function public.rout_resolve_account(p_identifier text)
 returns table(user_id uuid, email text, username text)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select u.id, u.email, p.username from public.users u left join public.profiles p on p.id = u.id
  where public.rout_current_user_id() is not null and u.account_status = 'active'
    and (lower(p.username) = lower(ltrim(p_identifier, '@')) or u.email_normalized = lower(p_identifier))
  limit 1 $function$;

update public.workspace_invites i set email = u.email
  from public.users u
 where i.email is null and i.status = 'pending' and u.id = i.invited_user_id;
