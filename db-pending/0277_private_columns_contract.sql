-- 0277_private_columns_contract.sql — Stap 10 part II (CONTRACT, held in db-pending/ until production
-- runs the code that uses the 0276 EXPAND functions: the health probe must report schema >= 0276).
--
--   F1  rout_app reads the private profile columns (email, forwarding_email, forwarding_email_token, forwarding_email_token_expires_at, legal_first_name, legal_last_name, last_city, last_country, last_location_at)
--       no longer directly; owners, admins, notifications and verification links use the 0276 definers.
--       Every other profile column stays readable: the public profile is public by design.
--   F2  social_links rows (with verification_code and last_error) are readable only by their owner and
--       platform admins; public pages use rout_public_social_links.
--   F9  rout_resolve_account returns an e-mail address only when the caller looked the member up by
--       that same address; for an @handle it returns null. Pending handle invites drop the stored address.
--
-- A new profiles column is not readable by rout_app until a migration grants it (column privileges).
-- Rollback: db-pending/0277_private_columns_contract_rollback.sql.

revoke select on public.profiles from rout_app;
grant select (
  id, username, display_name, tagline, bio, avatar_url, favicon_url, theme, card_style, blocks,
  tier, status, verified, verified_at, verified_legal_name, is_suspended, is_banned, url_style,
  created_at, updated_at, preferred_language, business_info, is_early_believer, is_paid,
  subdomain_enabled, custom_domain, bluesky_did, redirect_target, show_email_publicly,
  forwarding_email_verified, handle_grant, payment_method, moderated_at, moderated_by,
  moderation_reason, alias_status, alias_sync_status, alias_sync_attempts, alias_sync_error,
  alias_synced_at, referred_by, referral_count, country_code, display_prefs, is_admin,
  subdomain_alias, subdomain_tier, root_subdomain_status, bluesky_handle, show_vcard_button,
  invited_count, verified_invites, stripe_account_id, stripe_account_status,
  stripe_charges_enabled, stripe_payouts_enabled, show_total_reach, total_reach_count,
  reach_last_synced_at, total_reach_manual, is_business, business_name, business_vat,
  is_influencer, is_shadowbanned, profile_descriptions, workspace_id, is_early_verified,
  early_believer_at
) on public.profiles to rout_app;

drop policy social_links_public_select on public.social_links;
create policy social_links_owner_select on public.social_links for select
  using (profile_id = public.rout_current_user_id() or public.rout_caller_is_admin());

create or replace function public.rout_resolve_account(p_identifier text)
 returns table(user_id uuid, email text, username text)
 language sql
 stable security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select u.id, case when u.email_normalized = pg_catalog.lower(p_identifier) then u.email end, p.username
    from public.users u left join public.profiles p on p.id = u.id
  where public.rout_current_user_id() is not null and u.account_status = 'active'
    and (pg_catalog.lower(p.username) = pg_catalog.lower(pg_catalog.ltrim(p_identifier, '@'))
         or u.email_normalized = pg_catalog.lower(p_identifier))
  limit 1
$function$;

update public.workspace_invites i set email = null
 where i.status = 'pending' and i.invited_user_id is not null
   and exists (select 1 from public.users u where u.id = i.invited_user_id and pg_catalog.lower(u.email) = pg_catalog.lower(i.email));
