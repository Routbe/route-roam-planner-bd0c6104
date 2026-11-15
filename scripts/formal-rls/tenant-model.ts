/**
 * Reviewed inputs to the formal RLS verifier (Stap 9). Every entry carries a
 * reason, and the verifier fails on an entry nothing uses, so this file can
 * only shrink by fixing the schema, never by quietly growing.
 */

/** A column names a principal (a user) when it matches this name or carries a FK to a user table. */
export const IDENTITY_COLUMN = /^((.+_)?user_id|owner_id|creator_id|recipient_id|sender_id|author_id|member_id|profile_id|created_by|consumed_by|granted_by|invited_by)$/;
export const USER_TABLES = new Set(["users", "profiles", "user"]);
export const WORKSPACE_TABLES = new Set(["workspaces"]);

/**
 * Settings the application sets from the verified session (src/lib/db-context.ts)
 * or that only name the caller. The model reads every one as "the caller"
 * (worst case: the app set it to the authenticated member).
 */
export const IDENTITY_SETTINGS = new Set(["rout.current_user_id", "rout.user_id", "rout.auth_user_id", "app.current_user_id"]);
export const IDENTITY_FUNCTIONS = new Set(["rout_current_user_id", "current_app_user_id", "caller_user_id"]);

/**
 * Public by design. The proof shows these reads are satisfiable for a stranger's
 * row; that is the declassification. Read-only and listed one by one.
 */
/** columns: the declassification covers only these columns, and only while rout_app has no table-level SELECT. */
export type Declassification = { table: string; cmd: "SELECT" | "INSERT"; reason: string; columns?: readonly string[] };
export const DECLASSIFIED: ReadonlyArray<Declassification> = [
  { table: "public.badges", cmd: "SELECT", reason: "badge catalogue shown on every public profile; no member columns" },
  { table: "public.reserved_brands", cmd: "SELECT", reason: "reserved brand names, checked at sign-up before any identity exists" },
  { table: "public.reserved_handles", cmd: "SELECT", reason: "reserved handles, checked at sign-up before any identity exists" },
  { table: "public.showcase_profiles", cmd: "SELECT", reason: "curated public showcase on the home page; no member columns" },
  { table: "public.platform_feature_switches", cmd: "SELECT", reason: "global on/off switches the public pages read; writes need a platform admin" },
  { table: "public.platform_integration_switches", cmd: "SELECT", reason: "global integration switches (db/0241): rout_app reads only provider and mode, no member columns", columns: ["mode", "provider"] },
  { table: "public.alias_profiles", cmd: "SELECT", reason: "only enabled alias pages, which are public profile pages by design" },
  { table: "public.custom_domains", cmd: "SELECT", reason: "only verified domains, needed to route a public host name; the TXT token is published in DNS" },
  { table: "public.account_deletion_audit", cmd: "INSERT", reason: "append-only, no member columns; each row carries an HMAC under the server secret, so a forged row fails verification" },
];

/** Private profile columns (db-pending/0277): only owner, admin, notification and token definers read them. */
export const PRIVATE_PROFILE_COLUMNS = ["email", "forwarding_email", "forwarding_email_token", "forwarding_email_token_expires_at", "legal_first_name", "legal_last_name", "last_city", "last_country", "last_location_at"] as const;
/**
 * Reviewed entries for the held-back db-pending/0277. They move into DECLASSIFIED (and the KNOWN_OPEN
 * entries F1/F2 leave) in the change that moves 0277 into db/; until then the pending-migration test
 * passes them to the verifier explicitly.
 */
export const PENDING_0277_DECLASSIFIED: ReadonlyArray<Declassification> = [
  { table: "public.profiles", cmd: "SELECT", reason: "public profile columns (handle, display name, design, badges, status); every private column is withheld from rout_app by column privileges", columns: ["id", "username", "display_name", "tagline", "bio", "avatar_url", "favicon_url", "theme", "card_style", "blocks", "tier", "status", "verified", "verified_at", "verified_legal_name", "is_suspended", "is_banned", "url_style", "created_at", "updated_at", "preferred_language", "business_info", "is_early_believer", "is_paid", "subdomain_enabled", "custom_domain", "bluesky_did", "redirect_target", "show_email_publicly", "forwarding_email_verified", "handle_grant", "payment_method", "moderated_at", "moderated_by", "moderation_reason", "alias_status", "alias_sync_status", "alias_sync_attempts", "alias_sync_error", "alias_synced_at", "referred_by", "referral_count", "country_code", "display_prefs", "is_admin", "subdomain_alias", "subdomain_tier", "root_subdomain_status", "bluesky_handle", "show_vcard_button", "invited_count", "verified_invites", "stripe_account_id", "stripe_account_status", "stripe_charges_enabled", "stripe_payouts_enabled", "show_total_reach", "total_reach_count", "reach_last_synced_at", "total_reach_manual", "is_business", "business_name", "business_vat", "is_influencer", "is_shadowbanned", "profile_descriptions", "workspace_id", "is_early_verified", "early_believer_at"] },
];

/**
 * Tables outside the per-member RLS model. Their rows are reached by the
 * auth adapter before any member identity exists.
 */
const AUTH_ADAPTER = "Better Auth adapter tables: looked up by session token, account or passkey id before any member identity exists, so row security cannot key on the caller (residual risk: a compromised rout_app reads all of them)";
export const SERVICE_BOUNDARY: ReadonlyArray<{ schema: string; table: string; reason: string }> = ["account", "passkey", "session", "twoFactor", "user", "verification"].map((table) => ({ schema: "neon_auth", table, reason: AUTH_ADAPTER }));

/**
 * Open findings that are known and tracked (HANDOVER appendix Stap 9). The
 * test fails when this list and the verifier's findings differ either way.
 */
/** Tables whose INSERT carries the 0275 workspace guard (db/0275). */
export const F8A = ["booking_event_types", "bookings", "oauth_clients", "rout_calendars", "tracked_qrs", "user_assets", "webhook_endpoints", "workspace_transfers"] as const;
/**
 * Findings db/0276 (EXPAND, applied on Neon 2026-11-15) closed: F3 and every F8b entry. Kept so the
 * replay tests can show the 0276 rollback reopens exactly these; never part of KNOWN_OPEN again.
 */
export const CLOSED_BY_0276: ReadonlyArray<string> = [
  "rls:public.workspaces:INSERT:check",
  ...[...F8A, "users", "profiles"].map((t) => `rls:public.${t}:UPDATE:check`),
  "rls:public.users:INSERT:check",
  "rls:public.profiles:INSERT:check",
];
const ORACLE_OPEN = "personal or externally known identifier: a duplicate-key error tells whether another member holds it; fix by moving writes into a definer that answers uniformly";
export const KNOWN_OPEN: ReadonlyArray<{ id: string; reason: string }> = [
  { id: "rls:public.profiles:SELECT:using", reason: "F1 rout_public_read = true exposes every profile column (email, legal names, forwarding token, location, Stripe ids) to rout_app; privacy is enforced only in server code. Needs EXPAND (public reads through public_profiles / a definer) before CONTRACT drops the policy" },
  { id: "rls:public.social_links:SELECT:using", reason: "F2 social_links_public_select = true also exposes verification_code and last_error; the owner policies key on app.current_user_id, which the app never sets" },
  ...["users(email_normalized)", "profiles(stripe_account_id)", "identity_links(issuer,provider_sub)", "user_identities(provider,provider_account_id)", "user_linked_accounts(platform,provider_account_id)", "user_snapchat(external_id)", "identity_relays(proxy_email)", "identity_verifications(unique_human_id)"].map((k) => ({ id: `oracle:${k}`, reason: `F6 ${ORACLE_OPEN}` })),
];

/**
 * Unique keys without a tenant column on tables rout_app can write, reviewed
 * one by one. "secret": the value is a hash or random token, so guessing it is
 * infeasible. "public": the value is public by design and an availability
 * check is the feature. "internal": a server-generated reference no member chooses.
 */
export const ORACLE_REVIEW: Readonly<Record<string, "secret" | "public" | "internal">> = {
  "account_email_changes(confirm_token_hash)": "secret", "account_email_changes(freeze_token_hash)": "secret",
  "ambient_weather_locations(token_hash)": "secret", "badge_claim_links(token)": "secret", "bookings(booking_token)": "secret",
  "bookings(stripe_checkout_session_id)": "secret", "connected_calendars(webhook_channel_id)": "secret",
  "identity_verification_sessions(state)": "secret", "oauth_access_tokens(token_hash)": "secret", "oauth_clients(client_id)": "secret",
  "oauth_refresh_tokens(token_hash)": "secret", "oauth_step_up_challenges(challenge)": "secret", "oidc_subjects(sector,subject)": "secret",
  "omni_ingest_tokens(token_hash)": "secret", "tracked_qrs(dashboard_token)": "secret", "user_custom_presence(api_key_hash)": "secret",
  "user_sessions(token_hash)": "secret", "workspace_transfers(token_hash)": "secret", "verified_identities(identity_nullifier)": "secret",
  "verified_identities(national_id_nullifier)": "secret", "verified_identities(provider,provider_sub_nullifier)": "secret",
  "avatar_objects(path)": "secret", "gallery_objects(path)": "secret",
  "alias_profiles(lower(handle))": "public", "card_designs(serial)": "public", "card_freezes(serial)": "public", "custom_badges(slug)": "public",
  "custom_domains(domain)": "public", "domain_claims(domain)": "public", "domain_claims(handle)": "public", "email_aliases(alias)": "public",
  "oauth_email_forwarding_rules(alias_local)": "public", "platform_feature_switches(feature)": "public", "profiles(username)": "public",
  "profiles(lower(subdomain_alias))": "public", "profiles(lower(username))": "public", "public_activity(source,external_ref)": "public",
  "rout_calendars(public_id)": "public", "tracked_qrs(slug)": "public", "user_badges(badge_id,serial_number)": "public",
  "workspace_root_aliases(handle)": "public", "workspaces(slug)": "public",
  "identity_link_events(id)": "internal", "omni_matrix_items(id)": "internal", "invoice_deliveries(payment_id)": "internal", "wallet_transactions(reference)": "internal",
};

/**
 * Set-returning SECURITY DEFINER helpers that policies call inside IN (...).
 * Each is modelled by its own SQL body, which is pinned: if the snapshot body
 * changes, the lemma no longer applies and the policy counts as unproven.
 */
export const SRF_LEMMAS: Record<string, { body: string; sql: string; bypassRls: true }> = {
  rout_accessible_tracked_qr_ids: {
    body: `  select t.id from public.tracked_qrs t
   where public.rout_current_user_id() is not null
     and (t.user_id = public.rout_current_user_id()
          or (t.workspace_id is not null and public.rout_is_workspace_member(t.workspace_id)))`,
    sql: "SELECT t.id FROM tracked_qrs t WHERE ((rout_current_user_id() IS NOT NULL) AND ((t.user_id = rout_current_user_id()) OR ((t.workspace_id IS NOT NULL) AND rout_is_workspace_member(t.workspace_id))))",
    bypassRls: true,
  },
};

/**
 * Views created WITH (security_invoker = true). The snapshot has no view
 * options, so the replay test compares this list with pg_class.reloptions.
 */
export const INVOKER_VIEWS: ReadonlySet<string> = new Set(["auth.users", "public.grid_items", "public.ingest_tokens", "public.profile_handles", "public.public_profiles"]);

/**
 * Helpers whose meaning the encoder relies on, pinned to their exact body
 * (whitespace-insensitive). rout_workspace_claimable (db/0275) is true
 * only for a workspace without any member.
 */
export const PINNED_FUNCTIONS: Readonly<Record<string, string>> = {
  // db-pending/0276: true iff the row with that primary key already holds p_ref in the named tenant column.
  rout_tenant_ref_kept: `
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
`,
  rout_workspace_claimable: `
  select exists (select 1 from public.workspaces w where w.id = ws and w.created_at >= pg_catalog.now() - interval '10 minutes')
     and not exists (select 1 from public.workspace_members m where m.workspace_id = ws)
`,
};
