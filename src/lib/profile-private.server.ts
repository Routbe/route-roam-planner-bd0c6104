/**
 * The only readers of the private profile columns (e-mail, forwarding address
 * and its token, legal names, last location). From db-pending/0277 on, rout_app
 * cannot select them from public.profiles; each reader below goes through the
 * db/0276 definer for its purpose. Until 0276 runs, the legacy column reads are
 * used (src/test/private-profile-columns.test.ts keeps every other module off them).
 */
import { currentDbUserId, sql, withDbContext } from "@/lib/neon";
import { hasSchemaFeature } from "@/lib/schema-features.server";

export type PrivateProfile = {
  email: string | null;
  forwarding_email: string | null;
  forwarding_email_verified: boolean | null;
  forwarding_email_token: string | null;
  forwarding_email_token_expires_at: string | null;
  legal_first_name: string | null;
  legal_last_name: string | null;
  last_city: string | null;
  last_country: string | null;
  last_location_at: string | null;
};
export type AdminPrivateProfile = Pick<PrivateProfile, "email" | "forwarding_email" | "legal_first_name" | "legal_last_name" | "last_city" | "last_country" | "last_location_at"> & { id: string };

const asOwner = <T>(userId: string, run: () => Promise<T>) =>
  currentDbUserId() === userId ? run() : withDbContext({ userId, workspaceId: null }, run);

/** The member's own private columns (null when the profile row does not exist). */
export async function readMyPrivateProfile(userId: string): Promise<PrivateProfile | null> {
  return asOwner(userId, async () => {
    const rows = (await hasSchemaFeature("0276"))
      ? ((await sql`select * from public.rout_profile_private_mine()`) as PrivateProfile[])
      : ((await sql`select email, forwarding_email, forwarding_email_verified, forwarding_email_token,
                           forwarding_email_token_expires_at, legal_first_name, legal_last_name,
                           last_city, last_country, last_location_at
                      from public.profiles where id = ${userId} limit 1`) as PrivateProfile[]);
    return rows[0] ?? null;
  });
}

/** The member's own complete profile row, for the data export. */
export async function exportMyProfileRow(userId: string): Promise<Record<string, unknown> | null> {
  return asOwner(userId, async () => {
    if (await hasSchemaFeature("0276")) {
      const rows = (await sql`select public.rout_profile_export_mine() as row`) as { row: Record<string, unknown> | null }[];
      return rows[0]?.row ?? null;
    }
    const rows = (await sql`select * from public.profiles where id = ${userId} limit 1`) as Record<string, unknown>[];
    return rows[0] ?? null;
  });
}

/** Where a visitor's booking request or contact-form message goes; null unless the profile publishes that block. */
export async function readNotifyAddress(profileId: string, purpose: "booking_request" | "contact_form"): Promise<string | null> {
  if (await hasSchemaFeature("0276")) {
    const rows = (await sql`select public.rout_profile_notify_address(${profileId}::uuid, ${purpose}) as email`) as { email: string | null }[];
    return rows[0]?.email ?? null;
  }
  const rows = (await sql`select coalesce(forwarding_email, email) as email from public.profiles where id = ${profileId}::uuid limit 1`) as { email: string | null }[];
  return rows[0]?.email ?? null;
}

/** Private columns for platform admins (empty for anyone else once 0276 runs). */
export async function readAdminPrivateProfiles(ids: string[]): Promise<Map<string, AdminPrivateProfile>> {
  const out = new Map<string, AdminPrivateProfile>();
  if (!ids.length) return out;
  const rows = (await hasSchemaFeature("0276"))
    ? ((await sql`select * from public.rout_admin_profiles_private() where id = any(${ids}::uuid[])`) as AdminPrivateProfile[])
    : ((await sql`select id, email, forwarding_email, legal_first_name, legal_last_name, last_city, last_country, last_location_at
                    from public.profiles where id = any(${ids}::uuid[])`) as AdminPrivateProfile[]);
  for (const r of rows) out.set(String(r.id), r);
  return out;
}

/**
 * SQL source with the admin-visible private columns (id, email, forwarding_email, ...), for joins in
 * admin listings that filter on them. A constant fragment: never built from input.
 */
export async function adminPrivateProfilesText(): Promise<string> {
  return (await hasSchemaFeature("0276"))
    ? "(select * from public.rout_admin_profiles_private())"
    : "(select id, email, forwarding_email, legal_first_name, legal_last_name, last_city, last_country, last_location_at from public.profiles)";
}
/** The same source as a raw fragment for tagged templates. */
export async function adminPrivateProfilesSource() {
  return sql.unsafe(await adminPrivateProfilesText());
}

/** The profile a forwarding verification link belongs to. */
export async function findForwardingToken(token: string): Promise<{ id: string; forwarding_email: string | null; forwarding_email_token_expires_at: string | null } | null> {
  if (await hasSchemaFeature("0276")) {
    const rows = (await sql`select * from public.rout_forwarding_token_lookup(${token})`) as { id: string; forwarding_email: string | null; forwarding_email_token_expires_at: string | null }[];
    return rows[0] ?? null;
  }
  const rows = (await sql`select id, forwarding_email, forwarding_email_token_expires_at from public.profiles where forwarding_email_token = ${token} limit 1`) as { id: string; forwarding_email: string | null; forwarding_email_token_expires_at: string | null }[];
  return rows[0] ?? null;
}
