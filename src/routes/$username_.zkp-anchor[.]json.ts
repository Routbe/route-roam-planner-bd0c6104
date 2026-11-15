import { createFileRoute } from "@tanstack/react-router";

/**
 * /@host/zkp-anchor.json — public discovery anchor of a host's anonymous
 * booking keys (Stap 7g): per registered device the anchor PK_0, its epoch
 * links and the host passkey's WebAuthn assertion over that anchor (MDS3
 * attested passkey). Public material only; guests verify it themselves with
 * src/lib/anon-booking/zkp-anchor.ts. Needs db/0274; on a database without it
 * every host answers 404 `not_available`.
 */
const json = (status: number, body: unknown, cache: string) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": cache,
      "access-control-allow-origin": "*",
      "x-content-type-options": "nosniff",
    },
  });

export const Route = createFileRoute("/$username_/zkp-anchor.json")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const { anchorHandle, readZkpAnchorDocument } = await import("@/lib/anon-booking/zkp-anchor.server");
        const handle = anchorHandle(String(params.username ?? ""));
        if (!handle) return json(400, { error: "invalid_handle" }, "no-store");
        try {
          const { sql } = await import("@/lib/neon");
          const { canonicalAppUrl } = await import("@/lib/app-url");
          const rpId = new URL(canonicalAppUrl()).hostname;
          const r = await readZkpAnchorDocument(async (q, p) => (await sql.query(q, p)) as Record<string, unknown>[], handle, rpId);
          if (r.status === "ok") return json(200, r.document, "public, max-age=300, s-maxage=300, stale-while-revalidate=3600");
          const error = r.status === "unavailable" ? "not_available" : r.status;
          return json(404, { error }, "public, max-age=60");
        } catch {
          return json(503, { error: "temporarily_unavailable" }, "no-store");
        }
      },
    },
  },
});
