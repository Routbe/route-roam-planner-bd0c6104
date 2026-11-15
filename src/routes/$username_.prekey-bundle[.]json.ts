import { createFileRoute } from "@tanstack/react-router";

/**
 * /@member/prekey-bundle.json — public PQ prekey document (Stap 8), served
 * unchanged from Scaleway (`users/<uid>/prekey-bundle.json`). Public
 * material only; initiators verify it themselves in the crypto worker
 * (verifyPrekeyDocument) before any handshake.
 */
const json = (status: number, body: BodyInit, cache: string) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": cache,
      "access-control-allow-origin": "*",
      "x-content-type-options": "nosniff",
    },
  });

export const Route = createFileRoute("/$username_/prekey-bundle.json")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const { readPrekeyDocument, productionReadDeps } = await import("@/lib/pq/prekey-publish.server");
        const { storageConfigured } = await import("@/lib/storage/s3.server");
        if (!storageConfigured("client")) return json(404, JSON.stringify({ error: "not_available" }), "no-store");
        try {
          const r = await readPrekeyDocument(await productionReadDeps(), String(params.username ?? ""));
          if (r.status === "invalid_handle") return json(400, JSON.stringify({ error: "invalid_handle" }), "no-store");
          if (r.status === "not_found") return json(404, JSON.stringify({ error: "not_available" }), "public, max-age=60");
          return json(200, r.status === "ok" ? (r.body as BodyInit) : "", "public, max-age=300");
        } catch {
          return json(503, JSON.stringify({ error: "unavailable" }), "no-store");
        }
      },
    },
  },
});
