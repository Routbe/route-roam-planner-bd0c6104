import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";

const B64U = /^[A-Za-z0-9_-]+$/;
const Input = z.object({
  bundle: z.string().regex(B64U).max(4096),
  credentialId: z.string().regex(B64U).min(16).max(1366),
  algorithm: z.number().int(),
  authenticatorData: z.string().regex(B64U).max(4096),
  clientDataJSON: z.string().regex(B64U).max(4096),
  signature: z.string().regex(B64U).max(1024),
});

/** Publishes the signed member's prekey document to Scaleway (no SQL write). */
export const publishMyPrekeyBundle = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((v: unknown) => Input.parse(v))
  .handler(async ({ context, data }) => {
    const { publishPrekey, productionPublishDeps } = await import("./prekey-publish.server");
    const { storageConfigured } = await import("@/lib/storage/s3.server");
    if (!storageConfigured("client")) return { ok: false as const, reason: "storage_unavailable" as const };
    return publishPrekey(await productionPublishDeps(), context.userId, data);
  });
