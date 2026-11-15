/**
 * Epoch clock of the anonymous booking engine (Stap 7g, owner decision
 * 2026-11-15): one host-key epoch per UTC day, the transition at exactly
 * 00:00:00.000 UTC. The epoch number is the day index since 1970-01-01 UTC,
 * so every host, guest and device agrees on it without a shared origin, and
 * local time zones or daylight saving never move a transition.
 *
 * A fresh chain starts at epoch 0 (its anchor PK_0) and ratchets straight to
 * the current day on first use; forward-secure.ts MAX_EPOCH_ADVANCE (65 536)
 * covers that first jump until the year 2149.
 */
export const EPOCH_SECONDS = 86_400;
export const EPOCH_MS = EPOCH_SECONDS * 1000;
export const EPOCH_ORIGIN = "1970-01-01T00:00:00Z";

function msOf(now: number | Date): number {
  const ms = typeof now === "number" ? now : now.getTime();
  if (!Number.isFinite(ms) || ms < 0) throw new RangeError("epoch_clock_invalid_time");
  return ms;
}

/** Epoch (UTC day index) at `now`. */
export function utcEpochAt(now: number | Date): number {
  return Math.floor(msOf(now) / EPOCH_MS);
}

/** First millisecond of `epoch` (00:00:00.000 UTC of that day). */
export function epochStartMs(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new RangeError("epoch_clock_invalid_epoch");
  return epoch * EPOCH_MS;
}

/** Milliseconds from `now` until the next 00:00:00.000 UTC (1..86 400 000). */
export function msUntilNextEpoch(now: number | Date): number {
  const ms = msOf(now);
  return epochStartMs(utcEpochAt(ms) + 1) - ms;
}
