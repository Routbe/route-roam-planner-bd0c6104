import { describe, expect, it } from "vitest";
import { EPOCH_MS, epochStartMs, msUntilNextEpoch, utcEpochAt } from "./epoch-clock";

describe("epoch clock: one epoch per UTC day, transition at 00:00 UTC (owner 2026-11-15)", () => {
  it("is the UTC day index since 1970-01-01", () => {
    expect(EPOCH_MS).toBe(86_400_000);
    expect(utcEpochAt(0)).toBe(0);
    expect(utcEpochAt(Date.UTC(2026, 10, 15, 7, 50))).toBe(20_772);
    expect(epochStartMs(20_772)).toBe(Date.UTC(2026, 10, 15));
  });

  it("changes exactly at 00:00:00.000 UTC, not a millisecond earlier", () => {
    const midnight = Date.UTC(2026, 10, 16, 0, 0, 0, 0);
    expect(utcEpochAt(midnight - 1)).toBe(20_772);
    expect(utcEpochAt(midnight)).toBe(20_773);
    expect(msUntilNextEpoch(midnight - 1)).toBe(1);
    expect(msUntilNextEpoch(midnight)).toBe(EPOCH_MS);
  });

  it("ignores local time and daylight saving: Brussels 00:30 CET is still the previous UTC day", () => {
    // 2026-11-16 00:30 in Brussels (UTC+1) is 2026-11-15 23:30 UTC.
    expect(utcEpochAt(new Date("2026-11-16T00:30:00+01:00"))).toBe(20_772);
    // DST end night 2026-10-25: the epoch only follows UTC.
    expect(utcEpochAt(new Date("2026-10-25T02:30:00+02:00"))).toBe(utcEpochAt(new Date("2026-10-25T02:30:00+01:00")));
  });

  it("refuses invalid times and epochs", () => {
    expect(() => utcEpochAt(Number.NaN)).toThrow();
    expect(() => utcEpochAt(-1)).toThrow();
    expect(() => epochStartMs(-1)).toThrow();
    expect(() => epochStartMs(1.5)).toThrow();
  });
});
