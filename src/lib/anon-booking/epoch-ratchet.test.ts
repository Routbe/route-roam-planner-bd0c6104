import { describe, expect, it, vi } from "vitest";
import type { EpochLink } from "@/lib/crypto-enclave/forward-secure";
import { DailyEpochRatchet, type PersistAnswer, type RatchetPort, type RatchetStep } from "./epoch-ratchet";
import { utcEpochAt } from "./epoch-clock";

const link = (from: number, to: number): EpochLink => ({ from, to, publicKey: new Uint8Array(96).fill(to & 0xff), signature: new Uint8Array(80) });

/** A worker + database stand-in: the held epoch moves only through advance(), the stored one only through persist(). */
function fakeChain(start: number) {
  const s = { held: start, stored: start, advances: [] as number[][], persisted: [] as RatchetStep[], fail: 0, answer: null as PersistAnswer | null };
  const port: RatchetPort = {
    heldEpoch: async () => s.held,
    advance: async (to) => {
      s.advances.push([s.held, to]);
      const from = s.held;
      s.held = to;
      return { epoch: to, link: link(from, to), sealedState: new Uint8Array(1703) };
    },
    persist: async (step) => {
      if (s.fail > 0) {
        s.fail--;
        throw new Error("network");
      }
      if (s.answer) return s.answer;
      if (step.from !== s.stored) return "conflict";
      s.stored = step.to;
      s.persisted.push(step);
      return "ok";
    },
  };
  return { s, port };
}

describe("daily epoch ratchet (00:00 UTC)", () => {
  it("moves SK_t to SK_{t+1} exactly at 00:00 UTC, once, and stores the new sealed state", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-11-15T23:59:58.000Z"));
      const today = utcEpochAt(Date.now());
      const { s, port } = fakeChain(today);
      const results: string[] = [];
      const r = new DailyEpochRatchet({ port, onResult: (x) => results.push(`${x.status}:${x.epoch}`) });
      expect((await r.start()).status).toBe("current");
      await vi.advanceTimersByTimeAsync(1_999);
      expect(s.advances).toEqual([]);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.advances).toEqual([[today, today + 1]]);
      expect(s.stored).toBe(today + 1);
      expect(results).toEqual([`current:${today}`, `advanced:${today + 1}`]);
      // Re-armed for the next midnight, 24 h later.
      await vi.advanceTimersByTimeAsync(86_400_000 - 1);
      expect(s.advances.length).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.advances).toEqual([[today, today + 1], [today + 1, today + 2]]);
      r.stop();
      await vi.advanceTimersByTimeAsync(3 * 86_400_000);
      expect(s.advances.length).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("catches up after sleep in one step (intermediate epochs are never published)", async () => {
    const now = Date.UTC(2026, 10, 20, 9);
    const { s, port } = fakeChain(utcEpochAt(now) - 5);
    const r = new DailyEpochRatchet({ port, now: () => now });
    const res = await r.ensureCurrent();
    expect(res).toEqual({ status: "advanced", epoch: utcEpochAt(now), target: utcEpochAt(now) });
    expect(s.advances).toEqual([[utcEpochAt(now) - 5, utcEpochAt(now)]]);
    expect(s.persisted.map((p) => [p.from, p.to])).toEqual([[utcEpochAt(now) - 5, utcEpochAt(now)]]);
  });

  it("first use of a fresh chain jumps from the anchor (epoch 0) to today", async () => {
    const now = Date.UTC(2026, 10, 15, 12);
    const { s, port } = fakeChain(0);
    expect((await new DailyEpochRatchet({ port, now: () => now }).ensureCurrent()).status).toBe("advanced");
    expect(s.advances).toEqual([[0, 20_772]]);
  });

  it("is single-flight: a signature waiting while the timer fires never advances twice", async () => {
    const now = Date.UTC(2026, 10, 15, 12);
    const { s, port } = fakeChain(utcEpochAt(now) - 1);
    const r = new DailyEpochRatchet({ port, now: () => now });
    const [a, b] = await Promise.all([r.ensureCurrent(), r.ensureCurrent()]);
    expect(a).toEqual(b);
    expect(s.advances.length).toBe(1);
  });

  it("keeps a step the database did not take and re-sends exactly that step (the old key is gone)", async () => {
    let now = Date.UTC(2026, 10, 15, 12);
    const { s, port } = fakeChain(utcEpochAt(now) - 1);
    s.fail = 1;
    const r = new DailyEpochRatchet({ port, now: () => now });
    expect((await r.ensureCurrent()).status).toBe("retrying");
    expect(r.hasPendingStep).toBe(true);
    expect(s.stored).toBe(utcEpochAt(now) - 1);
    // Next day: first the kept step, then the new transition.
    now += 86_400_000;
    const res = await r.ensureCurrent();
    expect(res.status).toBe("advanced");
    expect(r.hasPendingStep).toBe(false);
    expect(s.persisted.map((p) => [p.from, p.to])).toEqual([[utcEpochAt(now) - 2, utcEpochAt(now) - 1], [utcEpochAt(now) - 1, utcEpochAt(now)]]);
    expect(s.advances.length).toBe(2);
  });

  it("reports conflict, a full chain and a retired chain instead of guessing", async () => {
    const now = Date.UTC(2026, 10, 15, 12);
    for (const answer of ["conflict", "chain_full", "retired"] as const) {
      const { s, port } = fakeChain(utcEpochAt(now) - 1);
      s.answer = answer;
      expect((await new DailyEpochRatchet({ port, now: () => now }).ensureCurrent()).status).toBe(answer);
    }
  });

  it("refuses a jump beyond MAX_EPOCH_ADVANCE", async () => {
    const now = Date.UTC(2026, 10, 15, 12);
    const { s, port } = fakeChain(0);
    const far = 0 + 65_537 * 86_400_000 + now;
    expect((await new DailyEpochRatchet({ port, now: () => far }).ensureCurrent()).status).toBe("too_far");
    expect(s.advances).toEqual([]);
  });
});
