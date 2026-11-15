/**
 * Automatic daily ratchet of a host device's key chain (Stap 7g): at 00:00 UTC
 * SK_t -> SK_{t+1} (epoch-clock.ts). The ratchet itself runs in the crypto
 * worker ("host_key.advance_epoch"): wasm/rout-zk forward_secure.rs ratchet()
 * volatile-wipes SK_{t-1} inside the engine's fixed memory before it writes
 * SK_t, the engine memory is zero-filled when the call returns, and the
 * worker's HostKeyStore overwrites its held buffer in place. Only then is the
 * new device-sealed state (RVE1 hsk) written to the device's vault_enclave
 * row through anon_host_key_advance (compare-and-swap on ver and epoch).
 *
 * Browsers throttle timers in background tabs and devices sleep, so the timer
 * is only a trigger: every call to ensureCurrent() (before signing, on wake,
 * on visibility) compares the held epoch with the clock and catches up in one
 * step (intermediate epochs are ratcheted through and wiped unpublished).
 */
import type { EpochLink } from "@/lib/crypto-enclave/forward-secure";
import { MAX_EPOCH_ADVANCE } from "@/lib/crypto-enclave/forward-secure";
import { msUntilNextEpoch, utcEpochAt } from "./epoch-clock";

export type RatchetStep = { from: number; to: number; link: EpochLink; sealedState: Uint8Array };
export type PersistAnswer = "ok" | "replay" | "conflict" | "chain_full" | "retired" | "unknown" | "malformed";

export type RatchetPort = {
  /** Epoch the worker currently holds for this chain (host_key.chain). */
  heldEpoch(): Promise<number>;
  /** host_key.advance_epoch: new epoch, its link and the new device-sealed state. */
  advance(toEpoch: number): Promise<{ epoch: number; link: EpochLink; sealedState: Uint8Array }>;
  /** anon_host_key_advance for this device's chain. Throws on transport errors (retried later). */
  persist(step: RatchetStep): Promise<PersistAnswer>;
};

export type RatchetStatus = "current" | "advanced" | "retrying" | "conflict" | "chain_full" | "retired" | "too_far" | "failed";
export type RatchetResult = { status: RatchetStatus; epoch: number; target: number };

export type DailyRatchetOptions = {
  port: RatchetPort;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  onResult?: (r: RatchetResult) => void;
};

/**
 * One chain's scheduler. ensureCurrent() is single-flight: concurrent callers
 * share one run, so a timer firing while a signature waits never advances
 * twice. A step the worker made but the database did not take (network) is
 * kept and re-sent first on the next run: the worker no longer has SK_{t-1},
 * so the same link and sealed state are the only valid continuation.
 */
export class DailyEpochRatchet {
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (h: unknown) => void;
  private timer: unknown = null;
  private running: Promise<RatchetResult> | null = null;
  private pending: RatchetStep | null = null;
  private stopped = true;

  constructor(private readonly opts: DailyRatchetOptions) {
    this.now = opts.now ?? Date.now;
    this.setTimer = opts.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  }

  /** Catches up now and arms the timer for the next 00:00 UTC. */
  start(): Promise<RatchetResult> {
    this.stopped = false;
    return this.tick();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
  }

  get hasPendingStep(): boolean {
    return this.pending !== null;
  }

  /** Brings the held chain to today's epoch (no-op when it already is). */
  ensureCurrent(): Promise<RatchetResult> {
    if (!this.running) {
      this.running = this.run().finally(() => {
        this.running = null;
      });
    }
    return this.running;
  }

  private async tick(): Promise<RatchetResult> {
    const r = await this.ensureCurrent();
    this.opts.onResult?.(r);
    this.arm();
    return r;
  }

  private arm() {
    if (this.stopped) return;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.tick();
    }, msUntilNextEpoch(this.now()));
  }

  private async run(): Promise<RatchetResult> {
    const target = utcEpochAt(this.now());
    const { port } = this.opts;
    if (this.pending) {
      const step = this.pending;
      let answer: PersistAnswer;
      try {
        answer = await port.persist(step);
      } catch {
        return { status: "retrying", epoch: step.to, target };
      }
      this.pending = null;
      if (answer !== "ok" && answer !== "replay") return settle(answer, step.to, target);
    }
    let held: number;
    try {
      held = await port.heldEpoch();
    } catch {
      return { status: "failed", epoch: -1, target };
    }
    if (held >= target) return { status: "current", epoch: held, target };
    if (target - held > MAX_EPOCH_ADVANCE) return { status: "too_far", epoch: held, target };
    let step: RatchetStep;
    try {
      const r = await port.advance(target);
      step = { from: held, to: r.epoch, link: r.link, sealedState: r.sealedState };
    } catch {
      return { status: "failed", epoch: held, target };
    }
    try {
      return settle(await port.persist(step), step.to, target);
    } catch {
      this.pending = step;
      return { status: "retrying", epoch: step.to, target };
    }
  }
}

function settle(answer: PersistAnswer, epoch: number, target: number): RatchetResult {
  switch (answer) {
    case "ok":
    case "replay":
      return { status: epoch >= target ? "advanced" : "current", epoch, target };
    case "conflict":
      // Another tab or a restore moved the stored chain: reload it from the database.
      return { status: "conflict", epoch, target };
    case "chain_full":
      return { status: "chain_full", epoch, target };
    case "retired":
      return { status: "retired", epoch, target };
    default:
      return { status: "failed", epoch, target };
  }
}
